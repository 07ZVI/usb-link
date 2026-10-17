//go:build usblink_local_remote

package netconfig

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
)

func localMaintenanceCreationScript(host usbaddress.InterfaceProof, spec nativeRuleSpec) (string, error) {
	expected, err := localMaintenanceSpec(spec.Program, spec.Alias)
	if err != nil || expected != spec || host.Role != "host" || !strings.EqualFold(host.GUID, usbaddress.HostGUID) || host.Index == 0 || host.LUID == 0 || host.Created <= 0 {
		return "", errors.New("USB_LOCAL_PUSH_CREATE_SCOPE_INVALID")
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	// Create only a disabled exact rule. Native full readbacks authorize enabling.
	return fmt.Sprintf(`$ErrorActionPreference='Stop';
$a=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {$_.ifIndex -eq %d -and [guid]$_.InterfaceGuid -eq [guid]%s -and $_.Name -ceq %s});if($a.Count -ne 1){throw 'USB_LOCAL_PUSH_INTERFACE_CHANGED'};
$r=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object {$_.Name -ceq %s});if($r.Count -ne 0){throw 'USB_LOCAL_PUSH_NAME_OCCUPIED'};
New-NetFirewallRule -PolicyStore PersistentStore -Name %s -DisplayName %s -Group %s -Description %s -Enabled False -Direction Inbound -Action Allow -Profile Any -EdgeTraversalPolicy Block -Program %s -Service Any -InterfaceAlias %s -LocalAddress '10.6.9.1' -RemoteAddress '10.6.9.2' -Protocol TCP -LocalPort 47775 -RemotePort Any | Out-Null;
`, host.Index, quote(usbaddress.HostGUID), quote(spec.Alias), quote(spec.Name), quote(spec.Name), quote(spec.Display), quote(spec.Group), quote(spec.Description), quote(spec.Program), quote(spec.Alias)), nil
}

func localMaintenanceEnableScript(host usbaddress.InterfaceProof, spec nativeRuleSpec, baseline firewallConstraints, enable bool) (string, error) {
	if _, err := localMaintenanceCreationScript(host, spec); err != nil {
		return "", err
	}
	state, value := int32(2), "True"
	if !enable {
		state, value = 1, "False"
	}
	if err := verifyFirewallConstraints(baseline, spec, state); err != nil {
		return "", err
	}
	b, err := json.Marshal(baseline)
	if err != nil || len(b) > 16384 {
		return "", errors.New("USB_LOCAL_PUSH_BASELINE_LIMIT")
	}
	prefix := "$ErrorActionPreference='Stop';" + residentPSProbe
	prefix += "$want=([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(" + residentQuote(base64.StdEncoding.EncodeToString(b)) + "))|ConvertFrom-Json);"
	prefix += fmt.Sprintf("$a=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop|Where-Object {$_.ifIndex -eq %d -and [guid]$_.InterfaceGuid -eq [guid]%s -and $_.Name -ceq %s});if($a.Count -ne 1){throw 'USB_LOCAL_PUSH_INTERFACE_CHANGED'};", host.Index, residentQuote(usbaddress.HostGUID), residentQuote(spec.Alias))
	prefix += "$r=USB-ResidentRule " + residentQuote(spec.Name) + ";if($null -eq $r){throw 'USB_LOCAL_PUSH_RULE_ABSENT'};USB-ResidentCompare (USB-ResidentSnapshot $r) $want;"
	prefix += "$fr=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name " + residentQuote(spec.Name) + " -ErrorAction Stop);if($fr.Count -ne 1){throw 'USB_LOCAL_PUSH_RULE_CHANGED'};"
	prefix += "$r=USB-ResidentRule " + residentQuote(spec.Name) + ";if($null -eq $r){throw 'USB_LOCAL_PUSH_RULE_ABSENT'};USB-ResidentCompare (USB-ResidentSnapshot $r) $want;"
	return prefix + "$fr[0]|Set-NetFirewallRule -Enabled " + value + " -ErrorAction Stop|Out-Null;", nil
}

func localMaintenanceRemovalScript(spec nativeRuleSpec, baseline firewallConstraints) (string, error) {
	actual, err := localMaintenanceCleanupSpec(baseline)
	if err != nil || actual != spec {
		return "", errors.New("USB_LOCAL_PUSH_REMOVE_SCOPE_INVALID")
	}
	b, err := json.Marshal(baseline)
	if err != nil || len(b) > 16384 {
		return "", errors.New("USB_LOCAL_PUSH_BASELINE_LIMIT")
	}
	script := "$ErrorActionPreference='Stop';" + residentPSProbe
	script += "$want=([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(" + residentQuote(base64.StdEncoding.EncodeToString(b)) + "))|ConvertFrom-Json);"
	script += "$r=USB-ResidentRule " + residentQuote(spec.Name) + ";if($null -eq $r){throw 'USB_LOCAL_PUSH_RULE_ABSENT'};USB-ResidentCompare (USB-ResidentSnapshot $r) $want;"
	script += "$fr=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name " + residentQuote(spec.Name) + " -ErrorAction Stop);if($fr.Count -ne 1){throw 'USB_LOCAL_PUSH_RULE_CHANGED'};"
	script += "$r=USB-ResidentRule " + residentQuote(spec.Name) + ";if($null -eq $r){throw 'USB_LOCAL_PUSH_RULE_ABSENT'};USB-ResidentCompare (USB-ResidentSnapshot $r) $want;"
	return script + "$fr[0]|Remove-NetFirewallRule -ErrorAction Stop;", nil
}

type LocalMaintenanceFailure struct {
	Stage string
	Cause error
}

func (e *LocalMaintenanceFailure) Error() string { return "USB_LOCAL_PUSH_NATIVE_FAILED" }
func (e *LocalMaintenanceFailure) Unwrap() error { return e.Cause }
func LocalMaintenanceFailureStage(err error) string {
	var failure *LocalMaintenanceFailure
	if !errors.As(err, &failure) || failure == nil {
		return ""
	}
	switch failure.Stage {
	case "create_disabled", "read_disabled", "enable_exact", "read_enabled":
		return failure.Stage
	}
	return ""
}

func completeLocalMaintenanceRule(spec nativeRuleSpec, read func() (firewallConstraints, error), verify func() error, enable func() error) (string, error) {
	if _, err := verifyNativeRuleReadbacks(spec, 2, "", read, verify); err != nil {
		return "", &LocalMaintenanceFailure{"read_disabled", err}
	}
	if err := enable(); err != nil {
		return "", &LocalMaintenanceFailure{"enable_exact", err}
	}
	hash, err := verifyNativeRuleReuse(spec, "", read, verify)
	if err != nil {
		return "", &LocalMaintenanceFailure{"read_enabled", err}
	}
	return hash, nil
}
