//go:build windows && amd64 && usblink_local_remote

package netconfig

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"maps"
	"strings"
	"suhang/usbnet/internal/platform/windows/wincom"
	"suhang/usbnet/internal/transport/usbaddress"
	"sync/atomic"
)

// EnsureLocalMaintenanceNative creates only the explicit local USB push rule.
// It does not adopt a core rule or alter the global network implementation.
func EnsureLocalMaintenanceNative(ctx context.Context, host usbaddress.InterfaceProof, executable string, verifyGeneration func() error) error {
	if ctx == nil || verifyGeneration == nil || host.Role != "host" || !strings.EqualFold(host.GUID, usbaddress.HostGUID) || host.Created <= 0 || !validCoreExecutable(executable) {
		return errors.New("USB_LOCAL_PUSH_HOST_SCOPE_INVALID")
	}
	if err := verifyGeneration(); err != nil {
		return err
	}
	alias, err := nativeRuleInterface(ctx, host)
	if err != nil {
		return err
	}
	spec, err := localMaintenanceSpec(executable, alias)
	if err != nil {
		return err
	}
	// The full rule is removed before a fresh creation, even after a crash.
	// Its own exact executable and current generation must still be proven.
	if err = CleanupLocalMaintenanceNative(ctx, func(program string) error {
		if !strings.EqualFold(program, executable) {
			return errors.New("USB_LOCAL_PUSH_EXECUTABLE_CHANGED")
		}
		return verifyGeneration()
	}); err != nil {
		return err
	}
	if err = verifyGeneration(); err != nil {
		return err
	}
	if err = createLocalMaintenanceRule(ctx, host, spec, verifyGeneration); err != nil {
		return err
	}
	if err = verifyGeneration(); err != nil {
		return err
	}
	release, err := usbaddress.ConfigurationLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	return withFirewall(ctx, func(svc *wincom.Dispatch) error {
		if err := verifyGeneration(); err != nil {
			return err
		}
		currentAlias, err := nativeRuleInterface(ctx, host)
		if err != nil || currentAlias != alias {
			return errors.New("USB_LOCAL_PUSH_INTERFACE_CHANGED")
		}
		rule, err := matchingRule(svc, spec.Name)
		if err != nil {
			return err
		}
		if rule == nil {
			return errors.New("USB_LOCAL_PUSH_RULE_ABSENT")
		}
		defer rule.Close()
		if err = firewallExpected(rule, spec, 1); err != nil {
			return err
		}
		if err = verifyNativeRuleBaseline(rule, spec); err != nil {
			return err
		}
		return verifyGeneration()
	})
}

func createLocalMaintenanceRule(ctx context.Context, host usbaddress.InterfaceProof, spec nativeRuleSpec, verifyGeneration func() error) error {
	script, err := localMaintenanceCreationScript(host, spec)
	if err != nil {
		return err
	}
	release, err := usbaddress.ConfigurationLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	return nativeStep(nil, "firewall_rules", func() error {
		return withFirewall(ctx, func(svc *wincom.Dispatch) error {
			verify := func() error {
				if err := verifyGeneration(); err != nil {
					return err
				}
				alias, err := nativeRuleInterface(ctx, host)
				if err != nil {
					return err
				}
				if alias != spec.Alias {
					return errors.New("USB_LOCAL_PUSH_INTERFACE_CHANGED")
				}
				return nil
			}
			if err := verify(); err != nil {
				return err
			}
			present, err := matchingRule(svc, spec.Name)
			if err != nil {
				return err
			}
			if present != nil {
				present.Close()
				return errors.New("USB_LOCAL_PUSH_NAME_OCCUPIED")
			}
			if err = RunContext(ctx, script, log.New(io.Discard, "", 0)); err != nil {
				return &LocalMaintenanceFailure{"create_disabled", err}
			}
			var current *wincom.Dispatch
			var lastConstraints firewallConstraints
			defer func() {
				if current != nil {
					current.Close()
				}
			}()
			read := func() (firewallConstraints, error) {
				if current != nil {
					current.Close()
					current = nil
				}
				var err error
				current, err = matchingRule(svc, spec.Name)
				if err != nil {
					return nil, err
				}
				if current == nil {
					return nil, errors.New("USB_LOCAL_PUSH_RULE_ABSENT")
				}
				lastConstraints, err = readFirewallConstraints(current)
				return lastConstraints, err
			}
			var disabledBaseline firewallConstraints
			enableAttempted := false
			hash, err := completeLocalMaintenanceRule(spec, read, verify, func() error {
				disabledBaseline = maps.Clone(lastConstraints)
				script, err := localMaintenanceEnableScript(host, spec, disabledBaseline, true)
				if err != nil {
					return err
				}
				enableAttempted = true
				return RunContext(ctx, script, log.New(io.Discard, "", 0))
			})
			if err != nil {
				if enableAttempted {
					enabledBaseline := maps.Clone(disabledBaseline)
					enabledBaseline["/Enabled"] = []string{"N:1"}
					script, scriptError := localMaintenanceEnableScript(host, spec, enabledBaseline, false)
					if scriptError == nil {
						scriptError = RunContext(ctx, script, log.New(io.Discard, "", 0))
					}
					return errors.Join(err, scriptError)
				}
				return err
			}
			key, _ := json.Marshal(spec)
			nativeRuleCache.Lock()
			if len(nativeRuleCache.hashes) >= 64 {
				nativeRuleCache.hashes = map[string]string{}
			}
			nativeRuleCache.hashes[string(key)] = hash
			nativeRuleCache.Unlock()
			return nil
		})
	})
}

var localMaintenanceLegacyRetained atomic.Bool

// LocalMaintenanceLegacyRetained reports a disabled incomplete v1 rule without
// granting authority to delete or enable it.
func LocalMaintenanceLegacyRetained() bool { return localMaintenanceLegacyRetained.Load() }

// CleanupLocalMaintenanceNative cannot delete by name alone. Complete scope,
// stable readbacks and executable ownership are required before mutation.
func CleanupLocalMaintenanceNative(ctx context.Context, verifyExecutable func(string) error) error {
	if err := cleanupLocalMaintenanceRule(ctx, verifyExecutable, legacyLocalMaintenanceRule, true); err != nil {
		return err
	}
	return cleanupLocalMaintenanceRule(ctx, verifyExecutable, localMaintenanceRule, false)
}

func cleanupLocalMaintenanceRule(ctx context.Context, verifyExecutable func(string) error, name string, allowDisabledLegacy bool) error {
	if ctx == nil || verifyExecutable == nil {
		return errors.New("USB_LOCAL_PUSH_OWNER_REQUIRED")
	}
	release, err := usbaddress.ConfigurationLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	return withFirewall(ctx, func(svc *wincom.Dispatch) error {
		rule, err := matchingRule(svc, name)
		if err != nil || rule == nil {
			if err == nil && name == legacyLocalMaintenanceRule {
				localMaintenanceLegacyRetained.Store(false)
			}
			return err
		}
		enabled, enabledError := cimInt(rule, "Enabled")
		if enabledError != nil {
			rule.Close()
			return enabledError
		}
		if enabled != 1 && enabled != 2 {
			rule.Close()
			return errors.New("USB_LOCAL_PUSH_LEGACY_RULE_UNPROVEN")
		}
		got, err := readFirewallConstraints(rule)
		rule.Close()
		var spec nativeRuleSpec
		if err == nil {
			spec, err = localMaintenanceCleanupSpec(got)
		}
		retainDisabled := func(cause error) error {
			if !allowDisabledLegacy || enabledError != nil || enabled != 2 {
				return cause
			}
			fresh, queryError := matchingRule(svc, name)
			if queryError != nil {
				return queryError
			}
			if fresh == nil {
				return nil
			}
			defer fresh.Close()
			state, stateError := cimInt(fresh, "Enabled")
			if stateError != nil || !localMaintenanceRetainDisabledLegacy(name, enabled, state) {
				return errors.New("USB_LOCAL_PUSH_LEGACY_RULE_UNPROVEN")
			}
			localMaintenanceLegacyRetained.Store(true)
			return nil
		}
		if err != nil {
			return retainDisabled(err)
		}
		if ownerError := verifyExecutable(spec.Program); ownerError != nil {
			return retainDisabled(ownerError)
		}
		verify := func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return verifyExecutable(spec.Program)
		}
		read := func(nativeRuleSpec) (firewallConstraints, error) {
			rule, err := matchingRule(svc, spec.Name)
			if err != nil {
				return nil, err
			}
			if rule == nil {
				return nil, nil
			}
			defer rule.Close()
			return readFirewallConstraints(rule)
		}
		if err = executeNativeRuleCleanup([]nativeRuleSpec{spec}, read, verify, func(_ nativeRuleSpec, baseline string) error {
			rule, err := matchingRule(svc, spec.Name)
			if err != nil {
				return err
			}
			if rule == nil {
				return errors.New("USB_LOCAL_PUSH_RULE_CHANGED")
			}
			defer rule.Close()
			got, err := readFirewallConstraints(rule)
			if err != nil {
				return err
			}
			hash, err := firewallFingerprint(got)
			if err != nil || hash != baseline {
				return errors.New("USB_LOCAL_PUSH_RULE_CHANGED")
			}
			if err = verify(); err != nil {
				return err
			}
			script, err := localMaintenanceRemovalScript(spec, got)
			if err != nil {
				return err
			}
			if err = RunContext(ctx, script, log.New(io.Discard, "", 0)); err != nil {
				return err
			}
			remaining, err := matchingRule(svc, spec.Name)
			if remaining != nil {
				remaining.Close()
				return errors.New("USB_LOCAL_PUSH_RULE_REMAINS")
			}
			return err
		}); err != nil {
			return err
		}
		remaining, err := matchingRule(svc, spec.Name)
		if remaining != nil {
			remaining.Close()
			return errors.New("USB_LOCAL_PUSH_RULE_REMAINS")
		}
		if err != nil {
			return err
		}
		key, _ := json.Marshal(spec)
		nativeRuleCache.Lock()
		delete(nativeRuleCache.hashes, string(key))
		nativeRuleCache.Unlock()
		if name == legacyLocalMaintenanceRule {
			localMaintenanceLegacyRetained.Store(false)
		}
		return verify()
	})
}
