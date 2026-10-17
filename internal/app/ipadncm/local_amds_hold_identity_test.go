package ipadncm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func amdsIdentityTestConfig() localAMDSHoldConfig {
	return localAMDSHoldConfig{Image: `"C:\Program Files\Common Files\Apple\Mobile Device Support\AppleMobileDeviceService.exe"`, Account: "LocalSystem", ServiceType: 0x10, StartType: 2}
}

func TestLocalAMDSHoldIdentityFixedAccountsAndTypes(t *testing.T) {
	accounts := map[string]string{"LocalSystem": "system", `NT AUTHORITY\SYSTEM`: "system", `NT AUTHORITY\LocalSystem`: "system", "S-1-5-18": "system", `NT AUTHORITY\LocalService`: "local_service", "S-1-5-19": "local_service", `NT AUTHORITY\NetworkService`: "network_service", "S-1-5-20": "network_service"}
	for account, want := range accounts {
		for _, typ := range []uint32{0x10, 0x110, 0x20, 0x120, 1, 0x50, 0x210} {
			c := amdsIdentityTestConfig()
			c.Account, c.ServiceType = strings.ToLower(account), typ
			i, err := amdsHoldConfigIdentity(c)
			valid := typ == 0x10 || typ == 0x110 && want == "system"
			if (err == nil) != valid || i.Account != want || i.ServiceType != typ {
				t.Fatalf("account %q type %x: %+v %v", account, typ, i, err)
			}
		}
	}
	for _, account := range []string{`NT SERVICE\Apple Mobile Device Service`, `DOMAIN\SomeUser`, "LocalService", "NetworkService", "", "S-1-5-180", " LocalSystem"} {
		c := amdsIdentityTestConfig()
		c.Account = account
		i, err := amdsHoldConfigIdentity(c)
		if err == nil || (i.Account != "virtual" && i.Account != "other") {
			t.Fatal(i, err)
		}
		b, _ := json.Marshal(i)
		if account != "" && strings.Contains(string(b), account) {
			t.Fatal("account leaked")
		}
	}
}

func TestLocalAMDSHoldIdentityCommandForms(t *testing.T) {
	base := `C:\Program Files\Common Files\Apple\Mobile Device Support\AppleMobileDeviceService.exe`
	for _, tc := range []struct {
		command     string
		valid, args bool
		code        string
	}{
		{base, true, false, ""},
		{`"` + base + `"`, true, false, ""},
		{`"` + base + `" --service "private argument"`, true, true, ""},
		{`C:\Apple\AppleMobileDeviceService.exe --service`, true, true, ""},
		{`C:/Apple/AppleMobileDeviceService.exe`, true, false, ""},
		{base + ` --service`, false, true, "AMDS_HOLD_IMAGE_COMMAND_AMBIGUOUS"},
		{`"` + base, false, false, "AMDS_HOLD_IMAGE_COMMAND_INVALID"},
		{`"` + base + `"suffix`, false, true, "AMDS_HOLD_IMAGE_COMMAND_INVALID"},
		{`""`, false, false, "AMDS_HOLD_IMAGE_NOT_ABSOLUTE"},
		{`AppleMobileDeviceService.exe`, false, false, "AMDS_HOLD_IMAGE_NOT_ABSOLUTE"},
		{`C:AppleMobileDeviceService.exe`, false, false, "AMDS_HOLD_IMAGE_NOT_ABSOLUTE"},
		{`\\server\share\AppleMobileDeviceService.exe`, false, false, "AMDS_HOLD_IMAGE_NOT_LOCAL_DRIVE"},
		{`\\?\C:\Apple\AppleMobileDeviceService.exe`, false, false, "AMDS_HOLD_IMAGE_NOT_LOCAL_DRIVE"},
		{`C:\Apple\..\AppleMobileDeviceService.exe`, false, false, "AMDS_HOLD_IMAGE_PATH_INVALID"},
		{`C:\Apple\AppleMobileDeviceService.exe:stream`, false, false, "AMDS_HOLD_IMAGE_PATH_INVALID"},
		{`C:\Apple\Different.exe`, false, false, "AMDS_HOLD_IMAGE_BASENAME_MISMATCH"},
		{` C:\Apple\AppleMobileDeviceService.exe`, false, false, "AMDS_HOLD_IMAGE_COMMAND_INVALID"},
		{base + "\x00", false, false, "AMDS_HOLD_IMAGE_COMMAND_INVALID"},
	} {
		c := amdsIdentityTestConfig()
		c.Image = tc.command
		i, err := amdsHoldConfigIdentity(c)
		if (err == nil) != tc.valid || i.HasArguments != tc.args {
			t.Fatalf("%q: %+v %v", tc.command, i, err)
		}
		if !tc.valid && err.Error() != tc.code {
			t.Fatalf("%q: %v", tc.command, err)
		}
		if tc.valid && (!i.AbsoluteImage || !i.BasenameMatch) {
			t.Fatal(i)
		}
		b, _ := json.Marshal(i)
		if strings.Contains(string(b), "Apple") || strings.Contains(string(b), "private") || strings.Contains(string(b), `C:`) {
			t.Fatal("identity leaked command")
		}
	}
}

func TestLocalAMDSHoldConfigFingerprintPreservesV1RecoveryAndParameters(t *testing.T) {
	c := amdsIdentityTestConfig()
	c.Dependencies, c.SIDType, c.Delayed = []string{"RpcSs"}, 1, true
	old := struct {
		Image, Account                  string
		ServiceType, StartType, SIDType uint32
		Dependencies                    []string
		Delayed                         bool
	}{strings.ToLower(c.Image), strings.ToLower(c.Account), c.ServiceType, c.StartType, c.SIDType, c.Dependencies, c.Delayed}
	b, _ := json.Marshal(old)
	digest := sha256.Sum256(b)
	hash, err := amdsHoldPortableConfigHash(c)
	if err != nil || hash != hex.EncodeToString(digest[:]) {
		t.Fatal("v1 journal hash changed", err)
	}
	for _, mutate := range []func(*localAMDSHoldConfig){func(c *localAMDSHoldConfig) { c.Image += " --service" }, func(c *localAMDSHoldConfig) { c.Account = "S-1-5-18" }, func(c *localAMDSHoldConfig) { c.StartType = 3 }, func(c *localAMDSHoldConfig) { c.ServiceType = 0x110 }} {
		x := c
		mutate(&x)
		next, err := amdsHoldPortableConfigHash(x)
		if err != nil || next == hash {
			t.Fatal("changed configuration not distinguished", err)
		}
	}
	withArgs := c
	withArgs.Image += " --mode=MixedCase"
	first, err := amdsHoldPortableConfigHash(withArgs)
	if err != nil {
		t.Fatal(err)
	}
	withArgs.Image = strings.Replace(withArgs.Image, "MixedCase", "mixedcase", 1)
	second, err := amdsHoldPortableConfigHash(withArgs)
	if err != nil || first == second {
		t.Fatal("argument case change must revoke restoration authority", err)
	}
	c.Account = `DOMAIN\private-user`
	_, err = amdsHoldPortableConfigHash(c)
	var failure *localAMDSHoldFailure
	if !errors.As(err, &failure) || failure.Identity == nil || failure.Code != "AMDS_HOLD_ACCOUNT_UNSUPPORTED" {
		t.Fatal(err)
	}
}
