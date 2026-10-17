package ipadncm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// Only fixed enums and native numbers leave the protected SCM configuration.
type localAMDSHoldIdentity struct {
	AbsoluteImage bool   `json:"absolute_image"`
	BasenameMatch bool   `json:"basename_match"`
	Account       string `json:"account"`
	ServiceType   uint32 `json:"service_type"`
	HasArguments  bool   `json:"has_arguments"`
}

type localAMDSHoldConfig struct {
	Image, Account                  string
	ServiceType, StartType, SIDType uint32
	Dependencies                    []string
	Delayed                         bool
}

func amdsHoldAccount(account string) string {
	switch strings.ToLower(account) {
	case "localsystem", `nt authority\system`, `nt authority\localsystem`, "s-1-5-18":
		return "system"
	case `nt authority\localservice`, "s-1-5-19":
		return "local_service"
	case `nt authority\networkservice`, "s-1-5-20":
		return "network_service"
	}
	if strings.HasPrefix(strings.ToLower(account), `nt service\`) {
		return "virtual"
	}
	return "other"
}

// Parse only the image token. Parameters are never executed or returned; the
// complete original SCM command remains part of the configuration fingerprint.
func amdsHoldImage(command string) (image string, arguments bool, code string) {
	if command == "" || len(command) > 32768 || strings.ContainsAny(command, "\x00\r\n") || strings.TrimSpace(command) != command {
		return "", false, "AMDS_HOLD_IMAGE_COMMAND_INVALID"
	}
	if command[0] == '"' {
		end := strings.IndexByte(command[1:], '"')
		if end < 0 {
			return "", false, "AMDS_HOLD_IMAGE_COMMAND_INVALID"
		}
		image = command[1 : end+1]
		tail := command[end+2:]
		if tail != "" && tail[0] != ' ' && tail[0] != '\t' {
			return image, true, "AMDS_HOLD_IMAGE_COMMAND_INVALID"
		}
		return image, strings.TrimSpace(tail) != "", ""
	}
	// Existing AMDS installations also store the entire image path without
	// quotes. Preserve that v1-compatible form when the complete path ends in
	// the exact executable, rather than treating its folder spaces as arguments.
	if !strings.Contains(command, "\"") && (strings.HasSuffix(strings.ToLower(command), `\applemobiledeviceservice.exe`) || strings.HasSuffix(strings.ToLower(command), `/applemobiledeviceservice.exe`)) {
		return command, false, ""
	}
	end := strings.IndexAny(command, " \t")
	if end < 0 {
		return command, false, ""
	}
	image = command[:end]
	if !strings.HasSuffix(strings.ToLower(image), ".exe") {
		return image, true, "AMDS_HOLD_IMAGE_COMMAND_AMBIGUOUS"
	}
	return image, strings.TrimSpace(command[end:]) != "", ""
}

func amdsHoldConfigIdentity(c localAMDSHoldConfig) (*localAMDSHoldIdentity, error) {
	image, args, code := amdsHoldImage(c.Image)
	path := strings.ReplaceAll(image, "/", `\`)
	drive := len(path) >= 3 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1:3] == `:\`
	i := &localAMDSHoldIdentity{AbsoluteImage: drive || strings.HasPrefix(path, `\\`), Account: amdsHoldAccount(c.Account), ServiceType: c.ServiceType, HasArguments: args}
	base := path[strings.LastIndex(path, `\`)+1:]
	i.BasenameMatch = strings.EqualFold(base, "AppleMobileDeviceService.exe")
	fail := func(cause string) (*localAMDSHoldIdentity, error) {
		return i, &localAMDSHoldFailure{Code: cause, Identity: i}
	}
	if code != "" {
		return fail(code)
	}
	if !i.AbsoluteImage {
		return fail("AMDS_HOLD_IMAGE_NOT_ABSOLUTE")
	}
	if !drive {
		return fail("AMDS_HOLD_IMAGE_NOT_LOCAL_DRIVE")
	}
	for _, ch := range path {
		if ch < 32 {
			return fail("AMDS_HOLD_IMAGE_PATH_INVALID")
		}
	}
	for _, part := range strings.Split(path[3:], `\`) {
		if part == "" || part == "." || part == ".." || strings.TrimRight(part, " .") != part || strings.ContainsAny(part, ":\"<>|?*\t") {
			return fail("AMDS_HOLD_IMAGE_PATH_INVALID")
		}
	}
	if !i.BasenameMatch {
		return fail("AMDS_HOLD_IMAGE_BASENAME_MISMATCH")
	}
	if i.Account != "system" && i.Account != "local_service" && i.Account != "network_service" {
		return fail("AMDS_HOLD_ACCOUNT_UNSUPPORTED")
	}
	// SCM allows the interactive bit only for LocalSystem. Shared-process,
	// driver and per-user service types are outside this standalone AMDS scope.
	if c.ServiceType != 0x10 && c.ServiceType != 0x110 {
		return fail("AMDS_HOLD_SERVICE_TYPE_UNSUPPORTED")
	}
	if c.ServiceType == 0x110 && i.Account != "system" {
		return fail("AMDS_HOLD_INTERACTIVE_ACCOUNT_INVALID")
	}
	if c.StartType < 2 || c.StartType > 4 {
		return fail("AMDS_HOLD_START_TYPE_UNSUPPORTED")
	}
	return i, nil
}

func amdsHoldPortableConfigHash(c localAMDSHoldConfig) (string, error) {
	identity, err := amdsHoldConfigIdentity(c)
	if err != nil {
		return "", err
	}
	// Preserve the v1 journal encoding and case normalization for recovery of
	// existing receipts. Newly supported arguments can be case-sensitive.
	if !identity.HasArguments {
		c.Image = strings.ToLower(c.Image)
	}
	c.Account = strings.ToLower(c.Account)
	b, err := json.Marshal(c)
	if err != nil {
		return "", amdsHoldError("AMDS_HOLD_CONFIG_ENCODING_FAILED", 0)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
