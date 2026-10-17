package connectioninstall

import (
	"errors"
	"strings"
	"testing"
)

func TestRemoteInitializationClassificationKeepsCauseWithoutPublishingIt(t *testing.T) {
	cause := errors.New("private-owner-path-and-provider-text")
	for _, stage := range []string{"root", "config_read", "config_clear", "consent_clear", "guard", "local_firewall", "legacy_firewall", "unknown"} {
		err := remoteInitializationFailure(stage, cause)
		code := RemoteInitializationCode(err)
		if !errors.Is(err, cause) || !strings.HasPrefix(code, "LOCAL_REMOTE_INITIALIZATION_") || strings.Contains(code, cause.Error()) || err.Error() != code {
			t.Fatal(stage, code, err)
		}
	}
	if remoteInitializationFailure("root", nil) != nil || RemoteInitializationCode(nil) != "" || RemoteInitializationCode(cause) != "LOCAL_REMOTE_INITIALIZATION_FAILED" {
		t.Fatal("nil/unknown classification")
	}
}
