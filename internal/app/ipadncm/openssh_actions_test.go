package ipadncm

import "testing"

func TestOpenSSHActionsAreExplicitServiceCommands(t *testing.T) {
	for _, action := range []string{"openssh-refresh", "openssh-start", "openssh-stop", "openssh-automatic", "openssh-manual", "openssh-install-online", "openssh-install-download", "openssh-install-offline", "openssh-import", "openssh-delete"} {
		if !opensshDesktopAction(action) || !serviceAdditionalAction(action) {
			t.Fatal("missing service route", action)
		}
	}
	for _, action := range []string{"openssh-exec", "openssh-install", "openssh-", "OpenSSH-start", "openssh-delete;whoami"} {
		if opensshDesktopAction(action) || serviceAdditionalAction(action) {
			t.Fatal("unknown command accepted", action)
		}
	}
}
