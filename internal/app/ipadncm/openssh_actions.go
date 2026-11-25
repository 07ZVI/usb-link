package ipadncm

func opensshDesktopAction(action string) bool {
	switch action {
	case "openssh-refresh", "openssh-start", "openssh-stop", "openssh-automatic", "openssh-manual", "openssh-install-online", "openssh-install-download", "openssh-install-offline", "openssh-import", "openssh-delete":
		return true
	}
	return false
}
