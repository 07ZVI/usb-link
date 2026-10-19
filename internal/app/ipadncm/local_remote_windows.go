//go:build windows && amd64 && usblink_local_remote

package ipadncm

var localDeveloperDebug *developerDebugController

// Keep local inspection usable when protected initialization failed. No save,
// restore or USB admission is claimed by this fallback controller.
func SetLocalRemoteUnavailable(code string) {
	setLocalExperimentMaster(false)
	localDeveloperDebug = newUnavailableDeveloperDebugController(code)
}

// SetLocalRemoteControl is wired once before the desktop service starts.
func SetLocalRemoteControl(f func(bool) (string, error), save func(bool) error, restore func() (bool, error), intent func(bool) error, transport func() (bool, bool, string), startupError string) {
	localDeveloperDebug = &developerDebugController{apply: f, save: save, restore: restore, intent: intent, transport: transport, photoMaster: setLocalExperimentMaster, state: developerDebugSnapshot{Available: true, Busy: true, Persistence: "loading", USBPhase: "off", StartupError: startupError}}
	localDeveloperDebug.intentError = intent(false)
	go localDeveloperDebug.initialize()
}

func setLocalExperimentMaster(on bool) {
	SetLocalNCMDirectMaster(on)
	SetLocalMacMTUCapMaster(on)
}

func localDeveloperDebugStatus() any {
	if localDeveloperDebug == nil {
		return developerDebugSnapshot{}
	}
	return localDeveloperDebug.snapshot()
}

var macMTUCapActions = map[string]string{"mac-mtu-cap-auto": "auto", "mac-mtu-cap-9000": "9000", "mac-mtu-cap-1500": "1500"}

func handleLocalRemoteAction(u *modernUI, request desktopRequest) bool {
	action := request.Action
	var set func(bool, string) error
	switch action {
	case "photo-isolation-on", "photo-isolation-off":
		set = SetPhotoIsolation
	case "photo-policy-on", "photo-policy-off":
		set = SetLocalPhotoPolicy
	case "ncm-direct-on", "ncm-direct-off":
		set = SetLocalNCMDirect
	case "amds-hold-on", "amds-hold-off":
		set = SetLocalAMDSHold
	}
	if setting, ok := macMTUCapActions[action]; ok {
		if !validStartupDisplayRequestID(request.ID) {
			u.setNotice("本地實驗設定請求無效。")
			return true
		}
		go func() {
			if err := SetLocalMacMTUCap(setting, request.ID); err != nil {
				u.setNotice("本地實驗設定未完成：" + err.Error())
			}
			u.requestRefresh()
		}()
		return true
	}
	if set != nil {
		if !validStartupDisplayRequestID(request.ID) {
			u.setNotice("本地實驗設定請求無效。")
			return true
		}
		go func() {
			on := action == "photo-isolation-on" || action == "photo-policy-on" || action == "ncm-direct-on" || action == "amds-hold-on"
			if err := set(on, request.ID); err != nil {
				u.setNotice("本地實驗設定未完成：" + err.Error())
			}
			u.requestRefresh()
		}()
		return true
	}
	if action != "local-usb-update-on" && action != "local-usb-update-off" {
		return false
	}
	if localDeveloperDebug == nil {
		u.setNotice("開發者調試尚未就緒。")
		return true
	}
	if !validStartupDisplayRequestID(request.ID) {
		u.setNotice("開發者調試請求無效。")
		return true
	}
	localDeveloperDebug.request(action == "local-usb-update-on", request.ID)
	u.requestRefresh()
	return true
}

// DeveloperDebugDiagnostics exposes only cached state, never credentials.
func DeveloperDebugDiagnostics() any { return localDeveloperDebugStatus() }
