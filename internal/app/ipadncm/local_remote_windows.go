//go:build windows && amd64 && usblink_local_remote

package ipadncm

var localDeveloperDebug *developerDebugController

// Keep local inspection usable when protected initialization failed. No save,
// restore or USB admission is claimed by this fallback controller.
func SetLocalRemoteUnavailable(code string) {
	SetPhotoIsolationMaster(false)
	localDeveloperDebug = newUnavailableDeveloperDebugController(code)
}

// SetLocalRemoteControl is wired once before the desktop service starts.
func SetLocalRemoteControl(f func(bool) (string, error), save func(bool) error, restore func() (bool, error), intent func(bool) error, transport func() (bool, bool, string), startupError string) {
	SetPhotoIsolationMaster(false)
	localDeveloperDebug = &developerDebugController{apply: f, save: save, restore: restore, intent: intent, transport: transport, photoMaster: SetPhotoIsolationMaster, state: developerDebugSnapshot{Available: true, Busy: true, Persistence: "loading", USBPhase: "off", StartupError: startupError}}
	localDeveloperDebug.intentError = intent(false)
	go localDeveloperDebug.initialize()
}

func localDeveloperDebugStatus() any {
	if localDeveloperDebug == nil {
		return developerDebugSnapshot{}
	}
	return localDeveloperDebug.snapshot()
}

func handleLocalRemoteAction(u *modernUI, request desktopRequest) bool {
	action := request.Action
	if action == "photo-isolation-on" || action == "photo-isolation-off" {
		if !validStartupDisplayRequestID(request.ID) {
			u.setNotice("照片介面隔離請求無效。")
			return true
		}
		go func() {
			if err := SetPhotoIsolation(action == "photo-isolation-on", request.ID); err != nil {
				u.setNotice("照片介面隔離設定未完成：" + err.Error())
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
	if action == "local-usb-update-off" {
		ResetConnectionTimingTrial()
	}
	u.requestRefresh()
	return true
}

// DeveloperDebugDiagnostics exposes only cached state, never credentials.
func DeveloperDebugDiagnostics() any { return localDeveloperDebugStatus() }
