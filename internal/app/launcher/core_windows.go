//go:build windows && amd64

package launcher

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/app/coreprompt"
	"suhang/usbnet/internal/app/coreupdatenotice"
	"suhang/usbnet/internal/app/ipadncm"
	"suhang/usbnet/internal/app/macconnection"
	"suhang/usbnet/internal/app/startupopt"
	"suhang/usbnet/internal/app/startuptelemetry"
	"suhang/usbnet/internal/app/uistartup"
	"suhang/usbnet/internal/app/usbhost"
	"suhang/usbnet/internal/contracts/coreipc"
	"suhang/usbnet/internal/dependencies"
	"suhang/usbnet/internal/diagnostics/coreterm"
	"suhang/usbnet/internal/diagnostics/shutdowntrace"
	"suhang/usbnet/internal/platform/windows/background"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
)

type coreLifetime struct {
	ctx    context.Context
	appCtx context.Context
	exit   *coreProgramExit
}

var liveCore atomic.Pointer[coreLifetime]

// One small row per concern: how the previous core ended, and the pipe's own
// failure record. Neither is authority; both are exported with diagnostics.
func coreLifecycleRow(s coreterm.Status) map[string]any {
	return map[string]any{"core_version": version, "core_lifecycle": s}
}

var prompts = coreprompt.New()
var coreUpdateNotices = coreupdatenotice.New(verifyCoreNoticeClientLifetime)

func runCoreService() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	binding, err := connectioninstall.ActivateCoreOwner(exe)
	if err != nil {
		fmt.Fprintln(os.Stderr, "CORE_ACTIVATION_FAILED:", err)
		return
	}
	coreProcessMode = true
	releaseSource, err := connectioninstall.PinCoreSelfSource(exe)
	if err != nil {
		fmt.Fprintln(os.Stderr, "CORE_SOURCE_PIN_FAILED:", err)
		return
	}
	defer releaseSource()
	remoteInstallID, err = connectioninstall.CoreRemoteLaunch(version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "CORE_REMOTE_LAUNCH_FAILED:", err)
		return
	}
	logger := log.New(os.Stderr, "USBLinkCore ", log.LstdFlags|log.LUTC)
	if output, _, logErr := connectioninstall.OpenCoreLog(); logErr == nil {
		logger.SetOutput(output)
		log.SetOutput(output)
		defer func() { log.SetOutput(os.Stderr); _ = output.Close() }()
	} else {
		logger.Printf("CORE_LOG_UNAVAILABLE: %v", logErr)
	}
	verifyCore := func(path string) error {
		fresh, err := connectioninstall.CurrentCoreBinding()
		if err != nil || fresh != binding || path != binding.Executable {
			return fmt.Errorf("CORE_SERVICE_BINDING_CHANGED")
		}
		return connectioninstall.VerifyCoreExecutable(path)
	}
	if err = background.RunCoreService(background.CoreOptions{
		Executable: exe, OwnerSID: binding.OwnerSID, Verify: verifyCore, Log: logger,
		Terminated: func(reason string, code uint32) { coreterm.End(reason, code, time.Now()) },
		Run: func(ctx context.Context, owner background.CoreContext) error {
			appCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			appDone := make(chan struct{})
			var exit *coreProgramExit
			recordExit := func(stage, id string) {
				logger.Printf("PROGRAM_EXIT stage=%s request_id=%s", stage, id)
				if dir, ok := serviceDiagnosticDirectory.Load().(string); ok && dir != "" {
					if err := macconnection.RecordProgramExitEvidence(dir, version, stage); err != nil {
						logger.Print("PROGRAM_EXIT_EVIDENCE_WRITE_FAILED")
					}
				}
			}
			exit = newCoreProgramExit(func() {
				shutdowntrace.Start()
				end := shutdowntrace.Begin(shutdowntrace.PhaseApplicationJoin)
				defer end()
				cancel()
				<-appDone
			}, func() error {
				id := exit.snapshot().ID
				cleanupErr := ApplicationExitCleanupError()
				if cleanupErr != nil {
					recordExit("APPLICATION_CLEANUP_PENDING", id)
				} else {
					recordExit("APPLICATION_CLEANUP_CONFIRMED", id)
				}
				isolationErr := ipadncm.StopDefaultNetworkIsolation()
				if isolationErr != nil {
					recordExit("DEFAULT_RESTORE_PENDING", id)
				} else {
					recordExit("DEFAULT_RESTORE_CONFIRMED", id)
				}
				if isolationErr != nil {
					return isolationErr
				}
				return cleanupErr
			})
			exit.record = recordExit
			defer exit.closeUILifetimes()
			liveCore.Store(&coreLifetime{ctx: ctx, appCtx: appCtx, exit: exit})
			defer liveCore.Store(nil)
			ipadncm.SetPanelRelay(relayCorePanel)
			defer ipadncm.SetPanelRelay(nil)
			controlsCtx, stopControls := context.WithCancel(ctx)
			controlsDone := make(chan struct{})
			defer func() { stopControls(); <-controlsDone }()
			go func() {
				defer close(controlsDone)
				for {
					select {
					case <-controlsCtx.Done():
						return
					case control := <-owner.Controls:
						if control.Resume {
							usbhost.NudgeSharedHost()
						}
					}
				}
			}()
			go func() { defer close(appDone); runApplication(appCtx, cancel, true) }()
			select {
			case <-appDone:
				if appCtx.Err() == nil && !exit.active() {
					return fmt.Errorf("CORE_APPLICATION_STOPPED_BEFORE_CANCELLATION")
				}
			case <-ctx.Done():
				cancel()
				<-appDone
				return nil
			}
			if exit.active() {
				select {
				case <-exit.committed:
				case <-ctx.Done():
				}
			}
			return nil
		}, Handle: handleCoreRequest,
	}); err != nil {
		logger.Print(err)
	}
}

func relayCorePanel(ctx context.Context, title, body, accept string, checks []ipadncm.PanelCheck) (bool, []bool) {
	if ctx == nil {
		if owner := liveCore.Load(); owner != nil {
			ctx = owner.appCtx
		}
	}
	q := coreprompt.Question{Title: title, Body: body, Accept: accept}
	for _, c := range checks {
		q.Checks = append(q.Checks, coreprompt.Check{Text: c.Text, Checked: c.Checked, Disabled: c.Disabled})
	}
	a, err := prompts.Ask(ctx, q)
	if err != nil {
		return false, nil
	}
	return a.Accepted, a.Checks
}

func strictCorePayload(b json.RawMessage, out any) error {
	if !uniqueCorePayload(b) {
		return fmt.Errorf("CORE_PAYLOAD_INVALID")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("CORE_PAYLOAD_INVALID")
	}
	return nil
}

// Reject ambiguous field aliases/duplicates at every level before any typed
// decoder selects consent or an action. Product requests are shallow and fixed.
func uniqueCorePayload(b []byte) bool {
	if len(b) == 0 || len(b) > 32768 {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var walk func(int) bool
	walk = func(depth int) bool {
		if depth > 16 {
			return false
		}
		t, err := d.Token()
		if err != nil {
			return false
		}
		switch v := t.(type) {
		case json.Delim:
			switch v {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok {
						return false
					}
					name = strings.ToLower(name)
					if seen[name] {
						return false
					}
					seen[name] = true
					if !walk(depth + 1) {
						return false
					}
				}
				end, err := d.Token()
				return err == nil && end == json.Delim('}')
			case '[':
				for d.More() {
					if !walk(depth + 1) {
						return false
					}
				}
				end, err := d.Token()
				return err == nil && end == json.Delim(']')
			default:
				return false
			}
		default:
			return true
		}
	}
	return walk(0) && d.Decode(new(any)) == io.EOF
}

func handleCoreRequest(ctx context.Context, peer coreipc.Peer, request coreipc.Request) (coreipc.Response, error) {
	response := coreipc.Response{Version: 1, ID: request.ID}
	if !uniqueCorePayload(request.Payload) {
		return response, fmt.Errorf("CORE_PAYLOAD_INVALID")
	}
	owner := liveCore.Load()
	if owner == nil || owner.ctx.Err() != nil {
		response.Problem = "CORE_INITIALIZING"
		return response, nil
	}
	ipadncm.RecordAuthenticatedLogonTiming(peer.Session)
	switch request.Method {
	case "snapshot":
		var query struct {
			Replay    bool                 `json:"replay"`
			UITimings []uistartup.Timing   `json:"ui_timings,omitempty"`
			UIIPC     *ipadncm.UIIPCReport `json:"ui_ipc,omitempty"`
		}
		if err := strictCorePayload(request.Payload, &query); err != nil {
			return response, err
		}
		if query.UIIPC != nil {
			ipadncm.NoteUIIPCReport(*query.UIIPC)
		}
		if !uistartup.Record(query.UITimings, peer.PID, peer.Creation) {
			return response, fmt.Errorf("CORE_UI_TIMING_INVALID")
		}
		if query.Replay && !owner.exit.active() {
			_ = ipadncm.ServiceReplayDesktopRequests(owner.appCtx)
		}
		var display json.RawMessage
		var err error
		if !owner.exit.active() {
			display, err = ipadncm.ServiceDesktopSnapshot(owner.appCtx)
		}
		if err != nil && !owner.exit.active() {
			response.Problem = err.Error()
			return response, nil
		}
		display = owner.exit.display(display, ipadncm.DefaultNetworkIsolationDiagnostics(), version)
		display = extendDesktopSnapshot(display)
		type snapshotEnvelope struct {
			Version      string                   `json:"version"`
			Healthy      bool                     `json:"remote_usb_healthy"`
			Display      json.RawMessage          `json:"display"`
			Panel        *coreprompt.Question     `json:"panel,omitempty"`
			Timing       startuptelemetry.Report  `json:"startup_timing"`
			Options      map[string]bool          `json:"startup_options"`
			UpdateNotice *coreupdatenotice.Notice `json:"update_notice,omitempty"`
			LoginUI      *programLoginUIStatus    `json:"login_ui,omitempty"`
		}
		envelope := snapshotEnvelope{version, !owner.exit.active() && ipadncm.RemoteUSBConnectionHealthy(), display, prompts.Snapshot(), startuptelemetry.Snapshot(), startupopt.Snapshot(), coreUpdateNotices.Snapshot(coreNoticeClient(peer)), owner.exit.loginUIStatus(programExitOwner{SID: peer.SID, Session: peer.Session, PID: peer.PID, Creation: peer.Creation})}
		response.Payload, err = json.Marshal(envelope)
		if err == nil && len(response.Payload) > coreipc.MaxMessage-256 {
			// The display was measured before these sections joined it. Cut long
			// diagnostic text rather than leave the window unable to read at all.
			if trimmed, ok := ipadncm.TrimDisplayForTransport(envelope.Display, len(response.Payload)-(coreipc.MaxMessage-256)+512); ok {
				envelope.Display = trimmed
				response.Payload, err = json.Marshal(envelope)
			}
		}
		if err != nil || len(response.Payload) > coreipc.MaxMessage-256 {
			return response, fmt.Errorf("CORE_SNAPSHOT_LIMIT")
		}
	case "update-notice-ack":
		var notice coreupdatenotice.Notice
		if err := strictCorePayload(request.Payload, &notice); err != nil {
			return response, err
		}
		if err := coreUpdateNotices.Reply(coreNoticeClient(peer), notice); err != nil {
			response.Problem = err.Error()
		}
		response.Payload = json.RawMessage(`{}`)
	case "consent":
		if owner.exit.active() {
			response.Problem = "CORE_EXIT_IN_PROGRESS"
			return response, nil
		}
		var answer coreprompt.Answer
		if err := strictCorePayload(request.Payload, &answer); err != nil {
			return response, err
		}
		if err := prompts.Reply(answer); err != nil {
			response.Problem = err.Error()
		}
		response.Payload = json.RawMessage(`{}`)
	case "action":
		var exitCommand struct {
			Action string `json:"action"`
			ID     string `json:"id"`
		}
		_ = json.Unmarshal(request.Payload, &exitCommand)
		if exitCommand.Action == "ui-register" {
			var registration struct {
				Action string `json:"action"`
				Open   bool   `json:"ui_open"`
			}
			if err := strictCorePayload(request.Payload, &registration); err != nil || !peer.Elevated {
				return response, fmt.Errorf("CORE_UI_REGISTRATION_INVALID")
			}
			identity := programExitOwner{SID: peer.SID, Session: peer.Session, PID: peer.PID, Creation: peer.Creation}
			ui, err := pinProgramLoginUI(identity)
			if err != nil {
				return response, err
			}
			admitted, err := owner.exit.registerUI(identity, ui, registration.Open)
			if err != nil {
				response.Problem = err.Error()
			}
			response.Payload, _ = json.Marshal(struct {
				Admitted bool `json:"admitted"`
			}{admitted})
			return response, nil
		}
		if exitCommand.Action == "exit-program" || exitCommand.Action == "exit-program-commit" || exitCommand.Action == "restart-program" {
			if err := strictCorePayload(request.Payload, &exitCommand); err != nil || !validProgramExitID(exitCommand.ID) || !peer.Elevated || peer.SID == "" || peer.PID == 0 || peer.Session == 0 || peer.Creation == 0 {
				return response, fmt.Errorf("CORE_EXIT_REQUEST_INVALID")
			}
			restart := exitCommand.Action == "restart-program"
			if restart {
				if err := authorizeLocalRestart(exitCommand.ID, peer.SID, peer.Session, peer.PID, peer.Creation); err != nil {
					response.Problem = "LOCAL_RESTART_UNAVAILABLE"
					return response, nil
				}
				exitCommand.Action = "exit-program"
			}
			identity := programExitOwner{SID: peer.SID, Session: peer.Session, PID: peer.PID, Creation: peer.Creation}
			if exitCommand.Action == "exit-program" {
				if err := owner.exit.beginWithMode(exitCommand.ID, identity, restart); err != nil {
					response.Problem = err.Error()
				}
				response.Payload = json.RawMessage(`{}`)
			} else {
				after, err := owner.exit.prepareCommit(exitCommand.ID, identity)
				if err != nil {
					response.Problem = err.Error()
				} else {
					response.AfterAcknowledged = after
				}
				response.Payload, _ = json.Marshal(map[string]string{"event": "program-exit-complete", "request_id": exitCommand.ID})
			}
			return response, nil
		}
		if owner.exit.active() {
			response.Problem = "CORE_EXIT_IN_PROGRESS"
			return response, nil
		}
		if handled, e := internetAction(owner.appCtx, request.Payload); handled {
			if e != nil {
				response.Problem = e.Error()
			}
			response.Payload = json.RawMessage(`{}`)
			return response, nil
		}
		if reply, handled, err := ipadncm.ServiceSMBDesktopRead(owner.appCtx, request.Payload); handled {
			if err != nil {
				response.Problem = err.Error()
			} else {
				response.Payload = reply
			}
			return response, nil
		}
		if err := ipadncm.ServiceDesktopAction(owner.appCtx, request.Payload); err != nil {
			response.Problem = err.Error()
		}
		response.Payload = json.RawMessage(`{}`)
		if response.Problem == "" {
			if reply := ipadncm.PendingSMBUIReply(request.Payload); len(reply) > 0 {
				response.Payload = reply
			}
		}
	case "settings":
		if owner.exit.active() {
			response.Problem = "CORE_EXIT_IN_PROGRESS"
			return response, nil
		}
		var command struct {
			PrepareUninstall bool `json:"prepare_uninstall"`
		}
		if err := strictCorePayload(request.Payload, &command); err != nil || !command.PrepareUninstall {
			return response, fmt.Errorf("CORE_SETTINGS_COMMAND_INVALID")
		}
		if rt := currentInternet.Load(); rt != nil {
			rt.mu.Lock()
			e := rt.manager.Disable(owner.appCtx)
			rt.mu.Unlock()
			if e != nil {
				response.Problem = e.Error()
				return response, nil
			}
		}
		dir, ok := serviceDiagnosticDirectory.Load().(string)
		if !ok || dir == "" {
			response.Problem = "CORE_INITIALIZING"
			return response, nil
		}
		if err := interfaceconfig.RequestOwnedDADUninstall(dir); err != nil {
			response.Problem = err.Error()
			return response, nil
		}
		if err := interfaceconfig.RequestPersistentUninstall(dir); err != nil {
			response.Problem = err.Error()
			return response, nil
		}
		usbhost.RequestPersistentRestoreOnClose()
		response.Payload = json.RawMessage(`{}`)
	default:
		return response, fmt.Errorf("CORE_METHOD_UNSUPPORTED")
	}
	return response, nil
}

// Called only after the local uninstall confirmation. Source/token checks in
// coreipc authenticate this exact installed user's elevated process again.
func prepareCoreUninstall(ctx context.Context) error {
	status := connectioninstall.CoreServiceStatus()
	if status.Problem != "" {
		return fmt.Errorf("%s", status.Problem)
	}
	if !status.Installed {
		return nil
	}
	if err := connectioninstall.StartCoreService(); err != nil {
		return err
	}
	wait, stop := context.WithTimeout(ctx, 45*time.Second)
	defer stop()
	for wait.Err() == nil {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		call, cancel := context.WithTimeout(wait, 5*time.Second)
		r, err := coreipc.Call(call, coreipc.Request{Version: 1, ID: hex.EncodeToString(nonce[:]), Method: "settings", Payload: json.RawMessage(`{"prepare_uninstall":true}`)}, connectioninstall.VerifyCoreServiceProcess)
		cancel()
		if err == nil && r.Problem == "" {
			return nil
		}
		if err == nil && r.Problem != "CORE_INITIALIZING" {
			return fmt.Errorf("%s", r.Problem)
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-wait.Done():
			timer.Stop()
			return wait.Err()
		case <-timer.C:
		}
	}
	return wait.Err()
}

func setCoreStartup(ctx context.Context, enabled bool, exe string) error {
	previous, err := connectioninstall.ReadStartupTaskState(exe)
	if err != nil {
		return err
	}
	if err = connectioninstall.SetStartupContext(ctx, enabled, exe); err != nil {
		return err
	}
	if err = connectioninstall.SetCoreAutomatic(enabled); err != nil {
		if rollback := connectioninstall.SetStartupContext(ctx, previous.Enabled, exe); rollback != nil {
			return fmt.Errorf("%w; CORE_STARTUP_TASK_ROLLBACK: %v", err, rollback)
		}
		return err
	}
	return nil
}

func runCoreLoginUI(ctx context.Context, cancel context.CancelFunc, exe string, minimized bool) {
	// Whatever the exit path, no tray icon may outlive this process.
	defer ipadncm.RemoveTrayAndWait()
	loginStarted := time.Now()
	var loginNonce [16]byte
	loginRequest := ""
	if _, err := rand.Read(loginNonce[:]); err == nil {
		loginRequest = hex.EncodeToString(loginNonce[:])
	}
	var uiTimings uistartup.Queue
	recordLogin := func(stage string) {
		uiTimings.Add(uistartup.Timing{Request: loginRequest, Stage: stage, ElapsedUS: uint64(max(1, time.Since(loginStarted).Microseconds()))})
	}

	if connectioninstall.Verify(exe) != nil {
		dialog("介面來源驗證未通過；現有核心設定已保留。CORE_UI_SOURCE_UNPROVEN", 0x10)
		return
	}
	recordLogin("login-source-verified")
	// Pin only this fully verified process image before repeated service/binding
	// reads. The existing pin proves protected current binding and denies image
	// writes/deletes; foreign/upgrade targets still receive full independent hashes.
	// A failed early optimization retains the original complete verification path.
	if releaseSource, pinErr := connectioninstall.PinCoreSelfSource(exe); pinErr == nil {
		defer releaseSource()
		recordLogin("login-self-source-pinned")
	}
	if connectioninstall.StartCoreService() != nil {
		dialog("無法啟動已驗證的背景核心；請查看診斷。CORE_UI_START_FAILED", 0x10)
		return
	}
	recordLogin("login-service-start-verified")
	currentBinding, err := connectioninstall.CurrentCoreBinding()
	if err != nil {
		dialog("背景核心身份核對未通過；現有設定已保留。CORE_UI_BINDING_UNPROVEN", 0x10)
		return
	}
	// A preceding UI may hand off to the newly bound source. Only pin this
	// process when it remains the current source; foreign targets stay fully hashed.
	if strings.EqualFold(currentBinding.Executable, exe) {
		releaseSource, err := connectioninstall.PinCoreSelfSource(exe)
		if err != nil {
			dialog("介面來源保護未完成；現有核心設定已保留。CORE_UI_SOURCE_PIN_FAILED", 0x10)
			return
		}
		defer releaseSource()
		// Preserve a fresh final binding proof even when the mandatory pin reuses
		// the earlier immutable self handle. Pin reuse is never SCM authority.
		freshBinding, freshErr := connectioninstall.CurrentCoreBinding()
		if freshErr != nil || freshBinding != currentBinding {
			dialog("背景核心身份在啟動期間變更；現有設定已保留。CORE_UI_BINDING_CHANGED", 0x10)
			return
		}
	}
	recordLogin("login-service-bound")
	var bootstrapComplete atomic.Bool
	if remoteInstallID != "" {
		bootstrapBinding, err := connectioninstall.CurrentCoreBinding()
		if err != nil || bootstrapBinding.Executable != exe {
			return
		}
		defer func() {
			if bootstrapComplete.Load() {
				return
			}
			pending, err := connectioninstall.CoreBootstrapPending(remoteInstallID, version)
			if pending || err != nil {
				if bootstrapCreatedCore {
					_ = connectioninstall.RemoveExpectedCoreService(bootstrapBinding)
				} else {
					_ = connectioninstall.StopExpectedCoreService(bootstrapBinding)
				}
			}
		}()
	}
	confirmBootstrap := func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		if confirmLoginUIBootstrap(ctx, ticker.C, func() (bool, error) {
			return connectioninstall.CoreBootstrapPending(remoteInstallID, version)
		}, func() {
			_ = connectioninstall.ConfirmCoreBootstrap(ctx, remoteInstallID, version)
		}) {
			bootstrapComplete.Store(true)
		}
	}
	var pipeMu sync.Mutex
	call := func(callCtx context.Context, method string, payload json.RawMessage) (json.RawMessage, error) {
		pipeMu.Lock()
		defer pipeMu.Unlock()
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		r, err := coreipc.Call(callCtx, coreipc.Request{Version: 1, ID: hex.EncodeToString(nonce[:]), Method: method, Payload: payload}, connectioninstall.VerifyCoreServiceProcess)
		if err != nil {
			return nil, err
		}
		if r.Problem != "" {
			return nil, fmt.Errorf("%s", r.Problem)
		}
		return r.Payload, nil
	}
	// A verified core owns the single login UI for this user/session. Register
	// before any tray or renderer exists; a second launch only requests focus.
	registerCtx, registerStop := context.WithTimeout(ctx, 45*time.Second)
	registerPayload, _ := json.Marshal(map[string]any{"action": "ui-register", "ui_open": !minimized})
	var registration json.RawMessage
	for registerCtx.Err() == nil {
		registration, err = call(registerCtx, "action", registerPayload)
		if err == nil || err.Error() != "CORE_INITIALIZING" {
			break
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-registerCtx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	registerStop()
	admitted, confirmed := loginUIAdmission(registration)
	if err != nil || !confirmed {
		return
	}
	if !admitted {
		// Another verified UI can win registration during an upgrade. This
		// bootstrap process must still finish its original migration proof;
		// duplicate UI admission is not installation acceptance or failure.
		if remoteInstallID != "" {
			confirmBootstrap()
		}
		return
	}
	var panelMu sync.Mutex
	var panelWorkers sync.WaitGroup
	var panelID string
	var panelCancel context.CancelFunc
	updatePanel := func(q *coreprompt.Question) {
		panelMu.Lock()
		defer panelMu.Unlock()
		if q == nil {
			if panelCancel != nil {
				panelCancel()
				panelCancel = nil
			}
			panelID = ""
			return
		}
		if q.ID == panelID {
			return
		}
		if panelCancel != nil {
			panelCancel()
		}
		panelID = q.ID
		panelCtx, stop := context.WithCancel(ctx)
		panelCancel = stop
		panelWorkers.Add(1)
		go func() {
			defer panelWorkers.Done()
			var checks []ipadncm.PanelCheck
			for _, c := range q.Checks {
				checks = append(checks, ipadncm.PanelCheck{Text: c.Text, Checked: c.Checked, Disabled: c.Disabled})
			}
			yes, values := ipadncm.NativePanelWithContext(panelCtx, q.Title, q.Body, q.Accept, checks)
			if yes && q.Dependency != "" {
				if q.Dependency != "apple-support" {
					yes = false
				} else {
					e := dependencies.WithProgress(panelCtx, func(c context.Context) error { _, e := dependencies.Ensure(c, q.Dependency); return e })
					if e != nil {
						yes = false
						ipadncm.NativePanelWithContext(panelCtx, "元件尚未就緒", e.Error()+"\n受影響：iPad 通信。其他已滿足依賴的功能可繼續使用。", "知道了", nil)
					}
				}
			}

			if panelCtx.Err() != nil {
				return
			}
			if len(values) != len(checks) {
				values = make([]bool, len(checks))
				for i, c := range checks {
					values[i] = c.Checked
				}
			}
			b, _ := json.Marshal(coreprompt.Answer{ID: q.ID, Accepted: yes, Checks: values})
			_, _ = call(panelCtx, "consent", b)
		}()
	}
	defer func() { cancel(); updatePanel(nil); panelWorkers.Wait() }()
	var noticeMu sync.Mutex
	var renderedNoticeID string
	var replay atomic.Bool
	replay.Store(true)
	readFailure := func() {
		stopLoginUIForVerifiedReplacement(func() bool {
			return connectioninstall.LocalInstallationDraining(exe)
		}, func() bool {
			return handoffLoginUI(exe, minimized)
		}, cancel)
	}
	// Any failed call is kept with its specific cause for diagnostics. When the
	// core itself is gone or silent, start it again (never while exiting).
	recovery := coreRecovery{blocked: func() bool {
		return connectioninstall.LocalInstallationActive() || connectioninstall.CoreServiceTransitioning()
	}}
	linkFailed := func(operation string, err error) {
		outage, consecutive := ipadncm.RecordCoreLinkFailure(operation, err)
		if _, _, _, transport := coreipc.ErrorDetail(err); transport {
			replay.Store(true) // A replacement core must learn the pending display requests again.
		}
		if ctx.Err() != nil {
			return
		}
		action := recovery.Decide(time.Now(), err, outage, consecutive)
		if action == coreRecoveryNone {
			return
		}
		go func() {
			defer func() { recovery.Finish(time.Now()) }()
			result := "started"
			if ctx.Err() != nil || recovery.blocked() {
				return
			}
			binding, bindingErr := connectioninstall.CurrentCoreBinding()
			var recoverErr error
			switch {
			case bindingErr != nil || !strings.EqualFold(binding.Executable, exe):
				// A different verified core is the upgrade handoff's concern.
				recoverErr = fmt.Errorf("CORE_UI_RESTART_BINDING_CHANGED")
			default:
				if action == coreRecoveryRestart {
					result = "restarted"
					recoverErr = connectioninstall.StopCoreService()
				}
				if recoverErr == nil {
					recoverErr = connectioninstall.StartCoreService()
				}
			}
			if recoverErr != nil {
				code, _, _ := ipadncm.CoreLinkErrorCode(recoverErr)
				result = result + "_failed_" + code
			}
			ipadncm.RecordCoreRestartAttempt(result)
		}()
	}
	ipadncm.SetServiceUIProxy(&ipadncm.ServiceUIProxy{
		ObserveOpen: uiTimings.Add,
		Read: func(readCtx context.Context) (json.RawMessage, error) {
			// Re-register idempotently with the authenticated current core. A
			// replacement core must also know this still-running UI; a transient
			// pipe failure is never an instruction to terminate it.
			registration, registrationErr := call(readCtx, "action", json.RawMessage(`{"action":"ui-register","ui_open":false}`))
			if registrationErr != nil {
				readFailure()
				linkFailed("register", registrationErr)
				return nil, registrationErr
			}
			admitted, confirmed := loginUIAdmission(registration)
			if !confirmed {
				return nil, fmt.Errorf("CORE_UI_REGISTRATION_UNCONFIRMED")
			}
			if !admitted {
				cancel()
				return nil, fmt.Errorf("CORE_UI_ALREADY_REGISTERED")
			}
			timings := uiTimings.Take()
			linkReport, linkDelivered := ipadncm.TakeCoreLinkReport()
			q, _ := json.Marshal(struct {
				Replay    bool                 `json:"replay"`
				UITimings []uistartup.Timing   `json:"ui_timings,omitempty"`
				UIIPC     *ipadncm.UIIPCReport `json:"ui_ipc,omitempty"`
			}{replay.Swap(false), timings, linkReport})
			b, err := call(readCtx, "snapshot", q)
			if err != nil {
				uiTimings.Restore(timings)
				readFailure()
				linkFailed("read", err)
				return nil, err
			}
			linkDelivered()
			recovery.Healthy()
			var snapshot struct {
				Version      string                   `json:"version"`
				Display      json.RawMessage          `json:"display"`
				Panel        *coreprompt.Question     `json:"panel"`
				UpdateNotice *coreupdatenotice.Notice `json:"update_notice"`
				LoginUI      struct {
					ShowRequested bool `json:"show_requested"`
				} `json:"login_ui"`
			}
			if json.Unmarshal(b, &snapshot) != nil || snapshot.Version != version {
				return nil, fmt.Errorf("CORE_VERSION_CHANGED")
			}
			if loginUIFollowExit(snapshot.Display) {
				cancel()
				return snapshot.Display, nil
			}
			if snapshot.LoginUI.ShowRequested {
				ipadncm.ShowExistingConnectionUI()
			}
			updatePanel(snapshot.Panel)
			if snapshot.UpdateNotice != nil {
				err := func() error {
					noticeMu.Lock()
					defer noticeMu.Unlock()
					if renderedNoticeID == snapshot.UpdateNotice.ID {
						return nil
					}
					if err := ipadncm.ShowRemoteUpdateNotice(readCtx, snapshot.UpdateNotice.Version, snapshot.UpdateNotice.Phase); err != nil {
						return err
					}
					b, err := json.Marshal(snapshot.UpdateNotice)
					if err != nil {
						return err
					}
					if _, err = call(readCtx, "update-notice-ack", b); err != nil {
						return err
					}
					renderedNoticeID = snapshot.UpdateNotice.ID
					return nil
				}()
				if err != nil {
					return nil, err
				}
			}
			return snapshot.Display, nil
		}, Action: func(actionCtx context.Context, b json.RawMessage) (json.RawMessage, error) {
			var dep struct {
				Action string `json:"action"`
				ID     string `json:"id"`
			}
			if json.Unmarshal(b, &dep) == nil && dep.Action == "dependency-install" {
				if e := strictCorePayload(b, &dep); e != nil {
					return nil, e
				}
				if dep.ID != "all" {
					if _, e := dependencies.Lookup(dep.ID); e != nil {
						return nil, e
					}
				}
				e := dependencies.WithProgress(actionCtx, func(c context.Context) error {
					if dep.ID != "all" {
						_, e := dependencies.Retry(c, dep.ID)
						return e
					}
					var failures []error
					for _, asset := range dependencies.Catalog() {
						if e := c.Err(); e != nil {
							return errors.Join(append(failures, e)...)
						}
						if _, e := dependencies.Retry(c, asset.ID); e != nil {
							failures = append(failures, fmt.Errorf("%s: %w", asset.ID, e))
						}
					}
					return errors.Join(failures...)
				})
				if e != nil {
					return nil, e
				}
				return call(actionCtx, "action", json.RawMessage(`{"action":"dependency-refresh"}`))
			}
			reply, err := call(actionCtx, "action", b)
			if err != nil {
				// A refusal from the core is an answer, not an outage.
				if _, _, _, transport := coreipc.ErrorDetail(err); transport {
					linkFailed("action", err)
				}
			} else if dep.Action == "exit-program-commit" {
				// The core stops itself after this acknowledgement; the window
				// must not start it again while it is closing.
				recovery.Suppress()
			}
			return reply, err
		},
	})
	defer ipadncm.SetServiceUIProxy(nil)
	ipadncm.SetDesktopLauncher(prepareBundledDesktop)
	closeUI, problem := ipadncm.StartConnectionMonitor(ctx, cancel, minimized)
	if problem != "" {
		dialog(problem, 0x10)
		return
	}
	defer closeUI()
	bootstrapDone := make(chan struct{})
	if remoteInstallID != "" {
		// First migration's old worker owns this bootstrap PID. The verifier
		// independently authenticates the service and checks actual USB health.
		go func() {
			defer close(bootstrapDone)
			confirmBootstrap()
		}()
	} else {
		close(bootstrapDone)
	}
	<-ctx.Done()
	<-bootstrapDone
}

// A running login UI follows only the newly verified installed core binding.
// It cannot operate the previous version's engine after a successful upgrade.
func handoffLoginUI(exe string, minimized bool) bool {
	binding, err := connectioninstall.CurrentCoreBinding()
	if err != nil || binding.Executable == exe || connectioninstall.Verify(binding.Executable) != nil {
		return false
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid.String() != binding.OwnerSID {
		return false
	}
	var args []string
	if minimized {
		args = []string{"--resident"}
	}
	child := exec.Command(binding.Executable, args...)
	if err := child.Start(); err != nil {
		return false
	}
	_ = child.Process.Release()
	return true
}

// Only an independently verified elevated bound-owner pipe peer can claim or
// acknowledge a notice. PID creation ties delivery to that exact UI lifetime.
func coreNoticeClient(peer coreipc.Peer) coreupdatenotice.Client {
	if !peer.Elevated {
		return coreupdatenotice.Client{}
	}
	return coreupdatenotice.Client{PID: peer.PID, Session: peer.Session, Creation: peer.Creation}
}

func verifyCoreNoticeClientLifetime(client coreupdatenotice.Client) error {
	binding, err := connectioninstall.CurrentCoreBinding()
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil || binding.Executable != self {
		return fmt.Errorf("CORE_UPDATE_NOTICE_SOURCE_CHANGED")
	}
	return coreipc.VerifyOwnerClientLifetime(binding.OwnerSID, self, client.PID, client.Session, client.Creation, connectioninstall.VerifyCoreExecutable)
}
