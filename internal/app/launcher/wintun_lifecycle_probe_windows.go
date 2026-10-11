//go:build windows && amd64

package launcher

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/app/macconnection"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/transport/parentlifetime"
	"syscall"
	"unsafe"
)

// Only the installed SCM self can launch this fixed experiment. Its child waits
// for the parent's captured PID/creation/image check before the first Create.
// Cancellation signals cooperative cleanup and joins the child; it never kills
// or abandons the synchronous official PnP call.
func runWintunLifecycleProbe(ctx context.Context, hold bool) (report netconfig.WintunLifetimeProbeReport, result error) {
	if ctx == nil || ctx.Err() != nil {
		return report, errors.New("WINTUN_PROBE_PARENT_CONTEXT_INVALID")
	}
	pin, err := connectioninstall.PinCoreSourceBatchSelf()
	if err != nil {
		return report, errors.New("WINTUN_PROBE_PARENT_OWNER_UNPROVEN")
	}
	defer pin.Close()
	exe, err := os.Executable()
	if err != nil {
		return report, errors.New("WINTUN_PROBE_SELF_UNAVAILABLE")
	}
	link, err := parentlifetime.Prepare()
	if err != nil {
		return report, err
	}
	defer link.Close()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return report, errors.New("WINTUN_PROBE_EVENTS_UNPROVEN")
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd, InheritHandle: 1}
	start, err := windows.CreateEvent(sa, 1, 0, nil)
	if err != nil {
		return report, errors.New("WINTUN_PROBE_START_EVENT_UNAVAILABLE")
	}
	defer windows.CloseHandle(start)
	stop, err := windows.CreateEvent(sa, 1, 0, nil)
	if err != nil {
		return report, errors.New("WINTUN_PROBE_STOP_EVENT_UNAVAILABLE")
	}
	defer windows.CloseHandle(stop)
	mode := "off"
	if hold {
		mode = "on"
	}
	value := func(n uint64) string { return strconv.FormatUint(n, 10) }
	cmd := exec.Command(exe, "--wintun-lifecycle-probe="+mode,
		"--wintun-probe-parent-handle="+value(uint64(link.Handle)),
		"--wintun-probe-parent-pid="+value(uint64(link.PID)),
		"--wintun-probe-parent-creation="+value(link.Creation),
		"--wintun-probe-start-handle="+value(uint64(start)),
		"--wintun-probe-stop-handle="+value(uint64(stop)))
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW, AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(link.Handle), syscall.Handle(start), syscall.Handle(stop)}}
	var out, diagnostic probeBoundedOutput
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	if err := pin.Complete(); err != nil {
		return report, errors.New("WINTUN_PROBE_PARENT_OWNER_CHANGED")
	}
	if err := cmd.Start(); err != nil {
		return report, errors.New("WINTUN_PROBE_CHILD_START_FAILED")
	}
	// Retain the actual captured process handle until after Wait/JSON readback.
	h, openErr := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
	if openErr != nil {
		windows.SetEvent(stop)
		_ = cmd.Wait()
		return report, errors.New("WINTUN_PROBE_CHILD_HANDLE_UNAVAILABLE")
	}
	defer windows.CloseHandle(h)
	creation, openErr := probeChildIdentity(h, uint32(cmd.Process.Pid), exe)
	if openErr != nil || pin.Complete() != nil || ctx.Err() != nil {
		windows.SetEvent(stop)
		_ = cmd.Wait()
		if openErr != nil {
			return report, openErr
		}
		if ctx.Err() != nil {
			return report, errors.New("WINTUN_PROBE_PARENT_CANCELLED_BEFORE_RELEASE")
		}
		return report, errors.New("WINTUN_PROBE_PARENT_SOURCE_CHANGED_BEFORE_RELEASE")
	}
	if windows.SetEvent(start) != nil {
		windows.SetEvent(stop)
		_ = cmd.Wait()
		return report, errors.New("WINTUN_PROBE_CHILD_RELEASE_FAILED")
	}
	// A crashing helper may never render JSON. Retain only parent-captured
	// process identity and an explicit unknown observation, never infer absence.
	report = netconfig.WintunLifetimeProbeReport{Schema: 1, ObservationOnly: true, HoldModule: hold, ProcessID: uint32(cmd.Process.Pid), ProcessCreation: creation, Stage: "transport_verification_failed", Rounds: []netconfig.WintunLifetimeProbeRound{}}
	done := probeWaitDone(cmd)
	var waitErr error
	select {
	case <-ctx.Done():
		windows.SetEvent(stop)
		waitErr = <-done // join even beyond cancellation; never abandon native Create.
	case waitErr = <-done:
	}
	if out.exceeded || diagnostic.exceeded || out.Len() == 0 {
		report.Code = "WINTUN_PROBE_CHILD_OUTPUT_UNPROVEN"
		return report, errors.New(report.Code)
	}
	var received netconfig.WintunLifetimeProbeReport
	if strictCorePayload(out.Bytes(), &received) != nil || netconfig.ValidateWintunLifetimeProbeReport(received, hold, uint32(cmd.Process.Pid), creation) != nil {
		report.Code = "WINTUN_PROBE_CHILD_REPORT_INVALID"
		return report, errors.New(report.Code)
	}
	report = received
	// Read the bounded, strictly bound observation before the final transport
	// proof so failure does not discard what the child reported doing. This
	// still cannot authorize success: any failed proof marks it non-admissible.
	exitCode, err := probeExitedChildIdentity(h, uint32(cmd.Process.Pid), creation)
	if err != nil {
		return probeTransportFailure(report, err.Error())
	}
	if pin.Complete() != nil {
		return probeTransportFailure(report, "WINTUN_PROBE_PARENT_SOURCE_CHANGED_AFTER_WAIT")
	}
	if ctx.Err() != nil {
		return probeTransportFailure(report, "WINTUN_PROBE_PARENT_CANCELLED")
	}
	if report.Code != "" {
		return report, errors.New(report.Code)
	}
	if waitErr != nil || exitCode != 0 {
		return probeTransportFailure(report, "WINTUN_PROBE_CHILD_EXIT_UNCONFIRMED")
	}
	return report, nil
}

// A private waiter prevents duplicate Wait and keeps all process output joined.
func probeWaitDone(cmd *exec.Cmd) <-chan error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); close(done) }()
	return done
}

type probeBoundedOutput struct {
	bytes.Buffer
	exceeded bool
}

func (b *probeBoundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := 32768 - b.Len()
	if n > remaining {
		b.exceeded = true
		p = p[:remaining]
	}
	_, _ = b.Buffer.Write(p)
	return n, nil // drain all child output, even when the strict bound is exceeded.
}

// Before release, the live child image must be the held, verified installed
// source. This check is never repeated against the image/PEB of an exited child.
func probeChildIdentity(h windows.Handle, pid uint32, exe string) (uint64, error) {
	actual, err := windows.GetProcessId(h)
	if err != nil {
		return 0, errors.New("WINTUN_PROBE_CHILD_PID_UNREADABLE")
	}
	if actual != pid || pid == 0 {
		return 0, errors.New("WINTUN_PROBE_CHILD_PID_CHANGED")
	}
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) != nil {
		return 0, errors.New("WINTUN_PROBE_CHILD_CREATION_UNREADABLE")
	}
	creation := probeFiletime(created)
	if creation == 0 {
		return 0, errors.New("WINTUN_PROBE_CHILD_CREATION_UNPROVEN")
	}
	var path [32768]uint16
	size := uint32(len(path))
	if windows.QueryFullProcessImageName(h, 0, &path[0], &size) != nil {
		return 0, errors.New("WINTUN_PROBE_CHILD_IMAGE_UNREADABLE")
	}
	if size == 0 || size >= uint32(len(path)) || !strings.EqualFold(windows.UTF16ToString(path[:size]), exe) {
		return 0, errors.New("WINTUN_PROBE_CHILD_IMAGE_CHANGED")
	}
	if connectioninstall.VerifyCoreExecutable(exe) != nil {
		return 0, errors.New("WINTUN_PROBE_CHILD_SOURCE_CHANGED_BEFORE_RELEASE")
	}
	return creation, nil
}

// The same retained process object survives cmd.Wait closing its private
// handle. Kernel PID/creation and signaled termination remain the proof; an
// exited process no longer needs to have a readable image/PEB. Source bytes and
// the protected SCM binding are separately held by the parent's source pin.
func probeExitedChildIdentity(h windows.Handle, pid uint32, creation uint64) (uint32, error) {
	actual, err := windows.GetProcessId(h)
	if err != nil {
		return 0, errors.New("WINTUN_PROBE_CHILD_PID_UNREADABLE_AFTER_WAIT")
	}
	if actual != pid || pid == 0 {
		return 0, errors.New("WINTUN_PROBE_CHILD_PID_CHANGED_AFTER_WAIT")
	}
	var created, exited, kernel, user windows.Filetime
	if windows.GetProcessTimes(h, &created, &exited, &kernel, &user) != nil {
		return 0, errors.New("WINTUN_PROBE_CHILD_TIMES_UNREADABLE_AFTER_WAIT")
	}
	if creation == 0 || probeFiletime(created) != creation {
		return 0, errors.New("WINTUN_PROBE_CHILD_CREATION_CHANGED_AFTER_WAIT")
	}
	state, err := windows.WaitForSingleObject(h, 0)
	if err != nil || state != windows.WAIT_OBJECT_0 {
		return 0, errors.New("WINTUN_PROBE_CHILD_TERMINATION_UNPROVEN")
	}
	if probeFiletime(exited) == 0 {
		return 0, errors.New("WINTUN_PROBE_CHILD_EXIT_TIME_UNPROVEN")
	}
	var exitCode uint32
	if windows.GetExitCodeProcess(h, &exitCode) != nil {
		return 0, errors.New("WINTUN_PROBE_CHILD_EXIT_CODE_UNREADABLE")
	}
	return exitCode, nil
}

func probeFiletime(v windows.Filetime) uint64 {
	return uint64(v.HighDateTime)<<32 | uint64(v.LowDateTime)
}

// Keep strict parsed rounds for diagnosis when transport cannot be proven.
// This parent-only error is deliberately rejected by the child-report admission
// validator. Keep the child's original stage and code, too; a transport failure
// never means no Create happened, even when rounds are absent.
func probeTransportFailure(v netconfig.WintunLifetimeProbeReport, code string) (netconfig.WintunLifetimeProbeReport, error) {
	v.TransportError = code
	return v, errors.New(code)
}

// Main dispatch supplies only compiled-in archive/manifest and these inherited
// fixed handles. No CLI can select a DLL, adapter, command or source path.
func executeWintunLifecycleProbe(hold bool, link parentlifetime.Link, start, stop windows.Handle, archive macconnection.RuntimeArchive, manifest []byte) (report netconfig.WintunLifetimeProbeReport, result error) {
	exe, err := os.Executable()
	if err != nil || start == 0 || stop == 0 || start == stop || link.Handle == start || link.Handle == stop || link.Validate() != nil || connectioninstall.VerifyCoreExecutable(exe) != nil {
		return report, errors.New("WINTUN_PROBE_CHILD_AUTHORIZATION_UNPROVEN")
	}
	defer windows.CloseHandle(start)
	defer windows.CloseHandle(stop)
	defer link.Close()
	pin, err := connectioninstall.PinCoreSourceBatchParent(exe, link)
	if err != nil {
		return report, errors.New("WINTUN_PROBE_PARENT_SOURCE_UNPROVEN")
	}
	defer pin.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	join, err := link.Watch(ctx, cancel, stop)
	if err != nil {
		return report, err
	}
	defer join()
	state, err := windows.WaitForMultipleObjects([]windows.Handle{stop, link.Handle, start}, false, 15000)
	if err != nil || state != windows.WAIT_OBJECT_0+2 || ctx.Err() != nil || pin.Complete() != nil {
		return report, errors.New("WINTUN_PROBE_PARENT_RELEASE_UNPROVEN")
	}
	dir, err := connectioninstall.SecurityDirectory()
	if err != nil {
		return report, errors.New("WINTUN_PROBE_RUNTIME_ROOT_UNPROVEN")
	}
	dll, err := macconnection.PrepareSharedHostDLLArchive(dir, archive, manifest)
	if err != nil || pin.Complete() != nil {
		return report, errors.New("WINTUN_PROBE_BUILTIN_DLL_UNPROVEN")
	}
	owner := func() error {
		if ctx.Err() != nil || link.Validate() != nil {
			return fmt.Errorf("WINTUN_PROBE_PARENT_EXITED")
		}
		return pin.Complete()
	}
	return netconfig.RunWintunModuleLifetimeSelfTest(ctx, dll, hold, owner)
}
