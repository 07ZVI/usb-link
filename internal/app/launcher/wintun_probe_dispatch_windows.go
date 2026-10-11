//go:build windows && amd64

package launcher

import (
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"strings"
	"suhang/usbnet/internal/transport/parentlifetime"
)

// This private fixed helper must never enter the installer, SCM or desktop path.
func dispatchWintunLifecycleProbe() bool {
	if len(os.Args) < 2 || !strings.HasPrefix(os.Args[1], "--wintun-lifecycle-probe") {
		return false
	}
	flags := flag.NewFlagSet("wintun-lifecycle-probe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("wintun-lifecycle-probe", "", "")
	parentHandle := flags.Uint64("wintun-probe-parent-handle", 0, "")
	pid := flags.Uint64("wintun-probe-parent-pid", 0, "")
	creation := flags.Uint64("wintun-probe-parent-creation", 0, "")
	start := flags.Uint64("wintun-probe-start-handle", 0, "")
	stop := flags.Uint64("wintun-probe-stop-handle", 0, "")
	if flags.Parse(os.Args[1:]) != nil || flags.NArg() != 0 || flags.NFlag() != 6 || len(os.Args) != 7 || (*mode != "off" && *mode != "on") || *parentHandle == 0 || *pid == 0 || *pid > 0xffffffff || *creation == 0 || *start == 0 || *stop == 0 {
		fmt.Fprintln(os.Stderr, "WINTUN_PROBE_CHILD_ARGUMENT_INVALID")
		os.Exit(1)
	}
	archive, err := macArchive("assets/mac-payload.zip")
	manifest, manifestErr := payload.ReadFile("assets/mac-sources.json")
	if err != nil || manifestErr != nil {
		fmt.Fprintln(os.Stderr, "WINTUN_PROBE_CHILD_PAYLOAD_UNAVAILABLE")
		os.Exit(1)
	}
	result, err := executeWintunLifecycleProbe(*mode == "on", parentlifetime.Link{Handle: windows.Handle(*parentHandle), PID: uint32(*pid), Creation: *creation}, windows.Handle(*start), windows.Handle(*stop), archive, manifest)
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "WINTUN_PROBE_CHILD_FAILED")
		os.Exit(1)
	}
	return true
}
