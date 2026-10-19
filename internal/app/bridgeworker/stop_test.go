package bridgeworker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestStopCodes(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{nil, StopGraceful},
		{context.Canceled, StopGraceful},
		{fmt.Errorf("USB_IN_READ_FAILED: Bulk IN: x"), StopUSBInRead},
		{fmt.Errorf("USB_IN_NTB_DECODE_FAILED: NTB decode: y"), StopUSBInNTB},
		{fmt.Errorf("USB_IN_RESUBMIT_FAILED: z"), StopUSBInResubmit},
		{fmt.Errorf("USB_OUT_COMPLETION_TIMEOUT: USB OUT completion exceeded 2s deadline"), StopUSBOutTimeout},
		{errors.New("WinUsb_WritePipe: failed"), StopUSBOutWrite},
		{fmt.Errorf("WINTUN_SEND_FAILED: Wintun send: q"), StopWintunSend},
		{fmt.Errorf("BRIDGE_PANIC: boom"), StopPanic},
		{errors.New("something else"), StopOther},
	} {
		if got := StopCode(c.err); got != c.want {
			t.Fatalf("%v: %s want %s", c.err, got, c.want)
		}
	}
	line := StopLine(errors.New("a\nb"+strings.Repeat("x", 600)), 2)
	if strings.ContainsAny(line, "\r\n") || !strings.HasPrefix(line, "BRIDGE_STOP code=BRIDGE_ERROR_OTHER exit_code=2 detail=a b") || len(line) > 600 {
		t.Fatal(line)
	}
}
