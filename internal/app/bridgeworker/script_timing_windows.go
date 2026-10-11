//go:build windows && amd64

package bridgeworker

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"time"
)

func runBridgeNetworkScript(ctx context.Context, operation, script string, l *log.Logger) (err error) {
	if !netconfig.BridgeNetworkScriptOperationValid(operation) || script == "" {
		return errors.New("USB_BRIDGE_SCRIPT_OPERATION_INVALID")
	}
	start := time.Now()
	defer func() {
		row := netconfig.BridgeNetworkScriptTiming{Operation: operation, Count: 1, DurationMS: float64(time.Since(start)) / float64(time.Millisecond), Success: err == nil}
		if b, e := json.Marshal(row); e == nil {
			l.Printf("%s%s", netconfig.BridgeNetworkScriptTimingPrefix, b)
		}
	}()
	return netconfig.RunContext(ctx, script, l)
}
