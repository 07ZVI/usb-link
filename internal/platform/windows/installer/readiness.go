package installer

import (
	"context"
	"fmt"
	"time"
)

// waitDeviceList treats an empty startup combo as pending, not a device failure.
// Require two consecutive nonempty counts so initialization has time to settle.
func waitDeviceList(ctx context.Context, timeout, interval time.Duration, sample func() (uintptr, error)) (uintptr, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var previous uintptr
	for {
		if err := ctx.Err(); err != nil {
			return 0, fmt.Errorf("Zadig device list did not become ready: %w", err)
		}
		count, err := sample()
		if err != nil {
			return 0, err
		}
		if count > 512 {
			return 0, fmt.Errorf("invalid Zadig list count: %d", count)
		}
		if count > 0 && count == previous {
			return count, nil
		}
		previous = count
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("Zadig device list did not become ready: %w", ctx.Err())
		case <-time.After(interval):
		}
	}
}

// Only this optional update question is answered automatically. Installation,
// certificate and other security prompts are never included.
func isUpdateQuestion(title, body string) bool {
	return title == "Zadig update policy" && body == "Do you want to allow Zadig to check for application updates online?"
}
