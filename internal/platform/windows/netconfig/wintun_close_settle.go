package netconfig

import (
	"context"
	"errors"
	"time"
)

// Two complete read-only absence observations are required. A timer bounds
// waiting for real completion; its expiration is never evidence of completion.
func waitWintunCloseSettle(ctx context.Context, observe func() (bool, error), deadline, poll <-chan time.Time) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		absent, err := observe()
		if err != nil {
			return err
		}
		if absent {
			if err := ctx.Err(); err != nil {
				return err
			}
			absent, err = observe()
			if err != nil {
				return err
			}
			if absent && ctx.Err() == nil {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return errors.New("USB_MAC_LIFETIME_CLOSE_ABSENCE_UNCONFIRMED")
		case <-poll:
		}
	}
}
