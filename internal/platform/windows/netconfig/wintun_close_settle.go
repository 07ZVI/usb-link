package netconfig

import (
	"context"
	"errors"
	"time"
)

// Two complete read-only absence observations are required. A timer bounds
// waiting for real completion; its expiration is never evidence of completion.
func waitWintunCloseSettle(ctx context.Context, observe func() (bool, error), deadline, poll <-chan time.Time) error {
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case <-deadline:
			return errors.New("USB_MAC_LIFETIME_CLOSE_ABSENCE_UNCONFIRMED")
		default:
			return nil
		}
	}
	for {
		if err := check(); err != nil {
			return err
		}
		absent, err := observe()
		if expired := check(); expired != nil {
			return expired
		}
		if err != nil {
			return err
		}
		if absent {
			if err := check(); err != nil {
				return err
			}
			absent, err = observe()
			if expired := check(); expired != nil {
				return expired
			}
			if err != nil {
				return err
			}
			if absent {
				return check()
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
