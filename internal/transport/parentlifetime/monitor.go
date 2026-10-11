package parentlifetime

import "context"

// watch joins a potentially running wake callback before releasing its event.
// wait returns true for an external stop, parent exit or wait failure.
func watch(ctx context.Context, cancel context.CancelFunc, wake func(), wait func() bool, closeWake func()) func() {
	done := make(chan struct{})
	callbackDone := make(chan struct{})
	stopCallback := context.AfterFunc(ctx, func() { defer close(callbackDone); wake() })
	go func() {
		defer close(done)
		defer closeWake()
		defer func() {
			if !stopCallback() {
				<-callbackDone
			}
		}()
		if wait() {
			cancel()
		}
	}()
	return func() { cancel(); <-done }
}
