package installer

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestListWaitsThroughStartupAndRefresh(t *testing.T) {
	// The window and combo exist while first-run modal initialization blocks.
	// A transient refresh must also reset readiness.
	counts := []uintptr{0, 0, 5, 0, 5, 6, 6}
	i := 0
	count, err := waitDeviceList(context.Background(), time.Second, time.Millisecond, func() (uintptr, error) {
		if i >= len(counts) {
			t.Fatal("read past readiness")
		}
		v := counts[i]
		i++
		return v, nil
	})
	if err != nil || count != 6 || i != len(counts) {
		t.Fatalf("count=%d calls=%d err=%v", count, i, err)
	}
}

func TestListWaitStopsWithoutActions(t *testing.T) {
	_, err := waitDeviceList(context.Background(), 5*time.Millisecond, time.Millisecond, func() (uintptr, error) { return 0, nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = waitDeviceList(ctx, time.Second, time.Millisecond, func() (uintptr, error) { t.Fatal("queried after cancel"); return 0, nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	_, err = waitDeviceList(context.Background(), time.Second, time.Millisecond, func() (uintptr, error) { return ^uintptr(0), nil })
	if err == nil {
		t.Fatal("accepted CB_ERR")
	}
}

func TestUpdateQuestionNeverMatchesSecurityPrompts(t *testing.T) {
	question := "Do you want to allow Zadig to check for application updates online?"
	if !isUpdateQuestion("Zadig update policy", question) {
		t.Fatal("known update question rejected")
	}
	for _, prompt := range [][2]string{{"Windows Security", question}, {"Zadig update policy", "Install this driver?"}, {"Zadig update policy", "Do you want to install this certificate?"}, {"Driver Installation", "The driver was installed successfully."}} {
		if isUpdateQuestion(prompt[0], prompt[1]) {
			t.Fatal("answered unrelated prompt", prompt)
		}
	}
}
