package connectioninstall

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestDeletedInstallBackupAndProofPrecedeEveryRemoval(t *testing.T) {
	failure := errors.New("failure")
	for _, failAt := range []string{"backup", "recheck", "service", "registration", "verify", ""} {
		var calls []string
		invoke := func(name string) error {
			calls = append(calls, name)
			if name == failAt {
				return failure
			}
			return nil
		}
		a := deletedInstallRemoval{
			Backup:       func() (string, error) { return "before.json", invoke("backup") },
			Recheck:      func() error { return invoke("recheck") },
			Service:      func() error { return invoke("service") },
			Registration: func() error { return invoke("registration") },
			VerifyClean:  func() error { return invoke("verify") },
		}
		backup, e := runDeletedInstallRemoval(context.Background(), a)
		want := []string{"backup", "recheck", "service", "registration", "verify"}
		if failAt != "" {
			for i, n := range want {
				if n == failAt {
					want = want[:i+1]
					break
				}
			}
		}
		if backup != "before.json" || !reflect.DeepEqual(want, calls) || (failAt != "" && !errors.Is(e, failure)) {
			t.Fatalf("%s: backup=%s calls=%v err=%v", failAt, backup, calls, e)
		}
	}
}

func TestDeletedInstallCancellationBeforeAndDuringRemoval(t *testing.T) {
	for _, cancelAt := range []string{"before", "backup", "service"} {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var calls []string
		step := func(name string) error {
			calls = append(calls, name)
			if cancelAt == name {
				cancel()
			}
			return nil
		}
		a := deletedInstallRemoval{
			Backup:       func() (string, error) { return "before.json", step("backup") },
			Recheck:      func() error { return step("recheck") },
			Service:      func() error { return step("service") },
			Registration: func() error { return step("registration") },
			VerifyClean:  func() error { return step("verify") },
		}
		if cancelAt == "before" {
			cancel()
		}
		_, e := runDeletedInstallRemoval(ctx, a)
		if cancelAt == "before" && (len(calls) != 0 || !errors.Is(e, context.Canceled)) {
			t.Fatal(calls, e)
		}
		if cancelAt == "backup" && (!reflect.DeepEqual(calls, []string{"backup", "recheck"}) || !errors.Is(e, context.Canceled)) {
			t.Fatal(calls, e)
		}
		if cancelAt == "service" && (!reflect.DeepEqual(calls, []string{"backup", "recheck", "service", "registration", "verify"}) || e != nil) {
			t.Fatal("cleanup stopped halfway on cancellation", calls, e)
		}
	}
}
