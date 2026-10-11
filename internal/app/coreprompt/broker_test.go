package coreprompt

import (
	"context"
	"testing"
	"time"
)

func TestCancellationAndStaleAnswerCannotAuthorize(t *testing.T) {
	b := New()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := b.Ask(ctx, Question{Title: "device", Checks: []Check{{Checked: true, Disabled: true}}})
		done <- err
	}()
	var q *Question
	deadline := time.Now().Add(time.Second)
	for q == nil && time.Now().Before(deadline) {
		q = b.Snapshot()
		time.Sleep(time.Millisecond)
	}
	if q == nil {
		t.Fatal("missing question")
	}
	if b.Reply(Answer{ID: q.ID, Accepted: true, Checks: []bool{false}}) == nil {
		t.Fatal("disabled field changed")
	}
	cancel()
	if <-done == nil {
		t.Fatal("cancel accepted")
	}
	if b.Reply(Answer{ID: q.ID, Accepted: true, Checks: []bool{true}}) == nil {
		t.Fatal("stale accepted")
	}
}
func TestReplyIsSingleUseAndSnapshotIsCopy(t *testing.T) {
	b := New()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan Answer, 1)
	go func() {
		a, _ := b.Ask(ctx, Question{Checks: []Check{{Text: "remember", Checked: true, Disabled: true}}})
		done <- a
	}()
	var q *Question
	for q == nil && ctx.Err() == nil {
		q = b.Snapshot()
		time.Sleep(time.Millisecond)
	}
	if q == nil {
		t.Fatal("missing question")
	}
	q.Checks[0].Disabled = false
	if b.Snapshot().Checks[0].Disabled != true {
		t.Fatal("snapshot aliases pending")
	}
	a := Answer{ID: q.ID, Accepted: true, Checks: []bool{true}}
	if err := b.Reply(a); err != nil {
		t.Fatal(err)
	}
	if b.Reply(a) == nil {
		t.Fatal("duplicate accepted")
	}
	if answer := <-done; !answer.Accepted {
		t.Fatal("answer lost")
	}
}
