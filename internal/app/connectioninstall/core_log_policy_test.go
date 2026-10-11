package connectioninstall

import (
	"bytes"
	"testing"
)

func TestCoreLogBoundsRetainTruncationAndRejectUnknownFileSize(t *testing.T) {
	short := []byte("normal log\n")
	if !bytes.Equal(coreLogMessage(short), short) {
		t.Fatal("normal event changed")
	}
	long := coreLogMessage(bytes.Repeat([]byte("x"), coreLogEventLimit*3))
	if len(long) != coreLogEventLimit || !bytes.HasSuffix(long, []byte(" [core log event truncated]\n")) {
		t.Fatal("event is not bounded or truncation is hidden")
	}
	if rotate, e := coreLogRotation(coreLogLimit-1, 1); e != nil || rotate {
		t.Fatal("exact maximum must fit")
	}
	if rotate, e := coreLogRotation(coreLogLimit-1, 2); e != nil || !rotate {
		t.Fatal("overflow must rotate before write")
	}
	for _, size := range []int64{-1, coreLogLimit + 1} {
		if _, e := coreLogRotation(size, 1); e == nil {
			t.Fatal("unknown oversized log must not be overwritten")
		}
	}
	if _, e := coreLogRotation(0, coreLogEventLimit+1); e == nil {
		t.Fatal("unbounded event accepted")
	}
}

func TestCoreLogManyEventsNeverExceedTwoFiles(t *testing.T) {
	var current, previous int64
	for i := 0; i < 10000; i++ {
		event := coreLogMessage(bytes.Repeat([]byte("x"), coreLogEventLimit+100))
		rotate, e := coreLogRotation(current, len(event))
		if e != nil {
			t.Fatal(e)
		}
		if rotate {
			previous = current
			current = 0
		}
		current += int64(len(event))
		if current > coreLogLimit || previous > coreLogLimit || current+previous > 2*coreLogLimit {
			t.Fatal("persistent log grew past bound")
		}
	}
}
