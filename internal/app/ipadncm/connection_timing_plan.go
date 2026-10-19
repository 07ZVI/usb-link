package ipadncm

import "time"

type connectionTimingPlan struct {
	revision        uint64
	mode            string
	fallback, delay time.Duration
	changed         <-chan struct{}
}
