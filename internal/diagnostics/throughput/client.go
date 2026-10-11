package throughput

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// NativeClient exchanges bounded data only, with no browser or executable tasks.
type NativeClient struct {
	HTTP *http.Client
	Base string
}

func (c NativeClient) request(ctx context.Context, method, path, token, id string, body io.Reader) (*http.Response, error) {
	q, e := http.NewRequestWithContext(ctx, method, c.Base+path, body)
	if e != nil {
		return nil, e
	}
	q.Header.Set("X-Suhang-Test", token)
	q.Header.Set("X-Suhang-Run", id)
	r, e := c.HTTP.Do(q)
	if e != nil {
		return nil, e
	}
	if r.StatusCode != 200 {
		io.Copy(io.Discard, io.LimitReader(r.Body, 1024))
		r.Body.Close()
		return nil, fmt.Errorf("native test status %d", r.StatusCode)
	}
	return r, nil
}
func (c NativeClient) Poll(ctx context.Context) (NativeCommand, error) {
	var v NativeCommand
	start := time.Now()
	r, e := c.request(ctx, "GET", "/speed/native", "", "", nil)
	if e != nil {
		return v, e
	}
	defer r.Body.Close()
	e = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&v)
	if e == nil && (len(v.Token) != 48 || v.Chunk != ChunkBytes || v.Streams != Streams || v.Seconds != 10 || v.MaxBytes != MaxDirectionBytes) {
		e = fmt.Errorf("native protocol mismatch")
	}
	if e == nil {
		c.sendLatency(ctx, v.Token, float64(time.Since(start))/float64(time.Millisecond))
	}
	return v, e
}
func (c NativeClient) Start(ctx context.Context, v NativeCommand) error {
	r, e := c.request(ctx, "POST", "/speed/native/start", v.Token, "", nil)
	if e != nil {
		return e
	}
	r.Body.Close()
	return nil
}
func (c NativeClient) ping(ctx context.Context, v NativeCommand) (float64, error) {
	t := time.Now()
	r, e := c.request(ctx, "GET", "/speed/ping", v.Token, v.ID, nil)
	if e != nil {
		return 0, e
	}
	_, e = io.Copy(io.Discard, io.LimitReader(r.Body, 1024))
	r.Body.Close()
	return float64(time.Since(t)) / float64(time.Millisecond), e
}
func (c NativeClient) Run(ctx context.Context, v NativeCommand) (report Report, err error) {
	ctx, cancel := context.WithTimeout(ctx, 65*time.Second)
	defer cancel()
	defer func() {
		if err != nil {
			clean, stop := context.WithTimeout(context.Background(), 2*time.Second)
			defer stop()
			if r, e := c.request(clean, "POST", "/speed/cancel", v.Token, v.ID, nil); e == nil {
				r.Body.Close()
			}
		}
	}()
	var idle []float64
	for i := 0; i < 12; i++ {
		n, e := c.ping(ctx, v)
		if e != nil {
			return report, e
		}
		idle = append(idle, n)
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	for _, direction := range []string{"download", "upload"} {
		phase, stop := context.WithCancel(ctx)
		start := time.Now()
		end := start.Add(time.Duration(v.Seconds) * time.Second)
		var reserved, total atomic.Int64
		var workers sync.WaitGroup
		errors := make(chan error, Streams+1)
		rtts := make(chan []float64, 1)
		go func() {
			var samples []float64
			for phase.Err() == nil {
				n, e := c.ping(phase, v)
				if e != nil {
					if phase.Err() == nil {
						errors <- e
						stop()
					}
					break
				}
				samples = append(samples, n)
				select {
				case <-phase.Done():
				case <-time.After(180 * time.Millisecond):
				}
			}
			rtts <- samples
		}()
		for i := 0; i < Streams; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				body := make([]byte, v.Chunk)
				for time.Now().Before(end) && phase.Err() == nil {
					if reserved.Add(int64(v.Chunk)) > v.MaxBytes {
						return
					}
					path, method := "/speed/down", "GET"
					var input io.Reader
					if direction == "upload" {
						path, method = "/speed/up", "POST"
						input = bytes.NewReader(body)
					}
					r, e := c.request(phase, method, path, v.Token, v.ID, input)
					if e != nil {
						errors <- e
						stop()
						return
					}
					var n int64
					if direction == "download" {
						n, e = io.CopyBuffer(io.Discard, r.Body, make([]byte, 64*1024))
					} else {
						var reply struct {
							Bytes int64 `json:"bytes"`
						}
						e = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&reply)
						n = reply.Bytes
					}
					r.Body.Close()
					if e != nil || n != int64(v.Chunk) {
						errors <- fmt.Errorf("incomplete native chunk")
						stop()
						return
					}
					total.Add(n)
				}
			}()
		}
		workers.Wait()
		seconds := time.Since(start).Seconds()
		stop()
		samples := <-rtts
		select {
		case e := <-errors:
			return report, e
		default:
		}
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		b, _ := json.Marshal(finishRequest{Direction: direction, Bytes: total.Load(), Seconds: seconds, RTT: samples, Idle: idle})
		var e error
		for attempt := 0; attempt < 10; attempt++ {
			var r *http.Response
			r, e = c.request(ctx, "POST", "/speed/finish", v.Token, v.ID, bytes.NewReader(b))
			if e == nil {
				e = json.NewDecoder(io.LimitReader(r.Body, 16384)).Decode(&report)
				r.Body.Close()
				break
			}
			select {
			case <-ctx.Done():
				return report, ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		if e != nil {
			return report, e
		}
		idle = nil
	}
	return report, nil
}

func (c NativeClient) sendLatency(ctx context.Context, token string, ms float64) {
	b, _ := json.Marshal(map[string]float64{"ms": ms})
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if r, e := c.request(ctx, "POST", "/speed/latency", token, "", bytes.NewReader(b)); e == nil {
		io.Copy(io.Discard, io.LimitReader(r.Body, 1024))
		r.Body.Close()
	}
}
