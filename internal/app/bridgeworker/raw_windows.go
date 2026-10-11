//go:build windows && amd64

package bridgeworker

import (
	"context"
	"encoding/hex"
	"fmt"
	"suhang/usbnet/internal/diagnostics/bench"
	"suhang/usbnet/internal/diagnostics/rawusb"
	"suhang/usbnet/internal/transport/bridge"
	"suhang/usbnet/internal/transport/ncm"
	"suhang/usbnet/internal/transport/winusb"
	"sync/atomic"
	"time"
)

func rawRunner(bridgeCtx context.Context, rx *atomic.Pointer[rawusb.Receiver], work chan<- func() error, peer func() bridge.Peer, writer *winusb.Writer, parameters ncm.Parameters, encoded *[]byte, sequence *uint16) bench.RawRunner {
	return func(ctx context.Context, kind string, seconds int, nonceString string, ready func(int) error) (rawusb.Result, error) {
		var nonce [16]byte
		b, err := hex.DecodeString(nonceString)
		if err != nil || len(b) != 16 {
			return rawusb.Result{}, fmt.Errorf("raw nonce")
		}
		copy(nonce[:], b)
		direction, _, _, ok := rawusb.Command(kind)
		if !ok {
			return rawusb.Result{}, fmt.Errorf("raw kind")
		}
		p := peer()
		if p.MAC == [6]byte{} || p.MTU < rawusb.InputIPLength {
			return rawusb.Result{}, fmt.Errorf("raw requires resolved peer and verified MTU >= 8000")
		}
		_, percent, _ := bench.GCSettings()
		if percent != 100 || !bench.ReuseBuffers() {
			return rawusb.Result{}, fmt.Errorf("restore default buffers/GC100 before raw test")
		}
		r := rawusb.Result{Kind: kind, Nonce: nonceString, Direction: direction}
		if direction == "mac_to_windows" {
			r.IPLength = rawusb.InputIPLength
			receiver := &rawusb.Receiver{Nonce: nonce, MAC: p.MAC, Counter: rawusb.NewCounter()}
			if !rx.CompareAndSwap(nil, receiver) {
				return r, fmt.Errorf("raw receiver still draining")
			}
			start := time.Now()
			defer func() {
				receiver.Counter.Stop()
				time.AfterFunc(time.Second, func() { rx.CompareAndSwap(receiver, nil) })
			}()
			if err = ready(r.IPLength); err != nil {
				return r, err
			}
			timer := time.NewTimer(time.Duration(seconds) * time.Second)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				return r, ctx.Err()
			case <-bridgeCtx.Done():
				return r, bridgeCtx.Err()
			}
			r.Seconds = time.Since(start).Seconds()
			r.Counts = receiver.Counter.Stop()
			r.CompletedUSBBytes = r.Counts.USBReadBytes
			r.CompletedUSBTransfers = r.Counts.USBReads
			r.CompletedIPBytes = r.Counts.IPBytes
			r.CompletedUDPPayloadBytes = r.Counts.UniquePayloadBytes
			return r, nil
		}
		// The job runs on the sole OUT worker; ordinary pinned requests are fully
		// collected before the experiment starts. Default packet traffic resumes
		// after at most seconds+the existing two-second I/O completion deadline.
		result := make(chan struct {
			r rawusb.Result
			e error
		}, 1)
		job := func() error {
			var transportErr error
			e := func() error {
				if err := writer.Flush(bridgeCtx); err != nil {
					transportErr = err
					return err
				}
				r.BeforePending = writer.Pending()
				r.IPLength = min(p.MTU, 16000)
				count, err := ncm.BatchLimit(parameters, r.IPLength+14, 16)
				if err != nil {
					return err
				}
				r.FramesPerNTB = count
				frames := make([][]byte, count)
				for i := range frames {
					frames[i], err = rawusb.Frame(r.IPLength, nonce, p.MAC)
					if err != nil {
						return err
					}
				}
				block, err := ncm.EncodeInto(*encoded, frames, *sequence, parameters)
				if err != nil {
					return err
				}
				*encoded = block
				r.NTBLength = len(block)
				if err = ready(r.IPLength); err != nil {
					return err
				}
				startBytes, startTransfers := writer.Bytes, writer.Completed
				start := time.Now()
				deadline := start.Add(time.Duration(seconds) * time.Second)
				for time.Now().Before(deadline) {
					if err := ctx.Err(); err != nil {
						return err
					}
					for i, f := range frames {
						rawusb.FrameSequence(f, r.SubmittedPackets+uint64(i))
					}
					block, err = ncm.EncodeInto(*encoded, frames, *sequence, parameters)
					if err != nil {
						return err
					}
					*encoded = block
					*sequence++
					if err = writer.Submit(bridgeCtx, block); err != nil {
						transportErr = err
						return err
					}
					r.SubmittedPackets += uint64(count)
				}
				if err = writer.Flush(bridgeCtx); err != nil {
					transportErr = err
					return err
				}
				r.Seconds = time.Since(start).Seconds()
				r.CompletedUSBBytes = writer.Bytes - startBytes
				r.CompletedUSBTransfers = writer.Completed - startTransfers
				r.CompletedIPBytes = r.CompletedUSBTransfers * uint64(count*r.IPLength)
				r.CompletedUDPPayloadBytes = r.CompletedUSBTransfers * uint64(count*(r.IPLength-28))
				r.AfterPending = writer.Pending()
				return nil
			}()
			if e != nil {
				r.Error = e.Error()
			}
			result <- struct {
				r rawusb.Result
				e error
			}{r, e}
			// A disconnected controller is not a device fault. Native write faults
			// retain the existing bridge reconnect path and pinned buffer ownership.
			if ctx.Err() != nil {
				return nil
			}
			return transportErr
		}
		select {
		case work <- job:
		case <-ctx.Done():
			return r, ctx.Err()
		case <-bridgeCtx.Done():
			return r, bridgeCtx.Err()
		}
		select {
		case v := <-result:
			return v.r, v.e
		case <-bridgeCtx.Done():
			return r, bridgeCtx.Err()
		}
	}
}
