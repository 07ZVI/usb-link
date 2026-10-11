// Temporary Mac-side native test responder; no installation or elevation.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"suhang/usbnet/internal/diagnostics/throughput"
	"time"
)

func main() {
	start := flag.Bool("start", false, "start a native throughput test")
	once := flag.Bool("once", false, "exit after one bounded test")
	output := flag.String("output", "", "save report JSON")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *once {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 80*time.Second)
		defer cancel()
	}
	started := false
	d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("10.6.9.2")}}
	transport := &http.Transport{Proxy: nil, DialContext: d.DialContext, MaxIdleConnsPerHost: 8}
	defer transport.CloseIdleConnections()
	client := throughput.NativeClient{HTTP: &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect refused") }}, Base: "http://10.6.9.1:10690"}
	fmt.Println("原生 USB 測速端已啟動，請在 Windows 流量面板按開始；Control-C 結束。")
	for ctx.Err() == nil {
		v, e := client.Poll(ctx)
		if e != nil && *once {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		if e == nil && *start && !started && v.ID == "" {
			if err := client.Start(ctx, v); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			started = true
		}
		if e == nil && v.ID != "" {
			r, e := client.Run(ctx, v)
			if e != nil {
				fmt.Println("測試未完成：", e)
			} else {
				fmt.Println(r.Summary())
				if *output != "" {
					data, err := json.MarshalIndent(r, "", "  ")
					if err == nil {
						err = os.WriteFile(*output, data, 0600)
					}
					if err != nil {
						fmt.Fprintln(os.Stderr, err)
						os.Exit(1)
					}
				}
			}
			if *once {
				if e != nil {
					os.Exit(1)
				}
				return
			}
		}
		select {
		case <-ctx.Done():
			if *once {
				fmt.Fprintln(os.Stderr, "test timed out")
				os.Exit(1)
			}
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}
