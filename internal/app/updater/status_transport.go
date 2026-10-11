package updater

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// No mutation is retried across transports. A valid HTTP response, including
// rejection, is final; only a transport failure permits the read-only fallback.
func readUSBStatus(ctx context.Context, primary, normal *http.Client, url, token string) ([]byte, error) {
	clients := []*http.Client{primary}
	if normal != nil {
		clients = append(clients, normal)
	}
	var last error
	for _, client := range clients {
		attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
		q, err := http.NewRequestWithContext(attempt, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			return nil, err
		}
		q.Header.Set("Authorization", "Bearer "+token)
		response, err := client.Do(q)
		if err != nil {
			cancel()
			last = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		data, err := readControlResponse(response.Body)
		response.Body.Close()
		cancel()
		if err != nil {
			return nil, err
		}
		if response.StatusCode/100 != 2 {
			return nil, fmt.Errorf("server %d: %s", response.StatusCode, data)
		}
		return data, nil
	}
	return nil, last
}
