// Package logfile bounds the disk usage of unattended runtime logs.
package logfile

import (
	"fmt"
	"os"
	"sync"
)

type Writer struct {
	mu    sync.Mutex
	file  *os.File
	path  string
	limit int64
	size  int64
}

func Open(path string, limit int64) (*Writer, error) {
	if limit < 1024 {
		return nil, fmt.Errorf("invalid log size limit")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	i, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Writer{file: f, path: path, limit: limit, size: i.Size()}, nil
}
func (w *Writer) Write(b []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return 0, os.ErrClosed
	}
	defer func() {
		// A diagnostic reader may briefly hold the file open on Windows. Keep
		// the current log usable after a failed rotation; do not grow past limit.
		if err != nil && w.file == nil {
			if f, e := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); e == nil {
				w.file = f
				if info, e := f.Stat(); e == nil {
					w.size = info.Size()
				}
			}
		}
	}()
	if int64(len(b)) > w.limit {
		return 0, fmt.Errorf("single log entry exceeds limit")
	}
	if w.size+int64(len(b)) > w.limit {
		if err := w.file.Close(); err != nil {
			return 0, err
		}
		w.file = nil
		if err := os.Remove(w.path + ".1"); err != nil && !os.IsNotExist(err) {
			return 0, err
		}
		if err := os.Rename(w.path, w.path+".1"); err != nil {
			return 0, err
		}
		f, err := os.OpenFile(w.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return 0, err
		}
		w.file = f
		w.size = 0
	}
	n, err = w.file.Write(b)
	w.size += int64(n)
	return n, err
}
func (w *Writer) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return os.ErrClosed
	}
	return w.file.Sync()
}
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}
