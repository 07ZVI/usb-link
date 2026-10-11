//go:build darwin

package updater

import "syscall"

func processCPU() (float64, float64) {
	var r syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &r) != nil {
		return 0, 0
	}
	return float64(r.Utime.Sec) + float64(r.Utime.Usec)/1e6, float64(r.Stime.Sec) + float64(r.Stime.Usec)/1e6
}
