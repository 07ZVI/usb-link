//go:build !darwin

package updater

func processCPU() (float64, float64) { return 0, 0 }
