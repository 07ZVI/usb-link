//go:build !windows || !amd64

package ipadncm

import "context"

func StartTrustDiagnostics(context.Context) {}
