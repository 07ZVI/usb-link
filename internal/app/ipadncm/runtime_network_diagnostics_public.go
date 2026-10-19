//go:build !usblink_local_remote

package ipadncm

import "context"

// The periodic network sampler is a developer-build investigation aid. Public
// builds never start it, so the diagnostics value stays absent.
func StartRuntimeNetworkDiagnostics(context.Context) {}
func RuntimeNetworkDiagnostics() any                 { return nil }
