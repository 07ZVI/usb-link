//go:build windows && amd64 && usblink_local_remote

package ipadncm

import "unsafe"

type wpdManifestEnumerationABI struct {
	Count, Reserved uint32
	Descriptors     [1]wpdEventDescriptor
}

var _ [16 - unsafe.Sizeof(wpdEventDescriptor{})]byte
var _ [unsafe.Sizeof(wpdEventDescriptor{}) - 16]byte
var _ [8 - unsafe.Offsetof(wpdManifestEnumerationABI{}.Descriptors)]byte
var _ [unsafe.Offsetof(wpdManifestEnumerationABI{}.Descriptors) - 8]byte

// Compile-time checks also run in cross-builds where Windows tests cannot run.
var _ [448 - unsafe.Sizeof(wpdLogfile{})]byte
var _ [unsafe.Sizeof(wpdLogfile{}) - 448]byte
var _ [112 - unsafe.Sizeof(wpdEventRecord{})]byte
var _ [unsafe.Sizeof(wpdEventRecord{}) - 112]byte
var _ [wpdCriticalHeaderSize - unsafe.Sizeof(wpdEventHeader{})]byte
var _ [unsafe.Sizeof(wpdEventHeader{}) - wpdCriticalHeaderSize]byte
var _ [120 - unsafe.Sizeof(wpdTraceProperties{})]byte
var _ [unsafe.Sizeof(wpdTraceProperties{}) - 120]byte
var _ [424 - unsafe.Offsetof(wpdLogfile{}.EventRecordCallback)]byte
var _ [unsafe.Offsetof(wpdLogfile{}.EventRecordCallback) - 424]byte
var _ [8 - unsafe.Offsetof(wpdEventHeader{}.ThreadID)]byte
var _ [unsafe.Offsetof(wpdEventHeader{}.ThreadID) - 8]byte
var _ [64 - unsafe.Offsetof(wpdEventHeader{}.Activity)]byte
var _ [unsafe.Offsetof(wpdEventHeader{}.Activity) - 64]byte
