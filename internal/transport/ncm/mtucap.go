package ncm

import "fmt"

// MTUCap is the developer experiment that bounds how far the Mac USB link may
// raise its frame size. MTUCapAuto is the unchanged default behaviour.
type MTUCap int

const (
	MTUCapAuto MTUCap = 0
	MTUCap9000 MTUCap = 9000
	MTUCap1500 MTUCap = 1500

	baseFrame = 1514
	// maxTrialFrame is the largest frame the jumbo trial ever asks a device for.
	maxTrialFrame = 16014
)

// ParseMTUCap accepts exactly "auto", "9000" and "1500"; empty means auto.
func ParseMTUCap(s string) (MTUCap, error) {
	switch s {
	case "", "auto":
		return MTUCapAuto, nil
	case "9000":
		return MTUCap9000, nil
	case "1500":
		return MTUCap1500, nil
	}
	return MTUCapAuto, fmt.Errorf("MAC_MTU_CAP_INVALID")
}

func (c MTUCap) String() string {
	switch c {
	case MTUCap9000:
		return "9000"
	case MTUCap1500:
		return "1500"
	}
	return "auto"
}

// FrameCeiling is the largest Ethernet frame the cap permits.
func (c MTUCap) FrameCeiling() int {
	switch c {
	case MTUCap9000:
		return 9014
	case MTUCap1500:
		return baseFrame
	}
	return maxTrialFrame
}

// MaxMTU is the largest IP MTU the cap permits.
func (c MTUCap) MaxMTU() int {
	if c == MTUCapAuto {
		return 16000
	}
	return int(c)
}

// AllowsJumbo reports whether the jumbo MTU trial may run at all.
func (c MTUCap) AllowsJumbo() bool { return c.FrameCeiling() > baseFrame }

// DeviceMaxSegment bounds the device-reported segment size by the cap, never
// below the standard frame.
func (c MTUCap) DeviceMaxSegment(deviceMax int) int {
	if deviceMax <= c.FrameCeiling() {
		return deviceMax
	}
	return c.FrameCeiling()
}

// TrialFrameLimit is the frame limit handed to the MTU trial: the smaller of
// the device's current maximum datagram, the verified batch capacity and the cap.
func (c MTUCap) TrialFrameLimit(deviceCurrent, batchFrameLimit int) int {
	return min(deviceCurrent, batchFrameLimit, c.FrameCeiling())
}
