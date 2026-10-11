package background

// Gate ties consent to one observed attachment. Denial/timeout/error is latched
// until unplug or an explicit local retry. Permission never survives reboot.
type Gate struct {
	Parent  string
	Decided bool
}

func (g *Gate) Observe(parent string) {
	if parent != g.Parent {
		g.Parent, g.Decided = parent, false
	}
}
func (g *Gate) CanAsk() bool { return g.Parent != "" && !g.Decided }
func (g *Gate) Decide(parent string, yes bool) bool {
	if parent == "" || parent != g.Parent || g.Decided {
		return false
	}
	g.Decided = true
	return yes
}
func (g *Gate) Retry() { g.Decided = false }

const ServiceName = "SuhangUSBNet"
const ProductID = "suhang-usbnet-3d547ef4-cc9f-4949-9ea7-8b0bd84e8c6a"
