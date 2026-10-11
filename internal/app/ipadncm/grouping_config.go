package ipadncm

import "bytes"

// Limit the trial to the exact unassociated union layout in the native report.
func groupingTrialConfig(c Configuration) bool {
	if c.Value != 5 || c.NCMControls != 2 || len(c.Associations) != 0 {
		return false
	}
	controls, data := 0, 0
	for _, i := range c.Interfaces {
		if i.Alternate == 0 && i.Class == 2 && i.Subclass == 13 {
			if (i.Number == 2 && bytes.Equal(i.Slaves, []byte{3})) || (i.Number == 4 && bytes.Equal(i.Slaves, []byte{5})) {
				controls++
			} else {
				return false
			}
		}
		if (i.Number == 3 || i.Number == 5) && i.Alternate == 1 && i.Class == 10 && i.Protocol == 1 && len(i.Endpoints) == 2 {
			in, out := false, false
			for _, e := range i.Endpoints {
				if e.Type == 2 {
					if e.Address&0x80 != 0 {
						in = true
					} else {
						out = true
					}
				}
			}
			if in && out {
				data++
			}
		}
	}
	return controls == 2 && data == 2
}
