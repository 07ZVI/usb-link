package ipadncm

// Configuration 5 is published only AFTER the observed mode-3 request.
// Before that request accept the measured photo + Apple MUX layout in cfg 3.
func networkUSBPreflight(configs []Configuration, current byte) bool {
	for _, c := range configs {
		if c.Value != current {
			continue
		}
		if current == 5 {
			return groupingTrialConfig(c)
		}
		if current != 3 || c.NCMControls != 0 || len(c.Associations) != 0 || len(c.Interfaces) != 2 {
			return false
		}
		photo, mux := false, false
		for _, i := range c.Interfaces {
			if i.Alternate != 0 {
				return false
			}
			if i.Number == 0 && i.Class == 6 && i.Subclass == 1 && i.Protocol == 1 {
				photo = true
			}
			if i.Number == 1 && i.Class == 255 && i.Subclass == 254 && i.Protocol == 2 && len(i.Endpoints) == 2 {
				in, out := false, false
				for _, e := range i.Endpoints {
					if e.Type != 2 {
						return false
					}
					if e.Address&0x80 != 0 {
						in = true
					} else {
						out = true
					}
				}
				mux = in && out
			}
		}
		return photo && mux
	}
	return false
}
