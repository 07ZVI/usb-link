package usbgateway

import "fmt"

// BFE can return FWPM_FILTER_FLAG_INDEXED (0x40) for classification lookup.
// It changes storage, not enforcement. All other flags still fail validation.
const filterFlagIndexed uint32 = 0x40

func validateFilterFlags(flags uint32) error {
	if flags & ^filterFlagIndexed != 0 {
		return fmt.Errorf("GATEWAY_FILTER_READBACK_FAILED field=flags actual=0x%x allowed=0x40", flags)
	}
	return nil
}

// Conditions are a conjunction of unique fields. BFE's returned array order
// need not match our submission order; duplicates and missing fields fail.
func conditionOrder(want, got []string) ([]int, error) {
	if len(want) == 0 || len(got) != len(want) {
		return nil, fmt.Errorf("GATEWAY_CONDITION_READBACK_FAILED field=count")
	}
	index := make(map[string]int, len(got))
	for i, field := range got {
		if _, exists := index[field]; exists {
			return nil, fmt.Errorf("GATEWAY_CONDITION_READBACK_FAILED field=duplicate actual=%s", field)
		}
		index[field] = i
	}
	order := make([]int, len(want))
	for i, field := range want {
		position, exists := index[field]
		if !exists {
			return nil, fmt.Errorf("GATEWAY_CONDITION_READBACK_FAILED field=missing expected=%s", field)
		}
		order[i] = position
		delete(index, field)
	}
	return order, nil
}
