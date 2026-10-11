package ipadncm

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// Private proof inputs are gathered again by the native admission reader. An
// enabled UI/cache value cannot substitute for owned policy and native state.
type networkOnlyDriverProof struct {
	choiceOn, ownerScope, descriptorBound, officialHealthy bool
	storeProtected, receiptValid, receiptOwnsRoot          bool
	serviceReadable, rootNativeHealthy                     bool
	serviceState, serviceStart, policyStart                uint32
}

func networkOnlyDriverOwnerMatches(stage int, scope string, ready bool, proofRoot string, proved bool, root string) bool {
	return stage == 5 && ready && proved && root != "" && strings.EqualFold(scope, root) && strings.EqualFold(proofRoot, root)
}

func networkOnlyDriverReceiptOwnsRoot(nodes []portableNodeReceipt, root string) bool {
	for _, node := range nodes {
		if !validPortableReceipt(node) {
			return false
		}
	}
	for _, node := range nodes {
		if root != "" && strings.EqualFold(node.Root, root) {
			return true
		}
	}
	return false
}

func networkOnlyDriverNativeHealthy(status, problem, flags uint32, readable bool) bool {
	return readable && status&0x8 != 0 && status&(0x100|0x40000) == 0 && problem == 0 && flags&1 == 0
}

func (p networkOnlyDriverProof) admitsExpectedStop() bool {
	return p.choiceOn && p.ownerScope && p.descriptorBound && p.officialHealthy &&
		p.storeProtected && p.receiptValid && p.receiptOwnsRoot && p.serviceReadable &&
		p.rootNativeHealthy && p.serviceState == 1 && p.serviceStart == p.policyStart
}

func (p networkOnlyDriverProof) admitsInitialApply(receiptConfirmedMissing bool) bool {
	return receiptConfirmedMissing && !p.receiptValid && !p.receiptOwnsRoot && p.choiceOn && p.ownerScope && p.descriptorBound && p.officialHealthy &&
		p.storeProtected && p.serviceReadable && p.rootNativeHealthy &&
		(p.serviceState == 1 || p.serviceState == 4) && p.serviceStart <= 4
}

func networkOnlyDriverChoice(data []byte) bool {
	var choice struct {
		Version int  `json:"version"`
		Enabled bool `json:"enabled"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var tail any
	return d.Decode(&choice) == nil && choice.Version == 1 && choice.Enabled && d.Decode(&tail) == io.EOF
}
