//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"context"
	"strings"
	"time"
)

// The protected intent scopes a read-only observation, never a USB grant.
// In particular this does not recreate issuedContext after a core restart.
func observeOwnedDirectBinding(parent context.Context, dir string) {
	j, found, err := readLocalNCMDirectJournal(dir)
	if err != nil || !found {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	s := inventoryPnP(ctx)
	d := directBindingEvidence{Source: "owned_journal_pnp_read_only", SampledUTC: time.Now().UTC().Format(time.RFC3339), Failure: "DIRECT_OBSERVATION_TARGET_UNAVAILABLE"}
	rootFound, children := false, 0
	var child Node
	if s.Error == "" {
		for _, n := range s.Nodes {
			belongs, why := configuredStartupNodeScope(n, j.Root)
			if why == "CONFIGURED_CM_NODE_ON_DIFFERENT_ROOT" {
				continue
			}
			if why != "" || !belongs {
				d.Failure = "DIRECT_OBSERVATION_SCOPE_UNREADABLE"
				break
			}
			if strings.EqualFold(n.instanceID, j.Root) {
				rootFound = true
			} else {
				children++
				child = n
			}
		}
		if rootFound && children == 1 && d.Failure != "DIRECT_OBSERVATION_SCOPE_UNREADABLE" {
			d = directBindingProof(child.IDPrefix, child.Service, child.DriverINF, child.LowerFilters, child.UpperFilters, nil)
			d.Source = "owned_journal_pnp_read_only"
			d.SampledUTC = time.Now().UTC().Format(time.RFC3339)
		} else if children > 1 && d.Failure != "DIRECT_OBSERVATION_SCOPE_UNREADABLE" {
			d.Failure = "DIRECT_OBSERVATION_SCOPE_AMBIGUOUS"
		}
	} else {
		d.Failure = "DIRECT_OBSERVATION_PNP_UNREADABLE"
	}
	if ctx.Err() != nil || verifyDirectJournal(dir, j) != nil {
		return
	}
	localNCMDirect.mu.Lock()
	if localNCMDirect.running || localNCMDirect.sessionCancel != nil {
		localNCMDirect.mu.Unlock()
		return
	}
	localNCMDirect.state.Binding = &d
	localNCMDirect.mu.Unlock()
}
