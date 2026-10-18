package ipadncm

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

type localPhotoNodeSummary struct {
	Hash     string `json:"hash"`
	Prefix   string `json:"prefix"`
	Class    string `json:"class"`
	Disabled bool   `json:"disabled"`
}
type localPhotoStatus struct {
	RejectedID    string                  `json:"rejected_id,omitempty"`
	RejectedError string                  `json:"rejected_error,omitempty"`
	CauseCode     string                  `json:"cause_code,omitempty"`
	NativeKind    string                  `json:"native_kind,omitempty"`
	NativeCode    uint32                  `json:"native_code,omitempty"`
	SampledUTC    string                  `json:"sampled_utc,omitempty"`
	RunID         string                  `json:"run_id,omitempty"`
	SampledMS     int64                   `json:"sampled_ms"`
	Available     bool                    `json:"available"`
	Requested     bool                    `json:"requested"`
	Effective     bool                    `json:"effective"`
	Busy          bool                    `json:"busy"`
	Persistence   string                  `json:"persistence"`
	SavedEnabled  bool                    `json:"saved_enabled"`
	RequestID     string                  `json:"request_id"`
	Phase         string                  `json:"phase"`
	Error         string                  `json:"error,omitempty"`
	OwnedNodes    int                     `json:"owned_nodes"`
	ObservedNodes int                     `json:"observed_nodes"`
	OmittedNodes  int                     `json:"omitted_nodes"`
	KnownNodes    int                     `json:"known_nodes"`
	KnownApplied  int                     `json:"known_applied"`
	KnownSkipped  int                     `json:"known_skipped"`
	KnownCode     string                  `json:"known_code,omitempty"`
	Nodes         []localPhotoNodeSummary `json:"nodes,omitempty"`
}
type localPhotoBackend interface {
	load() (localPhotoJournal, error)
	save(localPhotoJournal) error
	scan(string) ([]portableNodeReceipt, error)
	capture(portableNodeReceipt) (portablePropertyOriginal, error)
	disable(portablePropertyOriginal, func() bool) error
	disabled(portableNodeReceipt) (bool, error)
	restore(portablePropertyOriginal) error
	loadKnown() (localPhotoKnown, error)
	saveKnown(localPhotoKnown) error
	probe(portablePropertyOriginal) (localPhotoProbe, error)
	disableKnown(portablePropertyOriginal, func() bool) error
	disabledKnown(portablePropertyOriginal) (bool, error)
}
type localPhotoController struct {
	stamp               func() (string, string, int64)
	context             context.Context
	mu                  sync.Mutex
	operation           *sync.Mutex
	preference          sync.Mutex
	state               localPhotoStatus
	master              bool
	revision            uint64
	persistenceRevision uint64
	root                string
	initialized         bool
	journal             localPhotoJournal
	known               localPhotoKnown
	knownDirty          bool
	knownRetry          time.Time
	knownLoaded         bool
	backend             localPhotoBackend
	savePreference      func(bool) error
	readPreference      func() (bool, error)
	policyBlocked       func() bool
	runtimeAllowed      func() bool
	wake                chan struct{}
}

func newLocalPhotoController(b localPhotoBackend) *localPhotoController {
	return &localPhotoController{operation: new(sync.Mutex), backend: b, wake: make(chan struct{}, 1), state: localPhotoStatus{Available: true, Phase: "starting", Persistence: "unknown", SampledMS: -1}}
}
func (c *localPhotoController) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}
func (c *localPhotoController) snapshot() localPhotoStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.state
	s.Nodes = append([]localPhotoNodeSummary(nil), s.Nodes...)
	return s
}
func (c *localPhotoController) configure(save func(bool) error, read func() (bool, error)) {
	c.mu.Lock()
	c.savePreference = save
	c.readPreference = read
	c.mu.Unlock()
}
func (c *localPhotoController) masterChanged(on bool) {
	c.mu.Lock()
	c.master = on
	c.revision++
	rev := c.revision
	c.state.Requested = false
	c.state.Effective = false
	if !on {
		c.state.Phase = "recovering"
	} else {
		c.persistenceRevision = rev
		c.state.Persistence = "loading"
		c.state.Busy = true
	}
	read := c.readPreference
	c.mu.Unlock()
	c.signal()
	if !on {
		return
	}
	go c.persist(rev, true, false, read, nil)
}
func (c *localPhotoController) set(on bool, id string) error {
	if len(id) != 32 || strings.Trim(id, "0123456789abcdefABCDEF") != "" {
		return errors.New("PHOTO_REQUEST_INVALID")
	}
	localPhotoStrategyMutex.Lock()
	defer localPhotoStrategyMutex.Unlock()
	blocked := on && c.policyBlocked != nil && c.policyBlocked()
	c.mu.Lock()
	if blocked {
		c.state.RejectedID = id
		c.state.RejectedError = "PHOTO_POLICY_STRATEGY_CONFLICT"
		c.mu.Unlock()
		return errors.New("PHOTO_POLICY_STRATEGY_CONFLICT")
	}
	if on && !c.master {
		c.state.RejectedID = id
		c.state.RejectedError = "PHOTO_DEBUG_REQUIRED"
		c.mu.Unlock()
		return errors.New("PHOTO_DEBUG_REQUIRED")
	}
	c.revision++
	rev := c.revision
	c.persistenceRevision = rev
	c.state.RequestID = id
	c.state.RejectedID, c.state.RejectedError = "", ""
	c.state.Requested = on
	c.state.Effective = false
	c.state.Persistence = "saving"
	c.state.Busy = true
	c.state.Error = ""
	if !on {
		c.state.Phase = "recovering"
	}
	save := c.savePreference
	c.mu.Unlock()
	c.signal()
	go c.persist(rev, false, on, nil, save)
	return nil
}
func (c *localPhotoController) persist(rev uint64, restore, on bool, read func() (bool, error), save func(bool) error) {
	c.preference.Lock()
	defer c.preference.Unlock()
	c.mu.Lock()
	current := c.persistenceRevision == rev
	c.mu.Unlock()
	if !current {
		return
	}
	var err error
	if restore {
		if read == nil {
			err = errors.New("PHOTO_PREFERENCE_UNAVAILABLE")
		} else {
			on, err = read()
		}
	} else {
		if save == nil {
			err = errors.New("PHOTO_PREFERENCE_UNAVAILABLE")
		} else {
			err = save(on)
		}
	}
	localPhotoStrategyMutex.Lock()
	defer localPhotoStrategyMutex.Unlock()
	blocked := on && c.policyBlocked != nil && c.policyBlocked()
	c.mu.Lock()
	if err == nil {
		c.state.SavedEnabled = on
	}
	if c.persistenceRevision == rev {
		c.state.Busy = false
		if err != nil {
			c.state.Persistence = "failed"
			c.state.Error = "PHOTO_PREFERENCE_FAILED"
			c.state.Phase = "preference_failed"
		} else {
			c.state.Persistence = "saved"
			if c.revision == rev {
				c.state.Requested = on && c.master && !blocked
			}
			c.state.Error = ""
			if blocked {
				c.state.Error = "PHOTO_POLICY_STRATEGY_CONFLICT"
				c.state.Phase = "policy_conflict"
			}
		}
	}
	c.mu.Unlock()
	c.signal()
}

// A policy preference that resolves to off releases a classic startup restore
// which was deliberately held while the policy journal was still unknown.
func (c *localPhotoController) resumeAfterPolicy() {
	_ = WithLocalPhotoStrategySelection(func() error {
		if c.policyBlocked != nil && c.policyBlocked() {
			return nil
		}
		c.mu.Lock()
		if !c.master || !c.state.SavedEnabled || c.state.Error != "PHOTO_POLICY_STRATEGY_CONFLICT" || c.state.Busy {
			c.mu.Unlock()
			return nil
		}
		c.revision++
		rev := c.revision
		c.persistenceRevision = rev
		c.state.Persistence = "loading"
		c.state.Busy = true
		read := c.readPreference
		c.mu.Unlock()
		go c.persist(rev, true, false, read, nil)
		return nil
	})
}
func (c *localPhotoController) authorized(rev uint64, root string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return (c.runtimeAllowed == nil || c.runtimeAllowed()) && (c.context == nil || c.context.Err() == nil) && c.master && c.state.Requested && c.state.Persistence == "saved" && c.revision == rev && c.root == root
}
func (c *localPhotoController) publish(phase string, err error) {
	utc, run, ms := c.sample()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state.Phase = phase
	c.state.SampledUTC, c.state.RunID, c.state.SampledMS = utc, run, ms
	c.state.Effective = false
	c.state.OwnedNodes = len(c.journal.Entries)
	c.state.KnownNodes = len(c.known.Entries)
	c.state.Busy = false
	if c.state.Persistence == "saving" || c.state.Persistence == "loading" {
		c.state.Busy = true
	}
	if err != nil {
		c.state.CauseCode, c.state.NativeKind, c.state.NativeCode = photoFailureDetails(err)
		c.state.Error = err.Error()
	} else if c.state.Persistence != "failed" && c.state.Error != "PHOTO_POLICY_STRATEGY_CONFLICT" {
		c.state.Error = ""
		c.state.CauseCode, c.state.NativeKind, c.state.NativeCode = "", "", 0
	}
}

func (c *localPhotoController) sample() (string, string, int64) {
	if c.stamp != nil {
		return c.stamp()
	}
	return time.Now().UTC().Format(time.RFC3339Nano), "", -1
}
func (c *localPhotoController) recoverOwned() error {
	for len(c.journal.Entries) > 0 {
		p := c.journal.Entries[0]
		if err := c.backend.restore(p); err != nil {
			return photoFailure("PHOTO_RESTORE_FAILED", err)
		}
		next := localPhotoJournal{Schema: 1, Entries: append([]portablePropertyOriginal(nil), c.journal.Entries[1:]...)}
		if err := c.backend.save(next); err != nil {
			return photoFailure("PHOTO_JOURNAL_CHECKPOINT_FAILED", err)
		}
		c.journal = next
	}
	return nil
}

// Remembered identities survive restoration; a failure to remember is reported
// but never stops the isolation itself.
func (c *localPhotoController) rememberKnown(p portablePropertyOriginal) error {
	if !c.knownLoaded {
		return nil
	}
	next, changed := c.known.with(p)
	if !changed {
		return nil
	}
	if err := c.backend.saveKnown(next); err != nil {
		return photoFailure("PHOTO_KNOWN_SAVE_FAILED", err)
	}
	c.known = next
	return nil
}
func (c *localPhotoController) setKnownCode(code string) {
	c.mu.Lock()
	c.state.KnownCode = code
	c.mu.Unlock()
}
func (c *localPhotoController) journalEntry(id string) *portablePropertyOriginal {
	for i := range c.journal.Entries {
		if strings.EqualFold(c.journal.Entries[i].Node.ID, id) {
			p := c.journal.Entries[i]
			return &p
		}
	}
	return nil
}

// Apply isolation to every remembered instance of the (bound) iPad, present or
// not, before Windows can start a photo session on it. The caller holds the
// operation mutex. Per-instance failures are fixed codes and never abort the
// others; an instance that is not exactly proven is left untouched.
func (c *localPhotoController) reconcileKnown(rev uint64, root string) {
	c.mu.Lock()
	c.knownDirty = false
	c.mu.Unlock()
	if !c.knownLoaded {
		return
	}
	allowed := func() bool { return c.authorized(rev, root) }
	applied, skipped, code := 0, 0, ""
	fail := func(e error, fallback string) {
		if code == "" {
			if d, _, _ := photoFailureDetails(e); d != "" {
				code = d
			} else {
				code = fallback
			}
		}
	}
	for _, p := range c.journal.Entries {
		if e := c.rememberKnown(p); e != nil {
			fail(e, "PHOTO_KNOWN_SAVE_FAILED")
		}
	}
	for _, k := range append([]portablePropertyOriginal(nil), c.known.Entries...) {
		if root != "" && !strings.EqualFold(k.Node.Root, root) {
			continue
		}
		if !allowed() {
			return
		}
		pr, e := c.backend.probe(k)
		if e != nil {
			fail(e, "PHOTO_KNOWN_UNPROVEN")
			continue
		}
		plan := planLocalPhotoKnown(k, pr, c.journalEntry(k.Node.ID))
		switch plan.Kind {
		case knownSkip:
			skipped++
		case knownReject:
			fail(errors.New(plan.Code), plan.Code)
		case knownVerified:
			applied++
		case knownApply:
			if plan.Journal {
				if len(c.journal.Entries) >= 16 {
					fail(errors.New("PHOTO_JOURNAL_LIMIT"), "PHOTO_JOURNAL_LIMIT")
					continue
				}
				next := localPhotoJournal{Schema: 1, Entries: append(append([]portablePropertyOriginal(nil), c.journal.Entries...), plan.Original)}
				if e = c.backend.save(next); e != nil {
					fail(e, "PHOTO_JOURNAL_SAVE_FAILED")
					continue
				}
				c.journal = next
			}
			if e = c.backend.disableKnown(plan.Original, allowed); e != nil {
				fail(e, "PHOTO_DISABLE_FAILED")
				continue
			}
			if ok, e := c.backend.disabledKnown(plan.Original); e != nil || !ok {
				fail(e, "PHOTO_DISABLE_UNCONFIRMED")
				continue
			}
			applied++
			if e = c.rememberKnown(plan.Original); e != nil {
				fail(e, "PHOTO_KNOWN_SAVE_FAILED")
			}
		}
	}
	c.mu.Lock()
	c.state.KnownNodes, c.state.KnownApplied, c.state.KnownSkipped = len(c.known.Entries), applied, skipped
	c.state.KnownCode = code
	if code != "" {
		c.knownRetry = time.Now().Add(30 * time.Second)
	}
	c.mu.Unlock()
}

// Used right before a mode request: only the known-instance pass, no scan.
func (c *localPhotoController) applyKnown() {
	c.operation.Lock()
	defer c.operation.Unlock()
	if c.backend == nil || !c.initialized || c.awaitingSessionCleanup() {
		return
	}
	c.mu.Lock()
	rev, root := c.revision, c.root
	on := (c.context == nil || c.context.Err() == nil) && c.master && c.state.Requested && c.state.Persistence == "saved"
	c.mu.Unlock()
	if on {
		c.reconcileKnown(rev, root)
		c.publish(c.knownPhase(root), nil)
	}
}
func (c *localPhotoController) knownPhase(root string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if root == "" && c.state.KnownApplied > 0 && c.state.KnownCode == "" {
		return "known_applied"
	}
	if root == "" {
		return "waiting_authorized_target"
	}
	return c.state.Phase
}
func (c *localPhotoController) step() {
	c.operation.Lock()
	defer c.operation.Unlock()
	if c.backend == nil {
		c.publish("unavailable", errors.New("PHOTO_NOT_STARTED"))
		return
	}
	if c.awaitingSessionCleanup() {
		return
	}
	if !c.initialized {
		j, err := c.backend.load()
		if err != nil {
			c.publish("recovery_pending", photoFailure("PHOTO_JOURNAL_UNREADABLE", err))
			return
		}
		c.journal = j
		// Leftover entries are kept while isolation is on: they are reconciled,
		// not restored and re-applied. Off (or an unreadable remembered set)
		// restores everything owned.
		c.mu.Lock()
		keep := (c.context == nil || c.context.Err() == nil) && c.master && c.state.Requested && c.state.Persistence == "saved"
		c.mu.Unlock()
		if !keep {
			if err = c.recoverOwned(); err != nil {
				c.publish("recovery_pending", err)
				return
			}
		}
		if k, err := c.backend.loadKnown(); err != nil {
			c.setKnownCode("PHOTO_KNOWN_UNREADABLE")
		} else {
			c.known, c.knownLoaded = k, true
			c.mu.Lock()
			c.state.KnownNodes = len(k.Entries)
			c.knownDirty = true
			c.mu.Unlock()
		}
		c.initialized = true
	}
	c.mu.Lock()
	rev, root := c.revision, c.root
	on := (c.context == nil || c.context.Err() == nil) && c.master && c.state.Requested && c.state.Persistence == "saved"
	retry := c.knownLoaded && (c.knownDirty || c.state.KnownCode != "" && !time.Now().Before(c.knownRetry))
	c.mu.Unlock()
	if !on {
		if err := c.recoverOwned(); err != nil {
			c.publish("recovery_pending", err)
		} else {
			c.publish("off", nil)
		}
		return
	}
	if retry {
		c.reconcileKnown(rev, root)
	}
	if root == "" {
		c.publish(c.knownPhase(root), nil)
		return
	}
	nodes, err := c.backend.scan(root)
	if err != nil || len(nodes) > 16 {
		c.publish("recovery_pending", photoFailure("PHOTO_SCAN_UNPROVEN", err))
		return
	}
	summaries := make([]localPhotoNodeSummary, 0, 8)
	all := len(nodes) > 0
	for _, n := range nodes {
		if !c.authorized(rev, root) {
			break
		}
		if !localPhotoReceiptValid(n) || !strings.EqualFold(n.Root, root) {
			c.publish("recovery_pending", errors.New("PHOTO_TARGET_CHANGED"))
			return
		}
		owned := false
		for _, p := range c.journal.Entries {
			if strings.EqualFold(p.Node.ID, n.ID) {
				owned = true
				if !strings.EqualFold(p.Node.Class, n.Class) || !strings.EqualFold(p.Node.Root, root) {
					c.publish("recovery_pending", errors.New("PHOTO_TARGET_CHANGED"))
					return
				}
				n = p.Node
				break
			}
		}
		disabled, e := c.backend.disabled(n)
		if e != nil {
			c.publish("recovery_pending", photoFailure("PHOTO_STATE_UNPROVEN", e))
			return
		}
		if !disabled {
			if !owned {
				if len(c.journal.Entries) >= 16 {
					c.publish("recovery_pending", errors.New("PHOTO_JOURNAL_LIMIT"))
					return
				}
				p, e := c.backend.capture(n)
				if e != nil {
					c.publish("recovery_pending", photoFailure("PHOTO_ORIGINAL_UNPROVEN", e))
					return
				}
				next := localPhotoJournal{Schema: 1, Entries: append(append([]portablePropertyOriginal(nil), c.journal.Entries...), p)}
				if err := c.backend.save(next); err != nil {
					c.publish("recovery_pending", photoFailure("PHOTO_JOURNAL_SAVE_FAILED", err))
					return
				}
				c.journal = next
				if e := c.rememberKnown(p); e != nil {
					c.setKnownCode("PHOTO_KNOWN_SAVE_FAILED")
				}
			}
			var original portablePropertyOriginal
			for _, p := range c.journal.Entries {
				if strings.EqualFold(p.Node.ID, n.ID) {
					original = p
					break
				}
			}
			if e = c.backend.disable(original, func() bool { return c.authorized(rev, root) }); e != nil {
				c.publish("recovery_pending", photoFailure("PHOTO_DISABLE_FAILED", e))
				return
			}
			disabled, e = c.backend.disabled(original.Node)
			if e != nil || !disabled {
				c.publish("recovery_pending", photoFailure("PHOTO_DISABLE_UNCONFIRMED", e))
				return
			}
		}
		all = all && disabled
		if len(summaries) < 8 {
			summaries = append(summaries, localPhotoNodeSummary{Hash: portableNodeDigest(n)[:16], Prefix: portableNodePrefix(n.ID), Class: n.Class, Disabled: disabled})
		}
	}
	if !c.authorized(rev, root) {
		if c.awaitingSessionCleanup() {
			return
		}
		if err := c.recoverOwned(); err != nil {
			c.publish("recovery_pending", err)
		} else {
			c.publish("off", nil)
		}
		return
	}
	utc, run, ms := c.sample()
	c.mu.Lock()
	if c.revision != rev || !c.master || !c.state.Requested || c.root != root || (c.context != nil && c.context.Err() != nil) {
		c.mu.Unlock()
		if err := c.recoverOwned(); err != nil {
			c.publish("recovery_pending", err)
		} else {
			c.publish("off", nil)
		}
		return
	}
	c.state.CauseCode, c.state.NativeKind, c.state.NativeCode = "", "", 0
	c.state.SampledUTC, c.state.RunID, c.state.SampledMS = utc, run, ms
	c.state.Nodes = summaries
	c.state.ObservedNodes = len(nodes)
	c.state.OmittedNodes = len(nodes) - len(summaries)
	c.state.OwnedNodes = len(c.journal.Entries)
	c.state.Effective = all
	c.state.Busy = false
	c.state.Error = ""
	c.state.Phase = "waiting_photo_interface"
	if all {
		c.state.Phase = "isolated"
	}
	c.mu.Unlock()
}
func (c *localPhotoController) bind(root string) error {
	c.operation.Lock()
	if !c.initialized {
		c.operation.Unlock()
		c.step()
		c.operation.Lock()
	}
	if !c.initialized {
		c.operation.Unlock()
		return errors.New("PHOTO_RECOVERY_PENDING")
	}
	if c.root != root {
		// Owned entries stay owned (restored on off/exit); a new root only
		// changes which instances are scanned and reconciled.
		c.mu.Lock()
		c.root = root
		c.knownDirty = true
		c.mu.Unlock()
	}
	c.operation.Unlock()
	c.step()
	return nil
}
func (c *localPhotoController) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	c.step()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			c.mu.Lock()
			c.master = false
			c.state.Requested = false
			c.revision++
			c.mu.Unlock()
			c.step()
			return
		case <-c.wake:
			c.step()
		case <-t.C:
			c.step()
		}
	}
}
