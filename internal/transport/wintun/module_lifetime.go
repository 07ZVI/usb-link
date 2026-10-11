package wintun

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
)

// This experiment is OFF unless the verified process startup selects it.
// PIN is irreversible within a process; OFF/ON comparisons need fresh helpers.
var moduleLifetimeHold atomic.Bool

func SetModuleLifetimeHoldEnabled(enabled bool) { moduleLifetimeHold.Store(enabled) }
func ModuleLifetimeHoldEnabled() bool           { return moduleLifetimeHold.Load() }

const moduleLifetimeLimit = 4

const LifecycleProbeGUID = "{C87700CF-8923-4CB0-B77A-9D25690617BE}"
const LifecycleProbeName = "USB Link Lifecycle Probe"

type ModuleLifetimeObservation struct {
	Enabled       bool `json:"enabled"`
	PinnedModules int  `json:"pinned_modules"`
	Limit         int  `json:"limit"`
}

type modulePinSet struct {
	sync.Mutex
	sources map[uintptr]string
}

var lifetimeModules modulePinSet

func ModuleLifetimeSnapshot() ModuleLifetimeObservation {
	lifetimeModules.Lock()
	defer lifetimeModules.Unlock()
	return ModuleLifetimeObservation{ModuleLifetimeHoldEnabled(), len(lifetimeModules.sources), moduleLifetimeLimit}
}

// One pin per native module, never one reference per adapter/reconnect. A path
// alias of the same already held native module does not consume another slot.
// Callers hash the file and independently verify the actual module source first.
func (s *modulePinSet) hold(module uintptr, source string, pin func() error) error {
	if module == 0 || source == "" || strings.ContainsRune(source, 0) || pin == nil {
		return errors.New("WINTUN_MODULE_PIN_SOURCE_REQUIRED")
	}
	s.Lock()
	defer s.Unlock()
	if _, found := s.sources[module]; found {
		return nil
	}
	if len(s.sources) >= moduleLifetimeLimit {
		return errors.New("WINTUN_MODULE_PIN_LIMIT")
	}
	if err := pin(); err != nil {
		return err
	}
	if s.sources == nil {
		s.sources = make(map[uintptr]string)
	}
	s.sources[module] = source
	return nil
}
