//go:build windows && amd64

package usbgateway

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type journal struct {
	Sublayer string   `json:"sublayer"`
	LUID     uint64   `json:"luid"`
	Keys     []string `json:"keys"`
}
type configuration struct {
	Version  int       `json:"version"`
	Grants   []Grant   `json:"grants"`
	Journals []journal `json:"journals"`
}
type attachment struct {
	sub    windows.GUID
	luid   uint64
	keys   []windows.GUID
	base   map[uint64]bool
	permit map[string][]windows.GUID
	core   map[string]bool
	peer   string
}
type Manager struct {
	mu                   sync.Mutex
	engine, subscription uintptr
	path                 string
	conf                 configuration
	links                map[uint64]*attachment
	pending              map[string]Request
	asked                map[string]bool
	session              map[string]Grant
	events               chan rawEvent
	Requests             chan Request
	problem              string
	blockedAttempts      uint64
	lastDrops            []map[string]any
	lastSMBDrops         []map[string]any
	networkOnlyActive    int
	networkOnlyGroups    map[string]*networkOnlyFilterGroup
}
type rawEvent struct {
	filter                            uint64
	path, remote, protocol, direction string
	local                             string
}

var current struct {
	sync.Mutex
	m *Manager
}

func Current() *Manager { current.Lock(); defer current.Unlock(); return current.m }
func New(dir string) (*Manager, error) {
	current.Lock()
	defer current.Unlock()
	if current.m != nil {
		return current.m, nil
	}
	engine, e := openEngine()
	if e != nil {
		return nil, e
	}
	m := &Manager{engine: engine, path: filepath.Join(dir, "usb-gateway.json"), conf: configuration{Version: 1, Grants: []Grant{}, Journals: []journal{}}, links: map[uint64]*attachment{}, pending: map[string]Request{}, asked: map[string]bool{}, session: map[string]Grant{}, events: make(chan rawEvent, 128), Requests: make(chan Request, 32)}
	fail := func(err error) (*Manager, error) { closeEngine(engine); return nil, err }
	if e = m.load(); e != nil {
		return fail(e)
	}
	if e = m.recover(); e != nil {
		return fail(e)
	}
	var option *value
	if e = call("FwpmEngineGetOption0", engine, 0, uintptr(unsafe.Pointer(&option))); e != nil {
		return fail(e)
	}
	enabled := option != nil && option.Type == 3 && *(*uint32)(unsafe.Pointer(&option.Data)) == 1
	call("FwpmFreeMemory0", uintptr(unsafe.Pointer(&option)))
	if !enabled {
		return fail(fmt.Errorf("GATEWAY_NET_EVENTS_DISABLED"))
	}
	// Do not mutate Windows' global event collection option.
	callbacks.Store(engine, m)
	s := subscription{}
	if e = call("FwpmNetEventSubscribe0", engine, uintptr(unsafe.Pointer(&s)), callback, engine, uintptr(unsafe.Pointer(&m.subscription))); e != nil {
		callbacks.Delete(engine)
		return fail(e)
	}
	current.m = m
	go m.run()
	return m, nil
}
func (m *Manager) load() error {
	if e := safe(m.path); e != nil {
		if e == windows.ERROR_FILE_NOT_FOUND {
			return nil
		}
		return e
	}
	b, e := os.ReadFile(m.path)
	if e != nil {
		return e
	}
	if len(b) > 1<<20 {
		return fmt.Errorf("GATEWAY_STORE_TOO_LARGE")
	}
	if e = json.Unmarshal(b, &m.conf); e != nil {
		return e
	}
	if m.conf.Version != 1 || len(m.conf.Grants) > 256 || len(m.conf.Journals) > 32 {
		return fmt.Errorf("GATEWAY_STORE_INVALID")
	}
	for _, g := range m.conf.Grants {
		if !validGrant(g) {
			return fmt.Errorf("GATEWAY_GRANT_INVALID")
		}
	}
	for _, j := range m.conf.Journals {
		if _, e = windows.GUIDFromString(j.Sublayer); e != nil || len(j.Keys) > 2048 {
			return fmt.Errorf("GATEWAY_JOURNAL_INVALID")
		}
		for _, k := range j.Keys {
			if _, e = windows.GUIDFromString(k); e != nil {
				return e
			}
		}
	}
	return nil
}
func safe(path string) error {
	a, e := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if e != nil {
		return e
	}
	if a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("GATEWAY_STORE_REDIRECTED")
	}
	return nil
}
func (m *Manager) save() error {
	if e := safe(filepath.Dir(m.path)); e != nil {
		return e
	}
	if e := safe(m.path); e != nil && e != windows.ERROR_FILE_NOT_FOUND {
		return e
	}
	b, e := json.MarshalIndent(m.conf, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(m.path), "gateway-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return windows.MoveFileEx(windows.StringToUTF16Ptr(name), windows.StringToUTF16Ptr(m.path), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func (m *Manager) recover() error {
	for _, j := range m.conf.Journals {
		sub := guid(j.Sublayer)
		if e := m.removeOwned(sub, j.Keys); e != nil {
			return e
		}
	}
	m.conf.Journals = []journal{}
	return m.save()
}
func (m *Manager) removeOwned(sub windows.GUID, keys []string) error {
	return transaction(m.engine, func() error {
		for _, key := range keys {
			if e := removeFilter(m.engine, guid(key), sub); e != nil {
				return e
			}
		}
		var actual *sublayer
		e := call("FwpmSubLayerGetByKey0", m.engine, uintptr(unsafe.Pointer(&sub)), uintptr(unsafe.Pointer(&actual)))
		if isNotFound(e) {
			return nil
		}
		if e != nil {
			return e
		}
		owned := actual != nil && actual.Key == sub && actual.Display.Description != nil && windows.UTF16PtrToString(actual.Display.Description) == "USB Link owns this USB-scoped policy"
		call("FwpmFreeMemory0", uintptr(unsafe.Pointer(&actual)))
		if !owned {
			return fmt.Errorf("GATEWAY_SUBLAYER_OWNERSHIP_CHANGED")
		}
		return call("FwpmSubLayerDeleteByKey0", m.engine, uintptr(unsafe.Pointer(&sub)))
	})
}
func (m *Manager) Attach(luid uint64, corePaths ...string) (func() error, error) {
	return m.attach(luid, "", corePaths...)
}
func (m *Manager) AttachUSB(luid uint64, peer string, corePaths ...string) (func() error, error) {
	if peer != "10.6.9.2" && peer != "10.6.9.3" {
		return nil, fmt.Errorf("GATEWAY_LOCAL_PEER_INVALID")
	}
	return m.attach(luid, peer, corePaths...)
}
func (m *Manager) attach(luid uint64, peer string, corePaths ...string) (func() error, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if luid == 0 || m.links[luid] != nil {
		return nil, fmt.Errorf("GATEWAY_INTERFACE_INVALID")
	}
	sub, e := randomGUID()
	if e != nil {
		return nil, e
	}
	a := &attachment{sub: sub, luid: luid, peer: peer, base: map[uint64]bool{}, permit: map[string][]windows.GUID{}, core: map[string]bool{}}
	apps := []Grant{}
	for _, path := range corePaths {
		g, e := inspect(path)
		if e != nil {
			return nil, e
		}
		g.Decision = "allow"
		apps = append(apps, g)
		a.core[strings.ToLower(g.Path)] = true
	}
	for _, g := range effectiveGrants(m.conf.Grants, m.session) {
		if g.Decision == "allow" {
			fresh, e := inspect(g.Path)
			if e == nil && fresh.SHA256 == g.SHA256 && !a.core[strings.ToLower(g.Path)] {
				apps = append(apps, g)
			}
		}
	}
	// The full ownership receipt reaches stable storage before any WFP mutation.
	baseSpecs, e := BasePolicy(luid)
	if e != nil {
		return nil, e
	}
	if sharedHostLUID.Load() != 0 {
		local, e := LocalDeliveryPolicy(luid, peer)
		if e != nil {
			return nil, e
		}
		baseSpecs = append(baseSpecs, local...)
	}
	if peer != "" || luid == sharedHostLUID.Load() {
		nativeSMB, e := NativeSMBPolicy(luid, peer)
		if e != nil {
			return nil, e
		}
		baseSpecs = append(baseSpecs, nativeSMB...)
	}
	permitTemplate, _ := PermitPolicy(luid, "template")
	permitCount := len(permitTemplate)
	keys := []string{}
	for i := 0; i < len(baseSpecs)+permitCount*len(apps); i++ {
		key, e := randomGUID()
		if e != nil {
			return nil, e
		}
		a.keys = append(a.keys, key)
		keys = append(keys, key.String())
	}
	m.conf.Journals = append(m.conf.Journals, journal{sub.String(), luid, keys})
	if e = m.save(); e != nil {
		m.conf.Journals = m.conf.Journals[:len(m.conf.Journals)-1]
		return nil, e
	}
	e = commitThenVerify(func() error {
		return transaction(m.engine, func() error {
			if e := addSublayer(m.engine, sub); e != nil {
				return e
			}
			for i, spec := range baseSpecs {
				id, e := addFilter(m.engine, a.keys[i], sub, spec)
				if e != nil {
					return e
				}
				a.base[id] = true
			}
			for j, g := range apps {
				own := a.keys[len(baseSpecs)+permitCount*j : len(baseSpecs)+permitCount*(j+1)]
				permitSpecs, _ := PermitPolicy(luid, g.Path)
				for i, spec := range permitSpecs {
					if _, e := addFilter(m.engine, own[i], sub, spec); e != nil {
						return e
					}
				}
				a.permit[strings.ToLower(g.Path)] = own
			}
			return nil
		})
	}, func() error {
		for i, spec := range baseSpecs {
			if e := verifyFilter(m.engine, a.keys[i], sub, spec); e != nil {
				return e
			}
		}
		for j, g := range apps {
			specs, _ := PermitPolicy(luid, g.Path)
			for i, spec := range specs {
				if e := verifyFilter(m.engine, a.keys[len(baseSpecs)+permitCount*j+i], sub, spec); e != nil {
					return e
				}
			}
		}
		return nil
	})
	if e != nil {
		m.problem = e.Error()
		if recoveryErr := m.removeOwned(sub, keys); recoveryErr == nil {
			m.conf.Journals = m.conf.Journals[:len(m.conf.Journals)-1]
			if saveErr := m.save(); saveErr != nil {
				m.problem = saveErr.Error()
			}
		}
		// Return the exact failed attachment's durable cleanup obligation too.
		// The host supervisor must resolve it before removing/rebuilding its host;
		// a global gateway recovery would also disturb active USB attachments.
		return func() error { return m.recoverFailedAttachment(sub, luid, keys) }, e
	}
	m.links[luid] = a
	m.problem = ""
	return func() error {
		if e := m.Detach(luid); e != nil {
			return e
		}
		// Detach may have removed the in-memory link before its durable save
		// failed. Keep retrying this exact attachment's absence and receipt save.
		return m.recoverFailedAttachment(sub, luid, keys)
	}, nil
}

func (m *Manager) recoverFailedAttachment(sub windows.GUID, luid uint64, keys []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, j := range m.conf.Journals {
		if j.Sublayer != sub.String() {
			continue
		}
		if j.LUID != luid || len(j.Keys) != len(keys) {
			return fmt.Errorf("GATEWAY_FAILED_ATTACHMENT_OWNERSHIP_CHANGED")
		}
		for i := range keys {
			if j.Keys[i] != keys[i] {
				return fmt.Errorf("GATEWAY_FAILED_ATTACHMENT_OWNERSHIP_CHANGED")
			}
		}
	}
	if e := m.removeOwned(sub, keys); e != nil {
		return e
	}
	next := []journal{}
	for _, j := range m.conf.Journals {
		if j.Sublayer != sub.String() {
			next = append(next, j)
		}
	}
	m.conf.Journals = next
	return m.save()
}
func sessionValues(s map[string]Grant) []Grant {
	out := []Grant{}
	for _, g := range s {
		out = append(out, g)
	}
	return out
}
func (m *Manager) Detach(luid uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.links[luid]
	if a == nil {
		return nil
	}
	keys := []string{}
	for _, key := range a.keys {
		keys = append(keys, key.String())
	}
	if e := m.removeOwned(a.sub, keys); e != nil {
		m.problem = e.Error()
		return e
	}
	delete(m.links, luid)
	next := []journal{}
	for _, j := range m.conf.Journals {
		if j.Sublayer != a.sub.String() {
			next = append(next, j)
		}
	}
	m.conf.Journals = next
	if len(m.links) == 0 {
		m.pending = map[string]Request{}
		m.asked = map[string]bool{}
		m.session = map[string]Grant{}
	}
	return m.save()
}
func (m *Manager) Decide(id, decision string, remember bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.pending[id]
	if !ok || (decision != "allow" && decision != "block") {
		return fmt.Errorf("GATEWAY_REQUEST_EXPIRED")
	}
	g, e := inspect(r.Path)
	if e != nil || g.SHA256 != r.SHA256 {
		delete(m.pending, id)
		delete(m.asked, strings.ToLower(r.Path))
		return fmt.Errorf("GATEWAY_APPLICATION_CHANGED")
	}
	g.Decision = decision
	return m.applyGrant(g, remember, id)
}
func (m *Manager) Forget(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.links {
		if a.core[strings.ToLower(path)] {
			return fmt.Errorf("GATEWAY_CORE_PROTECTED")
		}
	}
	// Revoke permits first. Forgetting never grants access.
	if e := m.setPermits(path, false); e != nil {
		return e
	}
	delete(m.session, strings.ToLower(path))
	next := []Grant{}
	for _, g := range m.conf.Grants {
		if !strings.EqualFold(g.Path, path) {
			next = append(next, g)
		}
	}
	m.conf.Grants = next
	delete(m.asked, strings.ToLower(path))
	return m.save()
}
func (m *Manager) applyGrant(g Grant, remember bool, id string) error {
	if g.Decision == "allow" && m.networkOnlyActive > 0 && appleSyncApplication(g.Path) {
		if e := m.ensureNetworkOnlyAppBlocks(g.Path); e != nil {
			return e
		}
	}
	old := append([]Grant{}, m.conf.Grants...)
	if remember {
		next := []Grant{}
		for _, x := range m.conf.Grants {
			if !strings.EqualFold(x.Path, g.Path) {
				next = append(next, x)
			}
		}
		if len(next) >= 256 {
			return fmt.Errorf("GATEWAY_GRANT_LIMIT")
		}
		m.conf.Grants = append(next, g)
		if e := m.save(); e != nil {
			m.conf.Grants = old
			return e
		}
	}
	if e := m.setPermits(g.Path, g.Decision == "allow"); e != nil {
		m.problem = e.Error()
		return e
	}
	m.session[strings.ToLower(g.Path)] = g
	delete(m.pending, id)
	return nil
}
func (m *Manager) setPermits(path string, allow bool) error {
	// Preassign keys and persist them for recovery, even if the RPC fails.
	newKeys := map[uint64][]windows.GUID{}
	if allow {
		for luid, a := range m.links {
			if len(a.permit[strings.ToLower(path)]) != 0 {
				continue
			}
			specs, _ := PermitPolicy(luid, path)
			for range specs {
				key, e := randomGUID()
				if e != nil {
					return e
				}
				newKeys[luid] = append(newKeys[luid], key)
				a.keys = append(a.keys, key)
				for j := range m.conf.Journals {
					if m.conf.Journals[j].Sublayer == a.sub.String() {
						m.conf.Journals[j].Keys = append(m.conf.Journals[j].Keys, key.String())
					}
				}
			}
		}
		if e := m.save(); e != nil {
			return e
		}
	}
	e := transaction(m.engine, func() error {
		for luid, a := range m.links {
			if allow {
				permitSpecs, _ := PermitPolicy(luid, path)
				for i, key := range newKeys[luid] {
					if _, e := addFilter(m.engine, key, a.sub, permitSpecs[i]); e != nil {
						return e
					}
				}
			} else {
				for _, key := range a.permit[strings.ToLower(path)] {
					if e := removeFilter(m.engine, key, a.sub); e != nil {
						return e
					}
				}
			}
		}
		return nil
	})
	if e != nil {
		return e
	}
	if allow {
		verificationErr := func() error {
			for luid, keys := range newKeys {
				specs, _ := PermitPolicy(luid, path)
				for i, key := range keys {
					if e := verifyFilter(m.engine, key, m.links[luid].sub, specs[i]); e != nil {
						return e
					}
				}
			}
			return nil
		}()
		if verificationErr != nil {
			rollbackErr := transaction(m.engine, func() error {
				for luid, keys := range newKeys {
					for _, key := range keys {
						if e := removeFilter(m.engine, key, m.links[luid].sub); e != nil {
							return e
						}
					}
				}
				return nil
			})
			if rollbackErr != nil {
				return fmt.Errorf("%w; permit rollback failed: %v", verificationErr, rollbackErr)
			}
			return verificationErr
		}
	}
	for luid, a := range m.links {
		if allow {
			if keys := newKeys[luid]; len(keys) > 0 {
				a.permit[strings.ToLower(path)] = keys
			}
		} else {
			delete(a.permit, strings.ToLower(path))
		}
	}
	return nil
}
func (m *Manager) Snapshot() ([]Grant, string, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	all := effectiveGrants(m.conf.Grants, m.session)
	return all, m.problem, len(m.links)
}
func (m *Manager) run() {
	audit := time.NewTicker(2 * time.Second)
	defer audit.Stop()
	for {
		select {
		case e := <-m.events:
			m.handle(e)
		case <-audit.C:
			m.auditApplications()
		}
	}
}
func (m *Manager) handle(e rawEvent) {
	m.mu.Lock()
	owned := false
	for _, a := range m.links {
		if a.base[e.filter] {
			owned = true
		}
	}
	m.mu.Unlock()
	peer, _, _ := net.SplitHostPort(e.remote)
	if !owned && peer != "10.6.9.2" && peer != "10.6.10.2" && peer != "10.6.9.3" {
		return
	}
	path := devicePath(e.path)
	m.mu.Lock()
	core := false
	for _, a := range m.links {
		core = core || a.core[strings.ToLower(path)]
	}
	// Correlate other providers' drops only with our core executable and USB
	// peer. This is read-only evidence, not proof of the dropping interface.
	if owned || (core && (peer == "10.6.9.2" || peer == "10.6.10.2" || peer == "10.6.9.3")) {
		runes := []rune(path)
		name := ""
		for _, previous := range m.lastDrops {
			if previous["filter_id"] == e.filter {
				name, _ = previous["filter_name"].(string)
				break
			}
		}
		if name == "" {
			name = filterIdentity(m.engine, e.filter)
		}
		m.lastDrops = append(m.lastDrops, map[string]any{"filter_id": e.filter, "filter_name": name, "owned_filter": owned, "core": core, "path": string(runes[:min(384, len(runes))]), "remote": e.remote, "local": e.local, "direction": e.direction, "protocol": e.protocol})
		_, localPort, _ := net.SplitHostPort(e.local)
		if e.protocol == "TCP" && (localPort == "445" || localPort == "10690") {
			m.lastSMBDrops = append(m.lastSMBDrops, m.lastDrops[len(m.lastDrops)-1])
			if len(m.lastSMBDrops) > 8 {
				m.lastSMBDrops = m.lastSMBDrops[len(m.lastSMBDrops)-8:]
			}
		}
		if len(m.lastDrops) > 4 {
			m.lastDrops = m.lastDrops[len(m.lastDrops)-4:]
		}
	}
	if !owned {
		m.mu.Unlock()
		return
	}
	m.blockedAttempts++
	m.mu.Unlock()
	e.path = path
	if e.path == "" {
		return
	}
	if core {
		// Core grants were installed and independently read back before USB
		// activation. A drop here is a service/policy fault, not user consent.
		m.mu.Lock()
		m.problem = "GATEWAY_CORE_TRAFFIC_BLOCKED"
		m.mu.Unlock()
		return
	}
	m.mu.Lock()
	asked := m.asked[strings.ToLower(e.path)]
	m.mu.Unlock()
	if asked {
		return
	}
	g, err := inspect(e.path)
	if err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	stillOwned := false
	for _, a := range m.links {
		if a.base[e.filter] {
			stillOwned = true
		}
	}
	if !stillOwned || len(m.pending) >= 32 || m.asked[strings.ToLower(g.Path)] {
		return
	}
	for _, known := range effectiveGrants(m.conf.Grants, m.session) {
		if strings.EqualFold(known.Path, g.Path) && known.SHA256 == g.SHA256 && known.Decision == "block" {
			m.asked[strings.ToLower(g.Path)] = true
			return
		}
	}
	var token [12]byte
	if _, err = rand.Read(token[:]); err != nil {
		return
	}
	r := Request{ID: hex.EncodeToString(token[:]), Path: g.Path, SHA256: g.SHA256, Protocol: e.protocol, Direction: e.direction, Remote: e.remote}
	// Queue saturation never changes the default-deny policy. Retry after drain.
	select {
	case m.Requests <- r:
		m.pending[r.ID] = r
		m.asked[strings.ToLower(g.Path)] = true
	default:
	}
}

// The fingerprint is checked before granting and after metadata changes.
// WFP enforces executable paths, not hashes on every packet.
var allowedFileMetadata = map[string]os.FileInfo{}

func (m *Manager) auditApplications() {
	m.mu.Lock()
	defer m.mu.Unlock()
	paths := map[string]bool{}
	for _, a := range m.links {
		for path := range a.permit {
			if !a.core[path] {
				paths[path] = true
			}
		}
	}
	for path := range paths {
		st, err := os.Stat(path)
		old := allowedFileMetadata[path]
		if err == nil && old != nil && old.Size() == st.Size() && old.ModTime() == st.ModTime() {
			continue
		}
		var expected string
		for _, g := range effectiveGrants(m.conf.Grants, m.session) {
			if strings.EqualFold(g.Path, path) {
				expected = g.SHA256
			}
		}
		fresh, e := inspect(path)
		if err != nil || e != nil || fresh.SHA256 != expected {
			if e = m.setPermits(path, false); e != nil {
				m.problem = e.Error()
			} else {
				delete(m.asked, path)
				delete(allowedFileMetadata, path)
			}
		} else {
			allowedFileMetadata[path] = st
		}
	}
}

var callbacks sync.Map
var callback = windows.NewCallback(func(context uintptr, event *netEvent) uintptr {
	if value, ok := callbacks.Load(context); ok && event != nil {
		m := value.(*Manager)
		native := event
		if native.Type == 3 && native.Drop != nil && native.Header.Flags&0x20 != 0 {
			h := native.Header
			if h.App.Size >= 2 && h.App.Size <= 8192 && h.App.Size%2 == 0 && h.App.Data != nil {
				u := unsafe.Slice((*uint16)(unsafe.Pointer(h.App.Data)), int(h.App.Size)/2)
				path := windows.UTF16ToString(u)
				direction := "outbound"
				if native.Drop.Direction == 0x3900 {
					direction = "inbound"
				}
				proto := fmt.Sprint(h.Protocol)
				if h.Protocol == 6 {
					proto = "TCP"
				}
				if h.Protocol == 17 {
					proto = "UDP"
				}
				addr := ""
				if h.Flags&4 != 0 {
					if h.IPVersion == 0 {
						v := *(*uint32)(unsafe.Pointer(&h.Remote[0]))
						addr = net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String()
					} else if h.IPVersion == 1 {
						addr = net.IP(h.Remote[:]).String()
					}
				}
				local := ""
				if h.Flags&2 != 0 {
					if h.IPVersion == 0 {
						v := *(*uint32)(unsafe.Pointer(&h.Local[0]))
						local = net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String()
					} else if h.IPVersion == 1 {
						local = net.IP(h.Local[:]).String()
					}
				}
				e := rawEvent{native.Drop.FilterID, path, net.JoinHostPort(addr, fmt.Sprint(h.RemotePort)), proto, direction, net.JoinHostPort(local, fmt.Sprint(h.LocalPort))}
				select {
				case m.events <- e:
				default:
				}
			}
		}
	}
	return 0
})

func devicePath(path string) string {
	if strings.HasPrefix(path, `\??\`) {
		return strings.TrimPrefix(path, `\??\`)
	}
	for drive := 'A'; drive <= 'Z'; drive++ {
		name := string(drive) + ":"
		var b [1024]uint16
		if _, e := windows.QueryDosDevice(windows.StringToUTF16Ptr(name), &b[0], uint32(len(b))); e == nil {
			prefix := windows.UTF16ToString(b[:])
			if len(path) > len(prefix) && strings.EqualFold(path[:len(prefix)], prefix) && path[len(prefix)] == '\\' {
				return name + path[len(prefix):]
			}
		}
	}
	return ""
}

// Uninstall/recovery does not require network-event collection to be enabled.
// It removes only journalled objects with independently checked ownership.
func RemoveAll(dir string) error {
	h, e := openEngine()
	if e != nil {
		return e
	}
	defer closeEngine(h)
	m := &Manager{engine: h, path: filepath.Join(dir, "usb-gateway.json"), conf: configuration{Version: 1, Grants: []Grant{}, Journals: []journal{}}}
	if e = m.load(); e != nil {
		return e
	}
	if e = m.recover(); e != nil {
		return e
	}
	return os.Remove(m.path)
}

// Bounded read-only diagnostics. This reports kernel API readback and actual
// owned drop events, separately from an end-to-end packet acceptance claim.
func Evidence() any {
	m := Current()
	if m == nil {
		return map[string]any{"active_interfaces": 0, "prepared": false}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	filters := 0
	applications := map[string]bool{}
	for _, a := range m.links {
		filters += len(a.base)
		for path, keys := range a.permit {
			filters += len(keys)
			applications[path] = applications[path] || a.core[path]
		}
	}
	// Reveal only bounded read-only identities from existing permit readbacks.
	// No inspection, extra kernel call or policy decision occurs during snapshot.
	keys := make([]string, 0, len(applications))
	for path := range applications {
		keys = append(keys, path)
	}
	sort.Strings(keys)
	visible := []map[string]any{}
	for _, path := range keys[:min(8, len(keys))] {
		runes := []rune(path)
		visible = append(visible, map[string]any{"path": string(runes[:min(512, len(runes))]), "path_truncated": len(runes) > 512, "core": applications[path]})
	}
	requests := []map[string]any{}
	requestIDs := make([]string, 0, len(m.pending))
	for id := range m.pending {
		requestIDs = append(requestIDs, id)
	}
	sort.Strings(requestIDs)
	for _, id := range requestIDs[:min(4, len(requestIDs))] {
		r := m.pending[id]
		p := []rune(r.Path)
		requests = append(requests, map[string]any{"path": string(p[:min(384, len(p))]), "protocol": r.Protocol, "direction": r.Direction, "remote": r.Remote})
	}
	return map[string]any{"active_interfaces": len(m.links), "wfp_filter_readbacks": filters, "unknown_application_drop_events": m.blockedAttempts, "problem": m.problem, "prepared": true, "pending_requests": len(m.pending), "pending_applications": requests, "recent_drops": append([]map[string]any(nil), m.lastDrops...), "recent_smb_drops": append([]map[string]any(nil), m.lastSMBDrops...), "permitted_applications": visible, "permitted_application_count": len(keys), "applications_truncated": len(keys) > 8}
}

func (m *Manager) PendingRequests() []Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Request{}
	for _, r := range m.pending {
		out = append(out, r)
	}
	return out
}
