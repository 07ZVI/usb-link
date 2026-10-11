//go:build windows && amd64

package connectioninstall

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"suhang/usbnet/internal/diagnostics/bench"
	"suhang/usbnet/internal/diagnostics/latencyprobe"
	"suhang/usbnet/internal/diagnostics/throughput"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/security/usbgateway"
	"sync"
	"syscall"
	"time"
)

type measurementJob struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Seconds int    `json:"seconds"`
	Error   string `json:"error,omitempty"`
	dir     string
	cancel  context.CancelFunc
	command *exec.Cmd
}
type measurementState struct {
	sync.Mutex
	observer       []byte
	jobs           map[string]*measurementJob
	udpCancel      context.CancelFunc
	udpID          string
	udpKind        string
	udpICMPCleanup func() error
	udpGeneration  uint64
	uiControl      func(bool) error
	parentCancel   context.CancelFunc
	uiBaseline     func(int)
	guardBaseline  func(int)
	rootBaseline   func(int)
}

func (m *RemoteManager) SetResourceObserver(b []byte) {
	m.measurements.Lock()
	m.measurements.observer = b
	m.measurements.jobs = map[string]*measurementJob{}
	m.measurements.Unlock()
}
func (m *RemoteManager) SetMeasurementUIControl(f func(bool) error) {
	m.measurements.Lock()
	m.measurements.uiControl = f
	m.measurements.Unlock()
}
func (m *RemoteManager) stopMeasurements() {
	m.measurements.Lock()
	defer m.measurements.Unlock()
	if m.measurements.parentCancel != nil {
		m.measurements.parentCancel()
	}
	for _, j := range m.measurements.jobs {
		if j.cancel != nil {
			j.cancel()
		}
	}
	if m.measurements.udpCancel != nil {
		m.measurements.udpCancel()
	}
}
func (m *RemoteManager) measurementBusy() bool {
	m.measurements.Lock()
	defer m.measurements.Unlock()
	if m.measurements.parentCancel != nil || m.guardEnabled() && m.measurements.udpID != "" {
		return true
	}
	for _, j := range m.measurements.jobs {
		if j.Status == "running" {
			return true
		}
	}
	return false
}
func (m *RemoteManager) resourceStart(kind string, seconds int, id string) (any, error) {
	ms := &m.measurements
	ms.Lock()
	defer ms.Unlock()
	if ms.parentCancel != nil {
		return nil, fmt.Errorf("parent capture already active")
	}
	if len(ms.observer) == 0 {
		return nil, fmt.Errorf("embedded observer unavailable")
	}
	if len(ms.jobs) >= 8 {
		return nil, fmt.Errorf("measurement session limit")
	}
	for _, j := range ms.jobs {
		if j.Status == "running" {
			return nil, fmt.Errorf("resource observer already running")
		}
	}
	if ms.jobs[id] != nil {
		return nil, fmt.Errorf("measurement id already used")
	}
	if Verify(m.installed) != nil {
		return nil, fmt.Errorf("installed parent ownership changed")
	}
	if noReparse(m.root) != nil {
		return nil, fmt.Errorf("maintenance root redirected")
	}
	dir, e := os.MkdirTemp(m.root, "measurement-")
	if e != nil {
		return nil, e
	}
	started := false
	defer func() {
		if !started {
			os.RemoveAll(dir)
		}
	}()
	observer := filepath.Join(dir, "USBLink.Resource.exe")
	if e = os.WriteFile(observer, ms.observer, 0600); e != nil {
		return nil, e
	}
	want := sha256.Sum256(ms.observer)
	got, e := fileHash(observer)
	if e != nil || got != hex.EncodeToString(want[:]) {
		return nil, fmt.Errorf("observer hash mismatch")
	}
	log, e := os.OpenFile(filepath.Join(dir, "observer.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds+15)*time.Second)
	cmd := exec.CommandContext(ctx, observer, "--duration", strconv.Itoa(seconds)+"s", "--scenario", "integrated-measurement-"+m.version, "--output", filepath.Join(dir, "resource"))
	if kind == "RESOURCEDETAIL" {
		cmd.Args = append(cmd.Args, "--thread-counters")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	cmd.Stdout = log
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		cancel()
		log.Close()
		return nil, e
	}
	job := &measurementJob{ID: id, Status: "running", Seconds: seconds, dir: dir, cancel: cancel, command: cmd}
	ms.jobs[id] = job
	started = true
	go func() {
		e := cmd.Wait()
		log.Close()
		cancel()
		ms.Lock()
		defer ms.Unlock()
		job.Status = "complete"
		if e != nil {
			job.Status = "failed"
			job.Error = "observer exited before successful completion"
		}
		job.cancel = nil
	}()
	return map[string]any{"id": id, "status": "running", "seconds": seconds, "observer_pid": cmd.Process.Pid, "observer_excluded_from_product_totals": true, "version": m.version}, nil
}
func (m *RemoteManager) resourceResult(kind, id string) ([]byte, error) {
	ms := &m.measurements
	ms.Lock()
	defer ms.Unlock()
	j := ms.jobs[id]
	if j == nil {
		return nil, fmt.Errorf("unknown current-session measurement")
	}
	if kind == "RESOURCESTATUS" {
		return json.Marshal(j)
	}
	if j.Status == "running" {
		return nil, fmt.Errorf("resource capture still running")
	}
	if kind == "RESOURCEDELETE" {
		if noReparse(j.dir) != nil {
			return nil, fmt.Errorf("measurement directory redirected")
		}
		entries, err := os.ReadDir(j.dir)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			switch entry.Name() {
			case "USBLink.Resource.exe", "resource.jsonl", "resource.summary.json", "observer.log":
			default:
				return nil, fmt.Errorf("unexpected measurement file")
			}
			if entry.IsDir() || noReparse(filepath.Join(j.dir, entry.Name())) != nil {
				return nil, fmt.Errorf("measurement file redirected")
			}
		}
		for _, entry := range entries {
			if err := os.Remove(filepath.Join(j.dir, entry.Name())); err != nil {
				return nil, err
			}
		}
		if err := os.Remove(j.dir); err != nil {
			return nil, err
		}
		delete(ms.jobs, id)
		return json.Marshal(map[string]string{"id": id, "status": "deleted"})
	}
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	defer z.Close()
	var rawBytes int64
	for _, name := range []string{"resource.jsonl", "resource.summary.json", "observer.log"} {
		p := filepath.Join(j.dir, name)
		if noReparse(p) != nil {
			return nil, fmt.Errorf("measurement file redirected or missing")
		}
		f, e := os.Open(p)
		if e != nil {
			return nil, e
		}
		info, e := f.Stat()
		if e != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 128<<20 || rawBytes+info.Size() > 192<<20 {
			f.Close()
			return nil, fmt.Errorf("measurement file bounds")
		}
		rawBytes += info.Size()
		w, e := z.Create(name)
		if e == nil {
			_, e = io.CopyN(w, f, info.Size())
		}
		f.Close()
		if e != nil {
			return nil, e
		}
		if b.Len() > 60<<20 {
			return nil, fmt.Errorf("measurement archive bounds")
		}
	}
	state, e := z.Create("job.json")
	if e != nil {
		return nil, e
	}
	if e = json.NewEncoder(state).Encode(j); e != nil {
		return nil, e
	}
	if e = z.Close(); e != nil {
		return nil, e
	}
	if b.Len() > 60<<20 {
		return nil, fmt.Errorf("measurement archive bounds")
	}
	return b.Bytes(), nil
}
func (m *RemoteManager) measurement(w http.ResponseWriter, r *http.Request, kind string, seconds int, id string) {
	if e := validMeasurement(kind, seconds, id); e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	if kind == "UPGRADEGUARDON" || kind == "UPGRADEGUARDOFF" || kind == "UPGRADEGUARDSTATE" {
		m.upgradeGuardMeasurement(w, r, kind, seconds, id)
		return
	}
	m.mu.Lock()
	allowed := m.config.Enabled && !m.requested.Load() && !m.rawUSB.Load() && m.usbGUID() != ""
	m.mu.Unlock()
	if !allowed {
		http.Error(w, "active authorized Mac USB maintenance required", 403)
		return
	}

	if strings.HasPrefix(kind, "PARENT") {
		m.measurements.Lock()
		busy := m.measurements.parentCancel != nil
		for _, j := range m.measurements.jobs {
			busy = busy || j.Status == "running"
		}
		if busy {
			m.measurements.Unlock()
			http.Error(w, "measurement already active", 409)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
		m.measurements.parentCancel = cancel
		m.measurements.Unlock()
		defer func() { cancel(); m.measurements.Lock(); m.measurements.parentCancel = nil; m.measurements.Unlock() }()
		if kind == "PARENTSTATE" {
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			data, e := json.Marshal(map[string]any{"version": m.version, "pid": os.Getpid(), "go_memory": mem, "diagnostics": m.diagnostics()})
			if e != nil {
				http.Error(w, "state serialization failed", 500)
				return
			}
			sum := sha256.Sum256(data)
			w.Header().Set("Content-Type", "application/octet-stream")
			fmt.Fprintf(w, "DONE %s %d %s\n", id, len(data), hex.EncodeToString(sum[:]))
			w.Write(data)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		// Fixed profile names only; no GC policy or arbitrary pprof endpoint.
		if e := bench.CaptureFixed(ctx, &flushedProfileWriter{w: w}, strings.TrimPrefix(kind, "PARENT"), seconds, id); e != nil {
			return
		}
		return
	}
	var data []byte
	var e error
	switch kind {
	case "CSTREAMING", "CIPC", "CDEFAULT":
		var result any
		result, e = setDesktopRuntimeExperiment(kind, seconds)
		if e == nil {
			data, e = json.Marshal(result)
		}
	case "IPADWINTUNMODULEOFF", "IPADWINTUNMODULEON", "USBSTARTUPON", "USBHOSTSTARTUPSTATE", "IPADSIMPLIFIEDNATIVE", "IPADTRUSTRECYCLESELFTEST", "IPADUNPAIREDPREFLIGHT", "IPADUNPAIREDPREP", "IPADUNPAIREDSTATE", "IPADUNPAIREDFINISH", "IPADUNPAIREDREPLIED", "IPADAMDSRUNNING", "IPADAMDSSTOPPED", "IPADDIAGNOSTICRESULT", "IPADDIAGNOSTICCANCEL", "IPADDIAGNOSTICHOLD", "IPADSTARTUPSTATE", "IPADNETWORKONLYON", "IPADNETWORKONLYOFF", "IPADNETWORKONLYSTATE", "IPADNETWORKONLYPHASEON", "IPADNETWORKONLYPHASEOFF", "IPADSOFTRECONNECT", "IPADSOFTRECONNECTON", "IPADSOFTRECONNECTOFF", "IPADSOFTRECONNECTCANCEL", "IPADSOFTRECONNECTSTATE", "IPADCANDIDATE3", "IPADCANDIDATE41", "IPADCANDIDATE42", "IPADCANDIDATE43", "IPADCANDIDATE5", "IPADCANDIDATEDEFAULT", "IPADCANDIDATESTATE":
		var result any
		result, e = m.runIPadDiagnostic(kind)
		if e == nil {
			data, e = json.Marshal(result)
		}
	case "RESOURCESTART", "RESOURCEDETAIL":
		var v any
		v, e = m.resourceStart(kind, seconds, id)
		if e == nil {
			data, e = json.Marshal(v)
		}
	case "RESOURCESTATUS", "RESOURCERESULT", "RESOURCEDELETE":
		data, e = m.resourceResult(kind, id)
	case "UIBASELINE", "UIDEFAULT", "GUARDBASELINE", "GUARDDEFAULT", "ROOTBASELINE", "ROOTDEFAULT":
		if m.measurementBusy() {
			e = fmt.Errorf("measurement already active")
			break
		}
		m.measurements.Lock()
		f := m.measurements.uiBaseline
		if strings.HasPrefix(kind, "GUARD") {
			f = m.measurements.guardBaseline
		}
		if strings.HasPrefix(kind, "ROOT") {
			f = m.measurements.rootBaseline
		}
		m.measurements.Unlock()
		if f == nil {
			e = fmt.Errorf("UI baseline unavailable")
			break
		}
		f(seconds)
		data, e = json.Marshal(map[string]any{"action": kind, "temporary_seconds": seconds})
	case "UICLOSE", "UIOPEN":
		m.measurements.Lock()
		f := m.measurements.uiControl
		m.measurements.Unlock()
		if f == nil {
			e = fmt.Errorf("owned desktop controller unavailable")
			break
		}
		e = f(kind == "UIOPEN")
		if e == nil {
			data, e = json.Marshal(map[string]string{"status": "complete", "action": kind})
		}
	case "UDPRESULT":
		data, e = m.bridgeLatency("RESULT", 0, id, "-")
	case "UDPSTOP":
		m.measurements.Lock()
		e = m.measurements.cleanupICMP()
		if m.measurements.udpCancel != nil {
			m.measurements.udpCancel()
		}
		if e == nil && m.measurements.udpID != "" && m.measurements.udpKind != "" {
			_, e = m.bridgeLatency("STOP", 0, m.measurements.udpID, "-")
		}
		if e == nil {
			e = remoteUDPFirewall(false, "", m.measurements.udpID)
		}
		if e == nil {
			m.measurements.udpID = ""
			data, e = json.Marshal(map[string]string{"status": "stopped"})
		}
		m.measurements.Unlock()
	case "UDPSTART", "BRIDGEUDPSTART", "ICMPSTART":
		var key [32]byte
		if _, e = rand.Read(key[:]); e != nil {
			break
		}
		nonce, _ := hex.DecodeString(id)
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
		context.AfterFunc(ctx, cancel)
		m.measurements.Lock()
		m.measurements.udpGeneration++
		generation := m.measurements.udpGeneration
		if m.measurements.udpCancel != nil {
			m.measurements.udpCancel()
		}
		if e == nil && m.measurements.udpID != "" && m.measurements.udpKind != "" {
			_, e = m.bridgeLatency("STOP", 0, m.measurements.udpID, "-")
		}
		if e == nil {
			e = m.measurements.cleanupICMP()
		}
		probeMode := "APPLICATION"
		if kind == "BRIDGEUDPSTART" {
			probeMode = "BRIDGE"
		}
		if kind == "ICMPSTART" {
			probeMode = "ICMP"
		}
		if e == nil {
			_, e = m.bridgeLatency(probeMode, seconds, id, hex.EncodeToString(key[:]))
		}
		if e == nil && kind == "ICMPSTART" {
			g := usbgateway.Current()
			if g == nil {
				e = fmt.Errorf("USB gateway unavailable")
			} else {
				var undo func() error
				undo, e = g.TemporaryDiagnosticICMP(seconds)
				if e == nil {
					e = remoteICMPFirewall(true, m.usbGUID(), id)
					if e != nil {
						undo()
					} else {
						m.measurements.udpICMPCleanup = func() error {
							ge := undo()
							fe := remoteICMPFirewall(false, "", id)
							if ge != nil {
								return ge
							}
							return fe
						}
					}
				}
			}
		}
		if e == nil && kind == "UDPSTART" {
			e = remoteUDPFirewall(true, m.usbGUID(), id)
		}
		if e == nil {
			m.measurements.udpCancel = cancel
			m.measurements.udpID = id
			m.measurements.udpKind = probeMode
		}
		m.measurements.Unlock()
		if e != nil {
			m.measurements.Lock()
			m.measurements.cleanupICMP()
			m.measurements.Unlock()
			m.bridgeLatency("STOP", 0, id, "-")
			remoteUDPFirewall(false, "", id)
			cancel()
			break
		}
		context.AfterFunc(ctx, func() {
			m.measurements.Lock()
			defer m.measurements.Unlock()
			if m.measurements.udpID == id && m.measurements.udpGeneration == generation {
				m.measurements.cleanupICMP()
				if m.measurements.udpKind != "" {
					m.bridgeLatency("STOP", 0, id, "-")
				}
				remoteUDPFirewall(false, "", id)
				m.measurements.udpID = ""
			}
		})
		if kind == "UDPSTART" {
			e = throughput.StartUDPEcho(ctx, key[:], nonce, func() bool { return m.usbGUID() != "" && !m.requested.Load() })
		}
		if e != nil {
			cancel()
			break
		}
		data, e = json.Marshal(map[string]string{"key": hex.EncodeToString(key[:]), "nonce": id})
	}
	if e != nil {
		http.Error(w, e.Error(), 409)
		return
	}
	sum := sha256.Sum256(data)
	w.Header().Set("Content-Type", "application/octet-stream")
	fmt.Fprintf(w, "DONE %s %d %s\n", id, len(data), hex.EncodeToString(sum[:]))
	w.Write(data)
}

// Flush READY immediately, while the timed capture is still running.
type flushedProfileWriter struct{ w http.ResponseWriter }

func (f *flushedProfileWriter) Read(p []byte) (int, error) { return 0, io.EOF }
func (f *flushedProfileWriter) Write(p []byte) (int, error) {
	n, e := f.w.Write(p)
	if x, ok := f.w.(http.Flusher); ok {
		x.Flush()
	}
	return n, e
}

func (m *RemoteManager) SetMeasurementUIBaseline(f func(int)) {
	m.measurements.Lock()
	m.measurements.uiBaseline = f
	m.measurements.Unlock()
}

func (m *RemoteManager) SetMeasurementGuardBaseline(f func(int)) {
	m.measurements.Lock()
	m.measurements.guardBaseline = f
	m.measurements.Unlock()
}

func (m *RemoteManager) bridgeLatency(kind string, seconds int, id, key string) ([]byte, error) {
	if e := latencyprobe.Validate(kind, seconds, id, key); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, e := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}).DialContext(ctx, "tcp4", "127.0.0.1:47772")
	if e != nil {
		return nil, fmt.Errorf("bridge latency control unavailable")
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = fmt.Fprintf(conn, "%s %s %d %s %s\n", latencyprobe.Protocol, kind, seconds, id, key); e != nil {
		return nil, e
	}
	data, e := io.ReadAll(io.LimitReader(conn, 4<<20+1))
	if e != nil || len(data) > 4<<20 {
		return nil, fmt.Errorf("bridge latency result bounds")
	}
	var v struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(data, &v) != nil || v.ID != id {
		return nil, fmt.Errorf("bridge latency response invalid")
	}
	return data, nil
}

func remoteICMPFirewall(enabled bool, guid, id string) error {
	script, e := measurementICMPFirewallScript(enabled, guid, id)
	if e != nil {
		return e
	}
	return netconfig.Run(script, log.New(io.Discard, "", 0))
}
func (ms *measurementState) cleanupICMP() error {
	if ms.udpICMPCleanup == nil {
		return nil
	}
	e := ms.udpICMPCleanup()
	if e == nil {
		ms.udpICMPCleanup = nil
	}
	return e
}

func (m *RemoteManager) SetMeasurementRootBaseline(f func(int)) {
	m.measurements.Lock()
	m.measurements.rootBaseline = f
	m.measurements.Unlock()
}
