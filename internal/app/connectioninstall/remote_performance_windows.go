//go:build windows && amd64

package connectioninstall

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"suhang/usbnet/internal/diagnostics/bench"
	"time"
)

// Called only after the existing TLS/bearer authentication and USB peer gate.
// The bridge connection stays local to Windows, using its existing listener.
func (m *RemoteManager) performance(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Kind    string `json:"kind"`
		Seconds int    `json:"seconds"`
		Nonce   string `json:"nonce"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512))
	d.DisallowUnknownFields()
	var extra any
	if d.Decode(&q) != nil || d.Decode(&extra) != io.EOF || r.URL.RawQuery != "" {
		http.Error(w, "invalid capture request", 400)
		return
	}
	if q.Kind == "IPADWINTUNMODULEOFF" || q.Kind == "IPADWINTUNMODULEON" || q.Kind == "UPGRADEGUARDON" || q.Kind == "UPGRADEGUARDOFF" || q.Kind == "UPGRADEGUARDSTATE" || q.Kind == "CSTREAMING" || q.Kind == "CIPC" || q.Kind == "CDEFAULT" || q.Kind == "USBSTARTUPON" || q.Kind == "USBHOSTSTARTUPSTATE" || q.Kind == "IPADSIMPLIFIEDNATIVE" || q.Kind == "IPADTRUSTRECYCLESELFTEST" || q.Kind == "IPADUNPAIREDPREFLIGHT" || q.Kind == "IPADUNPAIREDPREP" || q.Kind == "IPADUNPAIREDSTATE" || q.Kind == "IPADUNPAIREDFINISH" || q.Kind == "IPADUNPAIREDREPLIED" || q.Kind == "IPADAMDSRUNNING" || q.Kind == "IPADAMDSSTOPPED" || q.Kind == "IPADDIAGNOSTICRESULT" || q.Kind == "IPADDIAGNOSTICCANCEL" || q.Kind == "IPADDIAGNOSTICHOLD" || q.Kind == "IPADSTARTUPSTATE" || q.Kind == "IPADNETWORKONLYON" || q.Kind == "IPADNETWORKONLYOFF" || q.Kind == "IPADNETWORKONLYSTATE" || q.Kind == "IPADNETWORKONLYPHASEON" || q.Kind == "IPADNETWORKONLYPHASEOFF" || q.Kind == "IPADSOFTRECONNECT" || q.Kind == "IPADSOFTRECONNECTON" || q.Kind == "IPADSOFTRECONNECTOFF" || q.Kind == "IPADSOFTRECONNECTCANCEL" || q.Kind == "IPADSOFTRECONNECTSTATE" || q.Kind == "IPADCANDIDATE3" || q.Kind == "IPADCANDIDATE41" || q.Kind == "IPADCANDIDATE42" || q.Kind == "IPADCANDIDATE43" || q.Kind == "IPADCANDIDATE5" || q.Kind == "IPADCANDIDATEDEFAULT" || q.Kind == "IPADCANDIDATESTATE" || q.Kind == "ROOTBASELINE" || q.Kind == "ROOTDEFAULT" || q.Kind == "PARENTFREEMEMORY" || q.Kind == "PARENTMEMORY" || q.Kind == "UDPRESULT" || q.Kind == "BRIDGEUDPSTART" || q.Kind == "ICMPSTART" || q.Kind == "GUARDBASELINE" || q.Kind == "GUARDDEFAULT" || q.Kind == "UIBASELINE" || q.Kind == "UIDEFAULT" || q.Kind == "PARENTCPU" || q.Kind == "PARENTHEAP" || q.Kind == "PARENTALLOCS" || q.Kind == "PARENTSTATE" || q.Kind == "RESOURCESTART" || q.Kind == "RESOURCEDETAIL" || q.Kind == "RESOURCESTATUS" || q.Kind == "RESOURCERESULT" || q.Kind == "RESOURCEDELETE" || q.Kind == "UDPSTART" || q.Kind == "UDPSTOP" || q.Kind == "UICLOSE" || q.Kind == "UIOPEN" {
		m.measurement(w, r, q.Kind, q.Seconds, q.Nonce)
		return
	}
	if e := bench.ValidatePerformance(q.Kind, q.Seconds, q.Nonce); e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	conn, e := (&net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}).DialContext(ctx, "tcp4", "127.0.0.1:47772")
	if e != nil {
		http.Error(w, "USB bridge diagnostics unavailable", 503)
		return
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(38 * time.Second))
	if _, e = fmt.Fprintf(conn, "%s %s %d %s\n", bench.PerfProtocol, q.Kind, q.Seconds, q.Nonce); e != nil {
		http.Error(w, "capture transport failed", 503)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	buf := make([]byte, 32<<10)
	for total := 0; total < (64<<20)+512; {
		n, e := conn.Read(buf[:min(len(buf), (64<<20)+512-total)])
		if n > 0 {
			if _, we := w.Write(buf[:n]); we != nil {
				return
			}
			total += n
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		if e != nil {
			return
		}
	}
}
