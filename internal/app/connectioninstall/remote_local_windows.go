//go:build windows && amd64 && usblink_local_remote

package connectioninstall

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/app/remoteupdate"
	"suhang/usbnet/internal/app/usbhost"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
)

const localRemoteBuild = true

type localRemoteState struct {
	consent    localRemoteConsentGate
	startup    localRemoteStartupCleanup
	desired    atomic.Bool
	admitted   atomic.Bool
	failure    *localRemoteFailure
	watchOnce  sync.Once
	generation uint64
	guid       string
}

func (m *RemoteManager) initializeLocalRemote() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.localRemoteSetConsent(false); err != nil {
		return remoteInitializationFailure("consent_clear", err)
	}
	if err := localRemoteFirewall(false, ""); err != nil {
		m.localRemote.startup.record("local_firewall", err)
		m.lastError = RemoteInitializationCode(m.localRemote.startup.firstError)
		m.localRemote.failure = describeLocalRemoteFailure(err)
	}
	return nil
}

// Only network cleanup is deferred. Protected storage and consent failures
// still prevent manager construction, and no listener exists at this point.
func (m *RemoteManager) deferLocalRemoteStartupCleanup(err error) bool {
	m.localRemote.startup.record("legacy_firewall", err)
	m.lastError = RemoteInitializationCode(m.localRemote.startup.firstError)
	m.localRemote.failure = describeLocalRemoteFailure(err)
	return true
}

func (m *RemoteManager) closeLocalRemoteConsentLocked() {
	m.consentRevision++
	if err := m.localRemoteSetConsent(false); err != nil {
		m.lastError = "LOCAL_REMOTE_CONSENT_REVOCATION_FAILED"
	}
	if err := localRemoteFirewall(false, ""); err != nil {
		m.lastError = "LOCAL_REMOTE_FIREWALL_CLEANUP_FAILED"
	}
}

func newLocalRemoteConfig() (remoteConfig, error) {
	var c remoteConfig
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return c, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return c, err
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "USB Link Local Development"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("10.6.9.1")}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return c, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return c, err
	}
	var token [32]byte
	if _, err = rand.Read(token[:]); err != nil {
		return c, err
	}
	c.Enabled, c.Token = true, hex.EncodeToString(token[:])
	c.Cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	c.Key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	return c, nil
}

func (m *RemoteManager) localRemoteEnabled() bool {
	if !m.localRemote.desired.Load() || !m.localRemote.admitted.Load() || !m.mu.TryLock() {
		return false
	}
	defer m.mu.Unlock()
	return !m.closing.Load() && !m.recoveryOnly && m.config.Enabled
}

// Saved intent is separate; every enable creates fresh process-local credentials.
func (m *RemoteManager) enableLocalRemote(enabled bool) (resultError error) {
	m.localRemote.admitted.Store(false)
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("LOCAL_ADMINISTRATOR_REQUIRED")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	defer func() {
		if resultError == nil && enabled && m.config.Enabled && m.localRemote.desired.Load() && !m.closing.Load() {
			m.localRemote.admitted.Store(true)
		}
		m.lastError = ""
		m.localRemote.failure = describeLocalRemoteFailure(resultError)
		if resultError != nil {
			m.lastError = localRemoteErrorText(resultError)
			resultError = fmt.Errorf("%s", m.lastError)
		}
	}()
	if m.closing.Load() || m.recoveryOnly || m.requested.Load() {
		return fmt.Errorf("LOCAL_REMOTE_OWNER_UNAVAILABLE")
	}
	consentEpoch := m.localRemote.consent.epoch()
	m.consentRevision++
	m.closeLocalListenerLocked()
	if err := m.localRemoteSetConsent(false); err != nil {
		m.config = remoteConfig{}
		m.api = nil
		return err
	}
	m.config = remoteConfig{}
	m.api = nil
	if err := writeRemote(filepath.Join(m.root, "config.json"), remoteConfig{}); err != nil {
		return err
	}
	return m.localRemote.startup.prepare(enabled, m.localRemote.desired.Load,
		func() error { return localRemoteFirewall(false, "") },
		func() error { return remoteFirewall(false, "") }, func() error {
			if len(remoteupdate.PublisherKey()) != 32 {
				return fmt.Errorf("LOCAL_PUBLISHER_UNAVAILABLE")
			}
			c, err := newLocalRemoteConfig()
			if err != nil {
				return err
			}
			m.config = c
			if err := m.localRemoteSetConsent(true, consentEpoch); err != nil {
				m.config = remoteConfig{}
				return err
			}
			err = m.openLocalRemote()
			m.lastError = ""
			if err != nil {
				m.lastError = localRemoteErrorText(err)
				m.localRemote.failure = describeLocalRemoteFailure(err)
				m.closeLocalListenerLocked()
				m.config = remoteConfig{}
				if revoke := m.localRemoteSetConsent(false); revoke != nil {
					return fmt.Errorf("LOCAL_REMOTE_CONSENT_REVOCATION_FAILED")
				}
			}
			return err
		})
}

// Caller holds m.mu. The fixed API survives cable reconnection so its staged
// job remains cancelable, but every request must prove the new USB generation.
func (m *RemoteManager) openLocalRemote() error {
	if !m.localRemote.desired.Load() || m.closing.Load() || m.recoveryOnly || !m.config.Enabled {
		return fmt.Errorf("LOCAL_REMOTE_DISABLED")
	}
	if m.server != nil {
		return nil
	}
	if m.usbGUID == nil {
		return fmt.Errorf("LOCAL_REMOTE_USB_UNAVAILABLE")
	}
	guid := m.usbGUID()
	if guid == "" {
		return nil
	}
	guard, err := nativeMaintenanceGenerationGuard(guid)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(m.config.Cert, m.config.Key)
	if err != nil || len(m.config.Token) != 64 {
		return fmt.Errorf("LOCAL_REMOTE_CREDENTIALS_INVALID")
	}
	listener, err := net.Listen("tcp4", "10.6.9.1:47775")
	if err != nil {
		return err
	}
	if err = localRemoteFirewall(true, guid); err != nil {
		listener.Close()
		return err
	}
	if !m.localRemote.desired.Load() || m.usbGUID() != guid || !guard() {
		listener.Close()
		return fmt.Errorf("LOCAL_REMOTE_USB_GENERATION_CHANGED")
	}
	if m.api == nil {
		api := &remoteupdate.Server{Version: m.version, Token: m.config.Token, Key: remoteupdate.PublisherKey(), Status: m.localRemoteStatus, Diagnostics: func() any { return map[string]any{"native_smb": NativeSMBDiagnostics()} }, Resilient: func() bool { return true }}
		api.Stage = func(manifest remoteupdate.Manifest, body io.Reader) (string, error) {
			if !m.localRemoteActiveAPI(api) {
				return "", fmt.Errorf("LOCAL_REMOTE_USB_REVOKED")
			}
			id, err := m.localRemoteStage(manifest, body)
			if err == nil && !m.localRemoteActiveAPI(api) {
				if cleanup := m.localRemoteCancel(id); cleanup != nil {
					return id, remoteupdate.RetainJobError(cleanup)
				}
				return "", fmt.Errorf("LOCAL_REMOTE_USB_REVOKED")
			}
			return id, err
		}
		api.Apply = func(id string) error {
			if !m.localRemoteActiveAPI(api) {
				return remoteupdate.RetainJobError(fmt.Errorf("LOCAL_REMOTE_USB_REVOKED"))
			}
			if err := m.localRemoteApply(id); err != nil {
				// A failed handoff may leave a valid staged package. Preserve the
				// cancellation slot until the bridge confirms a terminal journal.
				return remoteupdate.RetainJobError(err)
			}
			// The package is awaiting local UAC, not yet an installation. Keep
			// only cancellation available; the bridge arbitrates it with dispatch.
			api.HoldOwned(id)
			return nil
		}
		api.Cancel = func(id string) error {
			if !m.localRemoteActiveAPI(api) {
				return fmt.Errorf("LOCAL_REMOTE_USB_REVOKED")
			}
			return m.localRemoteCancel(id)
		}
		if id := m.localRemotePendingCancelID(); id != "" {
			api.ResumeOwned(id, true)
		}
		m.api = api
	}
	api := m.api
	m.localRemote.generation++
	generation := m.localRemote.generation
	active := func() bool { return m.localRemoteGenerationActive(api, generation, guid, guard) }
	handler := localRemoteHandler(localRestartHandler(api, m.config.Token, active, localRestartAPI{status: m.localRestartStatus, request: m.requestLocalRestart}), active)
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 180 * time.Second, WriteTimeout: 180 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}}
	m.server, m.nativeGeneration, m.localRemote.guid = server, guard, guid
	go func() {
		err := server.Serve(tls.NewListener(listener, server.TLSConfig))
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.server == server {
			m.server, m.nativeGeneration = nil, nil
			m.localRemote.generation++
			if err != nil && err != http.ErrServerClosed {
				m.lastError = "LOCAL_REMOTE_LISTENER_STOPPED"
			}
		}
	}()
	return nil
}

func (m *RemoteManager) closeLocalListenerLocked() {
	m.localRemote.generation++
	if m.server != nil {
		_ = m.server.Close()
		m.server = nil
	}
	m.nativeGeneration = nil
	m.localRemote.guid = ""
}

func (m *RemoteManager) localRemoteGenerationActive(api *remoteupdate.Server, generation uint64, guid string, guard func() bool) bool {
	if !m.localRemote.desired.Load() || !m.localRemote.admitted.Load() {
		return false
	}
	m.mu.Lock()
	live := !m.closing.Load() && !m.recoveryOnly && m.config.Enabled && m.server != nil && m.api == api && m.localRemote.generation == generation
	m.mu.Unlock()
	if !live || guard == nil || m.usbGUID == nil || m.usbGUID() != guid || !guard() {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.localRemote.desired.Load() && m.localRemote.admitted.Load() && !m.closing.Load() && m.config.Enabled && m.server != nil && m.api == api && m.localRemote.generation == generation
}
func (m *RemoteManager) localRemoteActiveAPI(api *remoteupdate.Server) bool {
	if !m.localRemote.desired.Load() || !m.localRemote.admitted.Load() {
		return false
	}
	m.mu.Lock()
	generation, guid, guard := m.localRemote.generation, m.localRemote.guid, m.nativeGeneration
	m.mu.Unlock()
	return m.localRemoteGenerationActive(api, generation, guid, guard)
}
func (m *RemoteManager) localRemoteActive() bool {
	if !m.localRemote.desired.Load() || !m.localRemote.admitted.Load() {
		return false
	}
	m.mu.Lock()
	api := m.api
	m.mu.Unlock()
	return api != nil && m.localRemoteActiveAPI(api)
}

func (m *RemoteManager) startLocalRemoteWatcher() {
	m.localRemote.watchOnce.Do(func() {
		go func() {
			tick := time.NewTicker(2 * time.Second)
			defer tick.Stop()
			for {
				select {
				case <-m.done:
					return
				case <-tick.C:
				}
				terminalID := m.localRemoteReconcile()
				if terminalID != "" {
					m.mu.Lock()
					api := m.api
					m.mu.Unlock()
					if api != nil {
						api.ResetOwned(terminalID)
					}
				}
				m.mu.Lock()
				if m.localRemote.desired.Load() && !m.closing.Load() && m.config.Enabled && !m.requested.Load() {
					if m.server != nil && (m.usbGUID == nil || m.usbGUID() != m.localRemote.guid || m.nativeGeneration == nil || !m.nativeGeneration()) {
						m.closeLocalListenerLocked()
						if err := localRemoteFirewall(false, ""); err != nil {
							m.lastError = "LOCAL_REMOTE_FIREWALL_CLEANUP_FAILED"
							m.mu.Unlock()
							continue
						}
					}
					if m.server == nil {
						if err := m.openLocalRemote(); err != nil {
							m.lastError = localRemoteErrorText(err)
							m.localRemote.failure = describeLocalRemoteFailure(err)
							if m.localRemote.failure != nil {
								m.localRemote.failure.Stage = netconfig.LocalMaintenanceFailureStage(err)
							}
						} else {
							m.lastError = ""
						}
					}
				}
				m.mu.Unlock()
			}
		}()
	})
}

func (m *RemoteManager) localRemoteListenerStatus() any {
	j, err := readLocalInstall(m.root, "")
	if os.IsNotExist(err) {
		return map[string]string{"status": "idle"}
	}
	if err != nil {
		return map[string]string{"status": "manual_recovery_required", "error": "LOCAL_REMOTE_JOURNAL_UNREADABLE"}
	}
	detail := j.Detail
	if len(detail) > 80 || strings.Trim(detail, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != "" {
		detail = ""
		if j.Status == "failed" {
			detail = "LOCAL_INSTALL_FAILED_SEE_LOCAL_DIAGNOSTICS"
		} else if j.Status == "manual_recovery_required" {
			detail = "LOCAL_INSTALL_RECOVERY_REQUIRED"
		}
	}
	return map[string]string{"status": j.Status, "version": j.Manifest.Version, "error": detail}
}

func localRemoteFirewall(enabled bool, guid string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	if !enabled {
		return netconfig.CleanupLocalMaintenanceNative(ctx, Verify)
	}
	executable, err := os.Executable()
	if err != nil || Verify(executable) != nil {
		return fmt.Errorf("LOCAL_REMOTE_EXECUTABLE_UNVERIFIED")
	}
	mac, err := netconfig.ResolveMacProofNative(ctx, guid)
	host, ready := usbhost.Proof()
	if err != nil || !ready {
		return fmt.Errorf("LOCAL_REMOTE_NATIVE_USB_UNPROVEN")
	}
	fresh := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if Verify(executable) != nil {
			return fmt.Errorf("LOCAL_REMOTE_EXECUTABLE_CHANGED")
		}
		current, valid := usbhost.Proof()
		freshMac, err := netconfig.ResolveMacProofNative(ctx, guid)
		if !valid || current != host || err != nil || freshMac != mac {
			return fmt.Errorf("LOCAL_REMOTE_USB_GENERATION_CHANGED")
		}
		return nil
	}
	return netconfig.EnsureLocalMaintenanceNative(ctx, host, executable, fresh)
}

func (m *RemoteManager) localRemoteInfo() (string, string) {
	if !m.localRemote.desired.Load() {
		return "USB 本地开发推送已关闭。", ""
	}
	if !m.mu.TryLock() {
		return "USB 本地开发推送正在准备。", ""
	}
	defer m.mu.Unlock()
	if !m.config.Enabled || !m.localRemote.admitted.Load() || m.closing.Load() {
		return "本次 USB 本地开发推送未开启。", ""
	}
	if m.server == nil {
		return "本次 USB 本地开发推送已开启，等待已验证的 Mac USB 连接。", ""
	}
	block, _ := pem.Decode(m.config.Cert)
	if block == nil {
		return "本地推送凭证不可用。", ""
	}
	pin := sha256.Sum256(block.Bytes)
	invitation, _ := json.Marshal(map[string]any{"urls": []string{"https://10.6.9.1:47775"}, "certificate_sha256": hex.EncodeToString(pin[:]), "token": m.config.Token})
	return "本次 USB 本地开发推送已开启，仅接受签名的完整应用安装包。", string(invitation)
}

func (m *RemoteManager) localRemoteFailureStatus() any {
	return map[string]any{"failure": m.localRemote.failure, "initialization_code": RemoteInitializationCode(m.localRemote.startup.firstError), "initialization_failure": describeLocalRemoteFailure(m.localRemote.startup.firstError), "cleanup_pending": m.localRemote.startup.pending(), "legacy_disabled_rule_retained": netconfig.LocalMaintenanceLegacyRetained()}
}

func (m *RemoteManager) LocalRemoteInitializationCode() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return RemoteInitializationCode(m.localRemote.startup.firstError)
}
