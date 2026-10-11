//go:build windows && amd64

package internet

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"math/bits"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/security/usbgateway"
	"suhang/usbnet/internal/transport/routing"
	"suhang/usbnet/internal/transport/usbaddress"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type WindowsBackend struct {
	Directory string
	Host      func() (usbaddress.InterfaceProof, bool)
	Safe      func(string) error
	mu        sync.Mutex
	last      []Upstream
}

const preflightScript = `$ErrorActionPreference='Stop';if(-not(Get-Command New-NetNat -ErrorAction SilentlyContinue)){throw 'INTERNET_WINNAT_UNAVAILABLE'};if(@(Get-NetNat).Count -ne 0){throw 'INTERNET_EXISTING_NAT_CONFLICT'};$share=New-Object -ComObject HNetCfg.HNetShare;foreach($c in $share.EnumEveryConnection){if($share.INetSharingConfigurationForINetConnection($c).SharingEnabled){throw 'INTERNET_EXISTING_ICS_CONFLICT'}};$routes=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0'|Where-Object{$_.NextHop -ne '0.0.0.0'}|Sort-Object @{Expression={$_.RouteMetric+(Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $_.InterfaceIndex).InterfaceMetric}});$result=@();foreach($r in $routes){$i=Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $r.InterfaceIndex;$a=Get-NetAdapter | Where-Object {$_.ifIndex -eq $r.InterfaceIndex};if($a.Status -ne 'Up' -or $a.Name -like 'USB Link*'){continue};$dns=@((Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $a.ifIndex).ServerAddresses);if($dns.Count -eq 0){continue};$excluded=@(Get-NetRoute -AddressFamily IPv4|Where-Object{$_.NextHop -eq '0.0.0.0' -and $_.DestinationPrefix -ne '0.0.0.0/0'}|Select-Object -ExpandProperty DestinationPrefix -Unique);$result+=@{index=[uint32]$a.ifIndex;name=$a.Name;dns=$dns;excluded=$excluded;original_forwarding=($i.Forwarding -eq 'Enabled')}};ConvertTo-Json -Depth 4 -Compress -InputObject @($result)`
const createScript = `$ErrorActionPreference='Stop';$p=$env:USBLINK_NAT_PLAN|ConvertFrom-Json;if(@(Get-NetNat).Count -ne 0){throw 'INTERNET_EXISTING_NAT_CONFLICT'};$hostip=Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $p.host_index|Where-Object{$_.IPAddress -eq '10.6.9.1'};if(-not $hostip){throw 'INTERNET_HOST_ADDRESS_CHANGED'};New-NetNat -Name $p.nat -InternalIPInterfaceAddressPrefix '10.6.9.0/24' -ErrorAction Stop|Out-Null;$nat=Get-NetNat -Name $p.nat;if($nat.InternalIPInterfaceAddressPrefix -ne '10.6.9.0/24'){throw 'INTERNET_NAT_READBACK_FAILED'};Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $p.upstream.index -Forwarding Enabled -ErrorAction Stop;if((Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $p.upstream.index).Forwarding -ne 'Enabled'){throw 'INTERNET_FORWARD_READBACK_FAILED'}`
const closeScript = `$ErrorActionPreference='Stop';$p=$env:USBLINK_NAT_PLAN|ConvertFrom-Json;$nat=Get-NetNat -Name $p.nat -ErrorAction SilentlyContinue;if($nat){if($nat.InternalIPInterfaceAddressPrefix -ne '10.6.9.0/24'){throw 'INTERNET_NAT_OWNERSHIP_CHANGED'};Remove-NetNat -Name $p.nat -Confirm:$false -ErrorAction Stop};if(Get-NetNat -Name $p.nat -ErrorAction SilentlyContinue){throw 'INTERNET_NAT_REMOVAL_UNPROVEN'};if(-not $p.upstream.original_forwarding){$i=Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $p.upstream.index -ErrorAction SilentlyContinue;if($i){Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $p.upstream.index -Forwarding Disabled -ErrorAction Stop;if((Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $p.upstream.index).Forwarding -ne 'Disabled'){throw 'INTERNET_FORWARD_RESTORE_UNPROVEN'}}}`
const healthyScript = `$ErrorActionPreference='Stop';$p=$env:USBLINK_NAT_PLAN|ConvertFrom-Json;$n=Get-NetNat -Name $p.nat;if($n.InternalIPInterfaceAddressPrefix -ne '10.6.9.0/24'){throw 'INTERNET_NAT_CHANGED'};$a=Get-NetAdapter | Where-Object {$_.ifIndex -eq $p.upstream.index};if($a.Status -ne 'Up'){throw 'INTERNET_UPSTREAM_LOST'};if(-not(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $p.upstream.index -ErrorAction SilentlyContinue)){throw 'INTERNET_UPSTREAM_ROUTE_LOST'};$current=@(Get-NetRoute -AddressFamily IPv4|Where-Object{$_.NextHop -eq '0.0.0.0' -and $_.DestinationPrefix -ne '0.0.0.0/0'}|Select-Object -ExpandProperty DestinationPrefix -Unique);if(@(Compare-Object @($current|Sort-Object) @($p.upstream.excluded|Sort-Object)).Count){throw 'INTERNET_ONLINK_ROUTES_CHANGED'};$dns=@((Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceIndex $p.upstream.index).ServerAddresses);if(@(Compare-Object @($dns) @($p.upstream.dns)).Count){throw 'INTERNET_DNS_CHANGED'};$best=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0'|Where-Object{$_.NextHop -ne '0.0.0.0'}|Sort-Object @{Expression={$_.RouteMetric+(Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $_.InterfaceIndex).InterfaceMetric}}|Select-Object -First 1;if($best.InterfaceIndex -ne $p.upstream.index){throw 'INTERNET_SELECTED_UPSTREAM_NOT_DEFAULT'}`

func (b *WindowsBackend) run(ctx context.Context, script string, p *Plan) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	d, e := windows.GetSystemDirectory()
	if e != nil {
		return nil, e
	}
	c := exec.CommandContext(ctx, filepath.Join(d, `WindowsPowerShell\v1.0\powershell.exe`), "-NoProfile", "-NonInteractive", "-Command", script)
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	c.Env = os.Environ()
	if p != nil {
		data, _ := json.Marshal(p)
		for i := len(c.Env) - 1; i >= 0; i-- {
			if strings.HasPrefix(strings.ToUpper(c.Env[i]), "USBLINK_NAT_PLAN=") {
				c.Env = append(c.Env[:i], c.Env[i+1:]...)
			}
		}
		c.Env = append(c.Env, "USBLINK_NAT_PLAN="+string(data))
	}
	out, e := c.CombinedOutput()
	if e != nil {
		return nil, fmt.Errorf("INTERNET_NATIVE_CONFIGURATION_FAILED: %s", strings.TrimSpace(string(out)))
	}
	return out, nil
}
func (b *WindowsBackend) Preflight(ctx context.Context, index uint32) (Upstream, error) {
	out, e := b.run(ctx, preflightScript, nil)
	if e != nil {
		return Upstream{}, e
	}
	var choices []Upstream
	if json.Unmarshal(out, &choices) != nil {
		return Upstream{}, errors.New("INTERNET_UPSTREAM_READBACK_FAILED")
	}
	for i := range choices {
		var luid uint64
		if e = interfaceLUID(choices[i].Index, &luid); e != nil {
			return Upstream{}, e
		}
		choices[i].LUID = luid
	}
	b.mu.Lock()
	b.last = choices
	b.mu.Unlock()
	for i, u := range choices {
		if index == 0 || u.Index == index {
			if i != 0 {
				return Upstream{}, errors.New("INTERNET_SELECTED_UPSTREAM_NOT_DEFAULT")
			}
			return u, nil
		}
	}
	return Upstream{}, errors.New("INTERNET_UPSTREAM_NOT_AVAILABLE")
}
func (b *WindowsBackend) Choices() []Upstream {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Upstream{}, b.last...)
}
func (b *WindowsBackend) write(name string, value any) error {
	if b.Safe != nil {
		if e := b.Safe(b.Directory); e != nil {
			return e
		}
		if _, e := os.Lstat(filepath.Join(b.Directory, name)); e == nil {
			if e = b.Safe(filepath.Join(b.Directory, name)); e != nil {
				return e
			}
		}
	}
	data, e := json.Marshal(value)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(b.Directory, "internet-write-")
	if e != nil {
		return e
	}
	temp := f.Name()
	defer os.Remove(temp)
	if _, e = f.Write(data); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	from, _ := windows.UTF16PtrFromString(temp)
	to, _ := windows.UTF16PtrFromString(filepath.Join(b.Directory, name))
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func (b *WindowsBackend) Journal(p Plan) error {
	if b.Host == nil {
		return errors.New("INTERNET_HOST_IDENTITY_REQUIRED")
	}
	host, ok := b.Host()
	if !ok || host.Index != p.HostIndex || host.LUID != p.HostLUID {
		return errors.New("INTERNET_HOST_CHANGED")
	}
	gate := usbgateway.Current()
	if gate == nil {
		return errors.New("INTERNET_USB_GATEWAY_REQUIRED")
	}
	proofs, e := gate.OwnedInterfaces()
	if e != nil {
		return e
	}
	proofs = append(proofs, host)
	aliases := []string{}
	for _, proof := range proofs {
		if e = usbaddress.VerifyProofs([]usbaddress.InterfaceProof{proof}); e != nil {
			return e
		}
		script := fmt.Sprintf(`$ErrorActionPreference='Stop';$a=@(Get-NetAdapter -IncludeHidden|Where-Object{$_.ifIndex -eq %d -and [guid]$_.InterfaceGuid -eq [guid]'%s'});if($a.Count -ne 1){throw 'INTERNET_USB_INTERFACE_CHANGED'};$a[0].Name`, proof.Index, proof.GUID)
		out, e := b.run(context.Background(), script, nil)
		if e != nil {
			return e
		}
		aliases = append(aliases, strings.TrimSpace(string(out)))
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	p.CoreExecutable = exe
	p.DNSInterfaces = aliases
	return b.write("internet-journal.json", p)
}
func (b *WindowsBackend) nativePlan(p Plan) (Plan, error) {
	path := filepath.Join(b.Directory, "internet-journal.json")
	if b.Safe != nil {
		if e := b.Safe(path); e != nil {
			return p, e
		}
	}
	data, e := os.ReadFile(path)
	var saved Plan
	if e != nil || len(data) > 64<<10 || json.Unmarshal(data, &saved) != nil || saved.Epoch != p.Epoch || saved.NAT != p.NAT || saved.Root != p.Root || saved.HostLUID != p.HostLUID || saved.Upstream.LUID != p.Upstream.LUID || len(saved.DNSInterfaces) == 0 || len(saved.DNSInterfaces) > 4 || !filepath.IsAbs(saved.CoreExecutable) {
		return p, errors.New("INTERNET_OWNERSHIP_JOURNAL_CHANGED")
	}
	return saved, nil
}
func (b *WindowsBackend) Create(ctx context.Context, p Plan) error {
	saved, err := b.nativePlan(p)
	if err != nil {
		return err
	}
	p = saved
	if b.Host == nil {
		return errors.New("INTERNET_HOST_IDENTITY_REQUIRED")
	}
	host, ok := b.Host()
	if !ok || host.Index != p.HostIndex || host.LUID != p.HostLUID {
		return errors.New("INTERNET_HOST_IDENTITY_CHANGED")
	}
	gate := usbgateway.Current()
	if gate == nil {
		return errors.New("INTERNET_USB_GATEWAY_REQUIRED")
	}
	proofs, e := gate.OwnedInterfaces()
	if e != nil {
		return e
	}
	proofs = append(proofs, host)
	conflict, e := usbaddress.ConflictScript(host.Index, host.GUID, proofs)
	if e != nil {
		return e
	}
	if _, e = b.run(ctx, conflict, nil); e != nil {
		return e
	}

	_, e = b.run(ctx, createScript, &p)
	if e == nil {
		_, e = b.run(ctx, dnsFirewallScript+dnsFirewallCreate, &p)
	}
	return e
}
func (b *WindowsBackend) Close(ctx context.Context, p Plan) error {
	saved, err := b.nativePlan(p)
	if err != nil {
		return err
	}
	p = saved
	if _, e := b.run(ctx, dnsFirewallScript+dnsFirewallRemove, &p); e != nil {
		return e
	}
	var luid uint64
	if interfaceLUID(p.Upstream.Index, &luid) != nil || luid != p.Upstream.LUID {
		// Delete only our NAT; leave the recycled interface untouched and keep
		// the journal until original forwarding restoration can be proved.
		safe := p
		safe.Upstream.OriginalForwarding = true
		if _, e := b.run(ctx, closeScript, &safe); e != nil {
			return e
		}
		return errors.New("INTERNET_CLEANUP_INTERFACE_CHANGED")
	}
	_, e := b.run(ctx, closeScript, &p)
	return e
}
func (b *WindowsBackend) Clear(p Plan) error {
	if e := os.Remove(filepath.Join(b.Directory, "internet-journal.json")); e != nil && !os.IsNotExist(e) {
		return e
	}
	return nil
}
func (b *WindowsBackend) Healthy(ctx context.Context, p Plan) bool {
	saved, err := b.nativePlan(p)
	if err != nil {
		return false
	}
	p = saved

	var luid uint64
	if interfaceLUID(p.HostIndex, &luid) != nil || luid != p.HostLUID {
		return false
	}
	if interfaceLUID(p.Upstream.Index, &luid) != nil || luid != p.Upstream.LUID {
		return false
	}
	_, e := b.run(ctx, dnsFirewallScript+dnsFirewallVerify+";"+healthyScript, &p)
	return e == nil
}
func (b *WindowsBackend) Recover(ctx context.Context) error {
	if e := b.write("internet-session.json", routing.Lease{}); e != nil {
		return e
	}
	path := filepath.Join(b.Directory, "internet-journal.json")
	if _, e := os.Lstat(path); os.IsNotExist(e) {
		return nil
	}
	if b.Safe != nil {
		if e := b.Safe(path); e != nil {
			return e
		}
	}
	data, e := os.ReadFile(path)
	var p Plan
	if e != nil || len(data) > 64<<10 || json.Unmarshal(data, &p) != nil || len(p.Epoch) != 32 || p.NAT != "USBLink-"+p.Epoch || p.HostIndex == 0 || p.Upstream.Index == 0 {
		return errors.New("INTERNET_RECOVERY_JOURNAL_INVALID")
	}

	if e = b.Close(ctx, p); e != nil {
		return e
	}
	return b.Clear(p)
}
func (b *WindowsBackend) Open(ctx context.Context, p Plan) (func() error, error) {
	gate := usbgateway.Current()
	if gate == nil {
		return nil, errors.New("INTERNET_USB_GATEWAY_REQUIRED")
	}
	stop, e := gate.OpenInternet(p.Upstream.LUID, p.Upstream.Excluded)
	if e != nil {
		return stop, e
	}
	dns, err := startDNS(context.Background(), p)
	if err != nil {
		return stop, err
	}
	lease := routing.Lease{Schema: 1, Epoch: p.Epoch, Root: p.Root, Enabled: true, Excluded: p.Upstream.Excluded, Expires: time.Now().Add(5 * time.Second).Unix()}
	if e = b.write("internet-session.json", lease); e != nil {
		dns()
		return stop, e
	}
	return func() error {
		e := b.write("internet-session.json", routing.Lease{})
		dns()
		fe := stop()
		if e != nil {
			return e
		}
		return fe
	}, nil
}
func (b *WindowsBackend) Renew(p Plan) error {
	return b.write("internet-session.json", routing.Lease{Schema: 1, Epoch: p.Epoch, Root: p.Root, Enabled: true, Excluded: p.Upstream.Excluded, Expires: time.Now().Add(5 * time.Second).Unix()})
}
func (b *WindowsBackend) Observation() routing.Observation {
	var o routing.Observation
	path := filepath.Join(b.Directory, "internet-observation.json")
	if b.Safe != nil && b.Safe(path) != nil {
		return o
	}
	data, e := os.ReadFile(path)
	if e == nil && len(data) < 4096 {
		_ = json.Unmarshal(data, &o)
	}
	return o
}
func startDNS(ctx context.Context, p Plan) (func(), error) {
	listener, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.6.9.1"), Port: 53})
	if e != nil {
		return nil, fmt.Errorf("INTERNET_DNS_BIND_FAILED: %w", e)
	}
	tcpStop, e := startTCPDNS(p)
	if e != nil {
		listener.Close()
		return nil, fmt.Errorf("INTERNET_DNS_TCP_BIND_FAILED: %w", e)
	}
	lifetime, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		slots := make(chan struct{}, 16)
		buf := make([]byte, 4096)
		for {
			n, peer, e := listener.ReadFromUDP(buf)
			if e != nil {
				return
			}
			if !peer.IP.Equal(net.ParseIP("10.6.9.2")) || n < 12 || buf[2]&0x80 != 0 {
				continue
			}
			select {
			case slots <- struct{}{}:
			default:
				continue
			}
			q := append([]byte{}, buf[:n]...)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-slots }()
				query, stop := context.WithTimeout(lifetime, 3*time.Second)
				defer stop()
				dialer := upstreamDialer(p.Upstream.Index)
				for _, server := range p.Upstream.DNS {
					conn, e := dialer.DialContext(query, "udp4", net.JoinHostPort(server, "53"))
					if e != nil {
						continue
					}
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					if _, e = conn.Write(q); e == nil {
						answer := make([]byte, 4096)
						n, e = conn.Read(answer)
						if e == nil && n >= 12 && answer[0] == q[0] && answer[1] == q[1] && answer[2]&0x80 != 0 {
							_, _ = listener.WriteToUDP(answer[:n], peer)
							conn.Close()
							return
						}
					}
					conn.Close()
				}
			}()
		}
	}()
	return func() { cancel(); listener.Close(); tcpStop(); <-done; wg.Wait() }, nil
}

var indexToLUID = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("ConvertInterfaceIndexToLuid")

func interfaceLUID(index uint32, luid *uint64) error {
	r, _, _ := indexToLUID.Call(uintptr(index), uintptr(unsafe.Pointer(luid)))
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

// TCP DNS is required for truncated replies and large signed DNS responses.
func startTCPDNS(p Plan) (func(), error) {
	listener, e := net.Listen("tcp4", "10.6.9.1:53")
	if e != nil {
		return nil, e
	}
	lifetime, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var wg sync.WaitGroup
	go func() {
		defer close(done)
		slots := make(chan struct{}, 16)
		for {
			client, e := listener.Accept()
			if e != nil {
				return
			}
			peer, ok := client.RemoteAddr().(*net.TCPAddr)
			if !ok || !peer.IP.Equal(net.ParseIP("10.6.9.2")) {
				client.Close()
				continue
			}
			select {
			case slots <- struct{}{}:
			default:
				client.Close()
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-slots }()
				defer client.Close()
				client.SetDeadline(time.Now().Add(5 * time.Second))
				header := make([]byte, 2)
				if _, e := io.ReadFull(client, header); e != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(header))
				if n < 12 || n > 4096 {
					return
				}
				q := make([]byte, n)
				if _, e := io.ReadFull(client, q); e != nil || q[2]&0x80 != 0 {
					return
				}
				ctx, stop := context.WithTimeout(lifetime, 3*time.Second)
				defer stop()
				dialer := upstreamDialer(p.Upstream.Index)
				for _, server := range p.Upstream.DNS {
					conn, e := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(server, "53"))
					if e != nil {
						continue
					}
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					_, e = conn.Write(append(header, q...))
					if e == nil {
						_, e = io.ReadFull(conn, header)
					}
					if e != nil {
						conn.Close()
						continue
					}
					size := int(binary.BigEndian.Uint16(header))
					if size < 12 {
						conn.Close()
						continue
					}
					answer := make([]byte, size)
					_, e = io.ReadFull(conn, answer)
					conn.Close()
					if e == nil && answer[0] == q[0] && answer[1] == q[1] && answer[2]&0x80 != 0 {
						_, _ = client.Write(append(header, answer...))
						return
					}
				}
			}()
		}
	}()
	return func() { cancel(); listener.Close(); <-done; wg.Wait() }, nil
}
func upstreamDialer(index uint32) net.Dialer {
	return net.Dialer{Control: func(network, address string, c syscall.RawConn) error {
		var err error
		e := c.Control(func(fd uintptr) {
			err = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(bits.ReverseBytes32(index)))
		})
		if e != nil {
			return e
		}
		return err
	}}
}

// Defender Firewall exceptions complement the independently scoped USB WFP
// filters. Their exact immutable plan is journaled before native rule creation.
const dnsFirewallScript = `$ErrorActionPreference='Stop';$p=$env:USBLINK_NAT_PLAN|ConvertFrom-Json;
function VerifyDNS($r,$proto){if($r.Group -ne 'USBLink-Internet-DNS-v1' -or $r.Description -ne $p.epoch -or $r.Enabled -ne 'True' -or $r.Direction -ne 'Inbound' -or $r.Action -ne 'Allow' -or $r.EdgeTraversalPolicy -ne 'Block'){throw 'INTERNET_DNS_FIREWALL_OWNERSHIP_CHANGED'};$app=$r|Get-NetFirewallApplicationFilter;$addr=$r|Get-NetFirewallAddressFilter;$port=$r|Get-NetFirewallPortFilter;$iface=$r|Get-NetFirewallInterfaceFilter;if($app.Program -ne $p.core_executable -or (@($addr.LocalAddress)-join ',') -ne '10.6.9.1' -or (@($addr.RemoteAddress)-join ',') -ne '10.6.9.2' -or (@($port.LocalPort)-join ',') -ne '53' -or $port.Protocol -notin @($proto,$(if($proto -eq 'TCP'){'6'}else{'17'})) -or @(Compare-Object @($iface.InterfaceAlias|Sort-Object) @($p.dns_interfaces|Sort-Object)).Count){throw 'INTERNET_DNS_FIREWALL_READBACK_FAILED'}};
`
const dnsFirewallCreate = `foreach($proto in @('UDP','TCP')){$name=$p.nat+'-DNS-'+$proto;if(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue){throw 'INTERNET_DNS_FIREWALL_NAME_CONFLICT'};New-NetFirewallRule -Name $name -DisplayName 'USB Link Mac DNS' -Group 'USBLink-Internet-DNS-v1' -Description $p.epoch -Direction Inbound -Action Allow -Enabled True -Profile Any -EdgeTraversalPolicy Block -Program $p.core_executable -InterfaceAlias @($p.dns_interfaces) -LocalAddress '10.6.9.1' -RemoteAddress '10.6.9.2' -Protocol $proto -LocalPort 53 -ErrorAction Stop|Out-Null;$r=@(Get-NetFirewallRule -Name $name);if($r.Count -ne 1){throw 'INTERNET_DNS_FIREWALL_COUNT_INVALID'};VerifyDNS $r[0] $proto}`
const dnsFirewallVerify = `foreach($proto in @('UDP','TCP')){$r=@(Get-NetFirewallRule -Name ($p.nat+'-DNS-'+$proto));if($r.Count -ne 1){throw 'INTERNET_DNS_FIREWALL_COUNT_INVALID'};VerifyDNS $r[0] $proto}`
const dnsFirewallRemove = `foreach($proto in @('UDP','TCP')){$name=$p.nat+'-DNS-'+$proto;$r=@(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue);if($r.Count -gt 1){throw 'INTERNET_DNS_FIREWALL_COUNT_INVALID'};if($r.Count -eq 1){VerifyDNS $r[0] $proto;$r[0]|Remove-NetFirewallRule -ErrorAction Stop};if(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue){throw 'INTERNET_DNS_FIREWALL_REMOVAL_UNPROVEN'}}`
