using System.Diagnostics;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace Suhang.Desktop;

internal static class ProcessRate
{
    internal static string Format(double? bytes) => bytes is not double n || !double.IsFinite(n) || n < 0 ? "—" :
        n >= 1048576 ? (n / 1048576).ToString("0.0",System.Globalization.CultureInfo.InvariantCulture) + " MB/s" :
        (n / 1024).ToString("0.0",System.Globalization.CultureInfo.InvariantCulture) + " KB/s";
}

// Interval counters are keyed by PID plus creation time. Late events and PID
// reuse cannot contaminate a newly observed process. Unknown is distinct from zero.
internal sealed class ProcessIoLedger
{
    sealed class Counter(long started,long observed) {
        internal long Started=started, Since=observed, FirstSeen=observed;
        internal long Read, Receive, Send;
    }
    readonly Dictionary<int,Counter> counters = new();
    readonly object gate = new();
    internal void Forget(int pid) { lock(gate) counters.Remove(pid); }
    internal void Add(int pid,long qpc,long read=0,long receive=0,long send=0) {
        lock(gate) {
            if(!counters.TryGetValue(pid,out var c)||qpc<c.FirstSeen||read<0||receive<0||send<0)return;
            c.Read+=read;c.Receive+=receive;c.Send+=send;
        }
    }
    internal RunningProgram[] Sample(IEnumerable<RunningProgram> rows,long now,bool ready,bool lost) {
        lock(gate) {
            var result=new List<RunningProgram>(); var alive=new HashSet<int>();
            foreach(var row in rows) {
                alive.Add(row.Pid);
                if(!ready||lost||row.Started==0||!counters.TryGetValue(row.Pid,out var c)||c.Started!=row.Started||now<=c.Since) {
                    if(ready&&row.Started!=0)counters[row.Pid]=new(row.Started,now);else counters.Remove(row.Pid);
                    result.Add(row with {DiskRead=null,NetworkReceive=null,NetworkSend=null});continue;
                }
                var seconds=(now-c.Since)/(double)Stopwatch.Frequency;
                result.Add(row with {DiskRead=c.Read/seconds,NetworkReceive=c.Receive/seconds,NetworkSend=c.Send/seconds});
                c.Read=c.Receive=c.Send=0;c.Since=now;
            }
            foreach(var pid in counters.Keys.Where(p=>!alive.Contains(p)).ToArray())counters.Remove(pid);
            return result.ToArray();
        }
    }
}

// A private real-time ETW session, never the shared NT Kernel Logger. Retain
// only byte counts and process identity; do not persist event metadata or ETL files.
internal sealed class ProcessIoMonitor : IDisposable
{
    readonly ProcessIoLedger ledger = new();
    readonly object gate = new();
    TraceEventSession? session;
    bool disposed, ready;
    long lastLost;
    string status="磁碟 / 網路速率正在準備；首個完整區間後顯示。";
    internal string Status { get { lock(gate)return status; } }

    internal ProcessIoMonitor() { if(OperatingSystem.IsWindows())_ = Task.Run(Run); }

    // The ledger uses Stopwatch's raw QPC clock so late events can be rejected
    // across PID reuse. A session-relative timestamp cannot be compared to it.
#pragma warning disable CS0618
    static long EventClock(TraceEvent e) => e.TimeStampQPC;
#pragma warning restore CS0618

    void Run() {
        TraceEventSession? owned=null;
        try {
            if(TraceEventSession.IsElevated()!=true) {
                lock(gate)status="磁碟 / 網路速率需以系統管理員身分開啟；目前顯示 —，不代表沒有活動。";
                return;
            }
            owned=new TraceEventSession("USBLink.ProcessRates."+Environment.ProcessId+"."+Guid.NewGuid().ToString("N"),
                TraceEventSessionOptions.Create|TraceEventSessionOptions.NoRestartOnCreate) { StopOnDispose=true,BufferSizeMB=16 };
            ETWTraceEventSource source;
            lock(gate) {
                if(disposed)return;
                // Enabling can create a session before throwing. Keep its owner
                // visible until native cleanup finishes, including failed starts.
                session=owned;
                owned.EnableKernelProvider(KernelTraceEventParser.Keywords.DiskIO|KernelTraceEventParser.Keywords.DiskIOInit|
                    KernelTraceEventParser.Keywords.NetworkTCPIP|KernelTraceEventParser.Keywords.Process|KernelTraceEventParser.Keywords.Thread);
                source=owned.Source;
            }
            using var sourceLifetime=source;
            // Only retain thread-to-process state. Default tracking also caches
            // file/object names and disk histories that this panel does not need.
            var kernel=new KernelTraceEventParser(source,KernelTraceEventParser.ParserTrackingOptions.ThreadToProcess);
            kernel.DiskIORead += e=>ledger.Add(e.ProcessID,EventClock(e),read:e.TransferSize);
            kernel.TcpIpRecv += e=>ledger.Add(e.ProcessID,EventClock(e),receive:e.size);
            kernel.TcpIpSend += e=>ledger.Add(e.ProcessID,EventClock(e),send:e.size);
            kernel.TcpIpRecvIPV6 += e=>ledger.Add(e.ProcessID,EventClock(e),receive:e.size);
            kernel.TcpIpSendIPV6 += e=>ledger.Add(e.ProcessID,EventClock(e),send:e.size);
            kernel.UdpIpRecv += e=>ledger.Add(e.ProcessID,EventClock(e),receive:e.size);
            kernel.UdpIpSend += e=>ledger.Add(e.ProcessID,EventClock(e),send:e.size);
            kernel.UdpIpRecvIPV6 += e=>ledger.Add(e.ProcessID,EventClock(e),receive:e.size);
            kernel.UdpIpSendIPV6 += e=>ledger.Add(e.ProcessID,EventClock(e),send:e.size);
            kernel.ProcessStart += e=>ledger.Forget(e.ProcessID);
            kernel.ProcessStop += e=>ledger.Forget(e.ProcessID);
            lock(gate) {
                if(disposed)return;
                ready=true;
                status="磁碟讀取：實際磁碟讀取完成量；網路：TCP / UDP 收發合計（含本機通訊）。快取命中不算磁碟讀取；無法歸屬的事件不計入進程。";
            }
            source.Process();
            lock(gate)if(!disposed)status="速率採集已停止，未取得的資料顯示 —。";
        } catch(Exception e) {
            lock(gate)if(!disposed)status="磁碟 / 網路速率無法採集（"+e.GetType().Name+"），請核對管理員權限；— 不代表零流量。";
        } finally {
            lock(gate)ready=false;
            try { owned?.Dispose(); }
            finally { lock(gate)session=null; }
        }
    }

    internal RunningProgram[] Sample(IEnumerable<RunningProgram> rows) {
        bool active;bool lost=false;
        lock(gate) {
            active=ready;
            if(active&&session!=null) {
                try {
                    var count=session.EventsLost;
                    lost=count!=lastLost;lastLost=count;
                    if(!lost)status="磁碟：實際磁碟讀取；網路：TCP / UDP 收發合計（含本機通訊）。每 3 秒區間平均，事件遞送可能稍有延遲；快取命中不算磁碟讀取。";
                    if(lost)status="速率事件有遺失，本次區間顯示 —；下個完整區間重新計算。";
                } catch { active=false;status="無法確認速率採集狀態，本次顯示 —。"; }
            }
        }
        return ledger.Sample(rows,Stopwatch.GetTimestamp(),active,lost);
    }
    public void Dispose() {
        TraceEventSession? owned;
        lock(gate){if(disposed)return;disposed=true;ready=false;owned=session;}
        // A foreground cleanup thread keeps normal process exit alive until
        // our session stops, without blocking the UI or stopping another tool.
        if(owned!=null)new Thread(()=>{try{owned.Stop(noThrow:true);}catch{}}) {
            IsBackground=false, Name="USB Link process rates cleanup"
        }.Start();
    }
}
