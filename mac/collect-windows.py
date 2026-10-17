#!/usr/bin/env python3
"""Collect only the USB probe's fixed logs over its point-to-point UDP channel."""
import argparse, base64, hashlib, json, os, secrets, shutil, signal, socket, subprocess, time
from pathlib import Path
def collect_archives(out):
 """Optional fixed-route export; failures never discard the primary USB logs."""
 root=Path(__file__).resolve().parents[1]
 go=os.environ.get('USBLINK_GO') or shutil.which('go') or str(root/'.local/tooling/go-1.26.0/go/bin/go')
 report={'status':'unavailable'}
 process=None
 try:
  # The child runs in the repository; resolve the caller's output before changing cwd.
  command=[go,'run','-tags=usblink_local_remote','./cmd/usb-link-local-update','--collect-archives',str((out/'connection-archives').resolve())]
  env={**os.environ,'GOTOOLCHAIN':'local','GOCACHE':str(root/'.local/tooling/go-cache')}
  process=subprocess.Popen(command,cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,start_new_session=True)
  text,_=process.communicate(timeout=180)
  report={'status':'collected' if process.returncode==0 else 'unavailable','exit_code':process.returncode}
  for line in text.splitlines():
   if line.startswith('Archive collection: '):
    state=line.split()[2]
    if state in ('complete','partial','failed','unsupported'):report['status']=state
 except subprocess.TimeoutExpired:
  if process is not None:
   try:os.killpg(process.pid,signal.SIGKILL)
   except OSError:pass
   try:process.communicate(timeout=3)
   except subprocess.TimeoutExpired:pass
  report={'status':'timeout'}
 except (OSError,ValueError):
  report={'status':'collector_unavailable'}
 try:(out/'archive-collection.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 except OSError:pass
 print('按輪連線檔案收取：',report['status'],'；原有 Windows 診斷已保留。')

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--profile',choices=['legacy','unified'],default='legacy')
parser.add_argument('--output',type=Path)
args=parser.parse_args()
local,remote=('10.6.9.2','10.6.9.1') if args.profile=='unified' else ('10.77.0.1','10.77.0.2')
nonce=secrets.token_hex(16)
request=('SUHANG-USB-PROBE/1 LOGS '+nonce).encode('ascii')
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind((local,47771))
s.settimeout(1)
parts={};total=None;digest=None
out=args.output or Path(__file__).resolve().parent/'logs';out.mkdir(parents=True,exist_ok=True)
# Retransmit the same read-only request at most three times. This never retries
# USB initialization or changes any Windows setting.
for attempt in range(3):
 s.sendto(request,(remote,47771))
 deadline=time.monotonic()+8
 while time.monotonic()<deadline:
  try:b,peer=s.recvfrom(2048)
  except socket.timeout:continue
  if peer!=(remote,47771):continue
  try:
   msg=json.loads(b)
   if msg.get('protocol')!='SUHANG-USB-PROBE/1' or msg.get('nonce')!=nonce:continue
   n=msg['total'];i=msg['index'];sha=msg['sha256']
   if not isinstance(n,int) or not isinstance(i,int) or not 1<=n<=438 or not 0<=i<n or len(sha)!=64:continue
   if total is None:total=n;digest=sha
   if n!=total or sha!=digest:continue
   data=base64.b64decode(msg['data'],validate=True)
   if len(data)>600:continue
   parts[i]=data
  except (ValueError,KeyError,TypeError):continue
  if total is not None and len(parts)==total:
   content=b''.join(parts[i] for i in range(total))
   if len(content)>256*1024 or hashlib.sha256(content).hexdigest()!=digest:raise RuntimeError('診斷資料校驗失敗')
   obj=json.loads(content)
   if set(obj.get('logs',{}))!=set(['installer.log','ncm-probe.log']):raise RuntimeError('非預期日誌')
   (out/'windows-diagnostics.json').write_bytes(content)
   for name in ['installer.log','ncm-probe.log']:(out/('windows-'+name)).write_text(obj['logs'][name],encoding='utf-8')
   print('已從 USB 收到 Windows 日誌：',out/'windows-diagnostics.json')
   s.close()
   if args.profile=='unified':collect_archives(out)
   raise SystemExit(0)
s.close()
raise SystemExit('USB 日誌回傳尚未成功；Windows 本地仍保留日誌。')
