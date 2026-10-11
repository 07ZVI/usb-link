#!/usr/bin/env python3
"""Fail closed on external components, archives, private materials and local state."""
import argparse,hashlib,io,json,pathlib,re,subprocess,sys,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
FORBIDDEN=re.compile(r'(?i)(^|/)(suhang-update\.exe|usb-send(?:\.exe)?|webdav-check(?:\.exe)?|wintun\.dll|zadig[^/]*\.exe|itunes[^/]*\.exe|apple[^/]*\.(msi|dll|sys|cat)|usbaapl[^/]*|dotnet\.exe|hostfxr\.dll|coreclr\.dll|.*\.(pfx|p12|pem|key|msi|cab))$')
BINARY={'.exe','.dll','.sys','.zip','.tar','.gz','.7z','.dmg','.pkg','.app','.pfx','.p12','.cab','.msi'}
SECRET=re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|/Users/[A-Za-z0-9][A-Za-z0-9._-]*/')
WINTUN_PINS=json.loads((ROOT/'licenses/Wintun-distribution.json').read_text())['files']
ZADIG_PIN='4ecaa95df3da3621486a043aef8b3050b8bafe7c901402871e816229ef82039b'
errors=[];archives=0;entries=0
PRIVATE={'.local','.env','.git','evidence','archive','tooling','reference','deliverables'}
def entry(name,data,source=False,depth=0):
 global entries,archives
 entries+=1
 if source and any(p in PRIVATE or p.startswith('.env.') for p in pathlib.PurePosixPath(name).parts):errors.append(name+' local-only path in public source')
 logical=name.rsplit('!/',1)[-1]
 permitted_wintun=not source and logical in WINTUN_PINS and hashlib.sha256(data).hexdigest()==WINTUN_PINS[logical]
 permitted_zadig=not source and logical=='zadig-2.9.exe' and hashlib.sha256(data).hexdigest()==ZADIG_PIN
 if FORBIDDEN.search(name) and not (permitted_wintun or permitted_zadig):errors.append(name+' external component/private material')
 if SECRET.search(data):errors.append(name+' private identity/credential')
 if source and pathlib.Path(name).suffix.lower() in BINARY and not (depth==0 and name.endswith('-source.zip') and data.startswith(b'PK\x03\x04')):errors.append(name+' binary in public source')
 if depth>4:errors.append(name+' nested archive limit');return
 if len(data)>256<<20:errors.append(name+' file limit');return
 # A regular ZIP's compressed bytes may contain an inner EOCD but not its
 # original local-header offsets. Inspect its logical entries once; raw EOCD
 # scanning is reserved for embedded resources in non-ZIP files such as PE.
 normal_zip=data.startswith(b'PK\x03\x04');normal_zip_found=False
 pos=0
 while True:
  pos=data.find(b'PK\x05\x06',pos)
  if pos<0:break
  if pos+22>len(data):break
  end=pos+22+int.from_bytes(data[pos+20:pos+22],'little');pos+=4
  if end>len(data):continue
  if normal_zip and end!=len(data):continue
  try:z=zipfile.ZipFile(io.BytesIO(data[:end]))
  except(zipfile.BadZipFile,ValueError):continue
  if normal_zip:
   normal_zip_found=True
   if z.infolist() and min(f.header_offset for f in z.infolist())!=0:errors.append(name+' unexpected prefixed archive');z.close();continue
  archives+=1
  if len(z.infolist())>5000 or sum(f.file_size for f in z.infolist())>512<<20:errors.append(name+' unbounded archive');continue
  for f in z.infolist():
   if f.is_dir():continue
   if '..' in pathlib.PurePosixPath(f.filename).parts or f.filename.startswith('/') or '\\' in f.filename:errors.append(name+' unsafe archive path');continue
   try:entry(name+'!/'+f.filename,z.read(f),source,depth+1)
   except(Exception) as e:errors.append(name+' corrupt archive '+str(e))
  z.close()
 if normal_zip and not normal_zip_found:errors.append(name+' corrupt ZIP footer')
def source():
 # Git, rather than a recursive walk, defines the publication boundary. This
 # never traverses ignored private directories, but catches force-added files.
 names=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=ROOT).split(b'\0')
 for raw in sorted(set(names)-{b''}):
  name=raw.decode('utf-8');f=ROOT/name
  if f.is_symlink():errors.append(name+' symlink');continue
  if not f.exists():continue  # locally deleted, not yet staged
  if not f.is_file():errors.append(name+' nested repository/non-file');continue
  entry(name,f.read_bytes(),True)
def staged():
 # Inspect the index, not the working copy: unstaged edits cannot conceal a
 # staged credential from a commit check.
 rows=subprocess.check_output(['git','ls-files','--stage','-z'],cwd=ROOT).split(b'\0')
 objects=[]
 for row in rows:
  if not row:continue
  meta,name=row.split(b'\t',1);mode,oid,stage=meta.split()
  if stage!=b'0' or mode not in (b'100644',b'100755'):errors.append(name.decode()+' unsupported index entry');continue
  objects.append((oid,name.decode()))
 scan_objects(objects)
def history():
 # Codex turn-diff trees are local UI snapshots, including untracked builds.
 # They are not source history. Keep auditing every other ref, including any
 # branch/tag that explicitly publishes the same tree.
 refs=subprocess.check_output(['git','for-each-ref','--format=%(refname)'],cwd=ROOT,text=True).splitlines()
 roots=['HEAD']+[r for r in refs if not r.startswith('refs/codex/turn-diffs/')]
 rows=subprocess.check_output(['git','rev-list','--objects',*roots],cwd=ROOT).splitlines()
 objects=[(row.split(b' ',1)[0],row.split(b' ',1)[1].decode()) for row in rows if b' ' in row]
 scan_objects(objects)
def scan_objects(objects):
 data=subprocess.check_output(['git','cat-file','--batch'],input=b''.join(oid+b'\n' for oid,_ in objects),cwd=ROOT)
 stream=io.BytesIO(data)
 for oid,name in objects:
  header=stream.readline().split()
  if len(header)!=3:raise RuntimeError('Cannot read Git object '+oid.decode())
  size=int(header[2]);body=stream.read(size);stream.read(1)
  if header[1]==b'blob':entry(name,body,True)
def package(path):
 path=pathlib.Path(path)
 for f in path.iterdir():
  if f.is_file() and f.suffix in {'.exe','.zip'}:entry(f.name,f.read_bytes(),f.name.endswith('-source.zip'))
 # Build output receipts must contain only original executable code and linked libs.
 assets=ROOT/'internal/app/launcher/assets'
 if assets.exists():
  for f in assets.glob('*.zip'):entry(f.name,f.read_bytes())
  for f in assets.glob('zadig-*.exe'):entry(f.name,f.read_bytes())
parser=argparse.ArgumentParser();parser.add_argument('--source',action='store_true');parser.add_argument('--staged',action='store_true');parser.add_argument('--history',action='store_true');parser.add_argument('--package');a=parser.parse_args()
if a.source:source()
if a.staged:staged()
if a.history:history()
if a.package:package(a.package)
result={'status':'failed' if errors else 'passed','files_and_entries':entries,'archives_inspected':archives,'errors':errors}
print(json.dumps(result,ensure_ascii=False,indent=2));sys.exit(bool(errors))
