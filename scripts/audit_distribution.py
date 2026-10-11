#!/usr/bin/env python3
"""Fail closed on external components, archives, private materials and local state."""
import argparse,io,json,pathlib,re,sys,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
FORBIDDEN=re.compile(r'(?i)(^|/)(wintun\.dll|zadig[^/]*\.exe|itunes[^/]*\.exe|apple[^/]*\.(msi|dll|sys|cat)|usbaapl[^/]*|dotnet\.exe|hostfxr\.dll|coreclr\.dll|.*\.(pfx|p12|pem|key|msi|cab))$')
BINARY={'.exe','.dll','.sys','.zip','.tar','.gz','.7z','.dmg','.pkg','.app','.pfx','.p12','.cab','.msi'}
SECRET=re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|/Users/[A-Za-z0-9][A-Za-z0-9._-]*/')
errors=[];archives=0;entries=0
IGNORED={'.git','out','bin','obj','assets','__pycache__','.avalonia-build-tasks'}
def entry(name,data,source=False,depth=0):
 global entries,archives
 entries+=1
 if FORBIDDEN.search(name):errors.append(name+' external component/private material')
 if SECRET.search(data):errors.append(name+' private identity/credential')
 if source and pathlib.Path(name).suffix.lower() in BINARY:errors.append(name+' binary in public source')
 if depth>4:errors.append(name+' nested archive limit');return
 if len(data)>256<<20:errors.append(name+' file limit');return
 # Inspect every embedded ZIP end, including ZIPs inside the native launcher PE.
 pos=0
 while True:
  pos=data.find(b'PK\x05\x06',pos)
  if pos<0:break
  if pos+22>len(data):break
  end=pos+22+int.from_bytes(data[pos+20:pos+22],'little');pos+=4
  if end>len(data):continue
  try:z=zipfile.ZipFile(io.BytesIO(data[:end]))
  except(zipfile.BadZipFile,ValueError):continue
  archives+=1
  if len(z.infolist())>5000 or sum(f.file_size for f in z.infolist())>512<<20:errors.append(name+' unbounded archive');continue
  for f in z.infolist():
   if f.is_dir():continue
   if '..' in pathlib.PurePosixPath(f.filename).parts or f.filename.startswith('/') or '\\' in f.filename:errors.append(name+' unsafe archive path');continue
   try:entry(name+'!/'+f.filename,z.read(f),source,depth+1)
   except(Exception) as e:errors.append(name+' corrupt archive '+str(e))
  z.close()
def source():
 for f in ROOT.rglob('*'):
  rel=f.relative_to(ROOT)
  if any(x in IGNORED for x in rel.parts) or not f.is_file():continue
  if f.is_symlink():errors.append(str(rel)+' symlink');continue
  entry(rel.as_posix(),f.read_bytes(),True)
def package(path):
 path=pathlib.Path(path)
 for f in path.iterdir():
  if f.is_file() and f.suffix in {'.exe','.zip'}:entry(f.name,f.read_bytes(),f.name.endswith('-source.zip'))
 # Build output receipts must contain only original executable code and linked libs.
 assets=ROOT/'internal/app/launcher/assets'
 if assets.exists():
  for f in assets.glob('*.zip'):entry(f.name,f.read_bytes())
parser=argparse.ArgumentParser();parser.add_argument('--source',action='store_true');parser.add_argument('--package');a=parser.parse_args()
if a.source:source()
if a.package:package(a.package)
result={'status':'failed' if errors else 'passed','files_and_entries':entries,'archives_inspected':archives,'errors':errors}
print(json.dumps(result,ensure_ascii=False,indent=2));sys.exit(bool(errors))
