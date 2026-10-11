#!/usr/bin/env python3
"""Single public build entry: python3 scripts/project.py check|build|package|verify."""
import argparse,hashlib,json,os,pathlib,shutil,subprocess,sys,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
VERSION=(ROOT/'VERSION').read_text().strip()
OUT=ROOT/'out'
ASSETS=ROOT/'internal/app/launcher/assets'
GO=os.environ.get('USBLINK_GO','go')
DOTNET=os.environ.get('USBLINK_DOTNET','dotnet')
ENV={**os.environ,'GOTOOLCHAIN':'local','DOTNET_CLI_TELEMETRY_OPTOUT':'1','DOTNET_NOLOGO':'1','AVALONIA_TELEMETRY_OPTOUT':'1'}
def run(args,env=None):
 print('+',' '.join(map(str,args)),flush=True)
 subprocess.run(list(map(str,args)),cwd=ROOT,env=env or ENV,check=True)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def zipped(path,files):
 path.parent.mkdir(parents=True,exist_ok=True)
 with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
  for name,f in sorted(files.items()):
   info=zipfile.ZipInfo(name,(2020,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=(0o100755 if f.stat().st_mode & 0o111 else 0o100644)<<16
   z.writestr(info,f.read_bytes())
def go_build(target,path,windows=True,extra=''):
 env={**ENV,'GOOS':'windows' if windows else 'darwin','GOARCH':'amd64','CGO_ENABLED':'0'}
 run([GO,'build','-trimpath','-buildvcs=false','-ldflags',f'-s -w -X suhang/usbnet/internal/buildinfo.Version={VERSION} '+extra,'-o',path,target],env)
def notices():
 parts=[(ROOT/'LICENSE').read_text()+'\n'+(ROOT/'LICENSE-WINTUN-EXCEPTION').read_text(),'USB Link '+VERSION+'\nGPL-3.0-only with the official Wintun DLL linking exception. See LICENSE and LICENSE-WINTUN-EXCEPTION.\n']
 for f in sorted((ROOT/'licenses').rglob('*')):
  if f.is_file() and f.suffix.lower()=='.txt':parts+=['\n--- '+f.relative_to(ROOT).as_posix()+' ---\n',f.read_text()]
 (ASSETS/'notices.txt').write_text(''.join(parts))
 (ASSETS/'sources.json').write_text(json.dumps({'version':VERSION,'external_dependencies':json.loads((ROOT/'internal/dependencies/catalog.json').read_text()),'go_module':'go.mod','go_lock':'go.sum','desktop_lock':'desktop/packages.lock.json'},indent=2)+'\n')
 shutil.copyfile(ROOT/'licenses/provenance/SMB-LICENSES-0.8.36.txt',ASSETS/'smb-licenses.txt')
 shutil.copyfile(ROOT/'licenses/provenance/SMB-SOURCES-0.8.36.json',ASSETS/'smb-sources.json')
def prepare():
 ASSETS.mkdir(parents=True,exist_ok=True);OUT.mkdir(exist_ok=True)
 go_build('./cmd/suhang-usbnet',OUT/'suhang-usbnet.exe')
 go_build('./cmd/usb-resource',ASSETS/'usb-resource.exe')
 zipped(ASSETS/'mac-payload.zip',{'suhang-usbnet.exe':OUT/'suhang-usbnet.exe'})
 bridge=sha(OUT/'suhang-usbnet.exe')
 (ASSETS/'mac-sources.json').write_text(json.dumps({'version':VERSION,'files':{'suhang-usbnet.exe':bridge},'payload_sha256':sha(ASSETS/'mac-payload.zip')},indent=2)+'\n')
 run([DOTNET,'restore','desktop/Suhang.Desktop.csproj','--locked-mode','-r','win-x64','-p:NuGetAudit=false'])
 run([DOTNET,'publish','desktop/Suhang.Desktop.csproj','--no-restore','-c','Release','-r','win-x64','--self-contained','false','-p:PublishSingleFile=false','-p:DebugType=None','-p:DebugSymbols=false',f'-p:PathMap={ROOT}=/_/usb-link',f'-p:Version={VERSION}','-o',OUT/'desktop'])
 files={f.relative_to(OUT/'desktop').as_posix():f for f in (OUT/'desktop').rglob('*') if f.is_file() and f.suffix!='.pdb'}
 zipped(ASSETS/'desktop.zip',files);notices()
 return bridge
def check():
 if os.name=='nt':prepare()
 run([GO,'test']+(['-race'] if os.name!='nt' else [])+['./...'])
 run([GO,'vet','./...'])
 run([sys.executable,'scripts/check_architecture.py'])
 run([sys.executable,'scripts/audit_distribution.py','--source'])
def build():
 bridge=prepare()
 go_build('./cmd/ipad-usb-easy',OUT/f'USB-Link-{VERSION}-windows-x64.exe',True,'-H windowsgui -X suhang/usbnet/internal/app/macconnection.expectedBridgeSHA='+bridge)
 go_build('./cmd/suhang-update',OUT/'suhang-update.exe')
 go_build('./cmd/mac-usbnet',OUT/'usb-link-mac-x64',False)
 env={**ENV,'GOOS':'darwin','GOARCH':'arm64','CGO_ENABLED':'0'}
 run([GO,'build','-trimpath','-buildvcs=false','-ldflags',f'-s -w -X suhang/usbnet/internal/buildinfo.Version={VERSION}','-o',OUT/'usb-link-mac-arm64','./cmd/mac-usbnet'],env)
 run([GO,'vet','./...'],{**ENV,'GOOS':'windows','GOARCH':'amd64','CGO_ENABLED':'0'})
def package():
 build();release=OUT/f'USB-Link-{VERSION}';release.mkdir(exist_ok=True)
 for name in [f'USB-Link-{VERSION}-windows-x64.exe','usb-link-mac-x64','usb-link-mac-arm64','suhang-update.exe']:
  shutil.copyfile(OUT/name,release/name)
 shutil.copytree(ROOT/'licenses',release/'licenses',dirs_exist_ok=True)
 for name in ['LICENSE','LICENSE-WINTUN-EXCEPTION','README.md','VERSION']:
  shutil.copyfile(ROOT/name,release/name)
 shutil.copytree(ROOT/'docs',release/'docs',dirs_exist_ok=True)
 shutil.copyfile(ROOT/'internal/dependencies/catalog.json',release/'external-dependencies.json')
 zipped(OUT/f'USB-Link-{VERSION}-windows-mac.zip',{f.relative_to(release).as_posix():f for f in release.rglob('*') if f.is_file()})
 # Source archive uses the committed tree, independently of ignored local files.
 run(['git','archive','--format=zip','--prefix=usb-link/','--output',OUT/f'USB-Link-{VERSION}-source.zip','HEAD'])
 verify()
def verify():
 run([sys.executable,'scripts/audit_distribution.py','--package',str(OUT)])
 files=sorted(f for f in OUT.iterdir() if f.is_file() and f.suffix in ['.zip','.exe'])
 (OUT/'SHA256SUMS').write_text(''.join(f'{sha(f)}  {f.name}\n' for f in files))
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('command',choices=['check','build','package','verify']);args=a.parse_args()
 globals()[args.command]()
