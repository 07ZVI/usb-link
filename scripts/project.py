#!/usr/bin/env python3
"""Single public build entry: python3 scripts/project.py check|build|package|verify."""
import argparse,hashlib,json,os,pathlib,re,shutil,subprocess,sys,tempfile,zipfile,urllib.request
from windows_resource import write_resource, verify_manifest, verify_icon
from local_installer_retention import retain as retain_local_installers
ROOT=pathlib.Path(__file__).resolve().parents[1]
VERSION=(ROOT/'VERSION').read_text(encoding='utf-8').strip()
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
def profile_tags(profile):
 if profile not in ('local','release'):raise ValueError('Unknown build profile: '+profile)
 # An explicit empty value overrides inherited GOFLAGS=-tags=... for release.
 return '-tags='+('usblink_local_remote' if profile=='local' else '')
def local_publisher_flags(profile):
 if profile!='local':return ''
 key=(ROOT/'.local/secrets/local-update.pub').read_text(encoding='utf-8').strip()
 if not re.fullmatch('[0-9a-f]{64}',key):raise ValueError('Invalid local developer public key')
 return ' -X suhang/usbnet/internal/app/remoteupdate.LocalPublisherHex='+key

def ensure_local_publisher():
 directory=ROOT/'.local/secrets'
 directory.mkdir(mode=0o700,parents=True,exist_ok=True)
 private=directory/'local-update.ed25519';public=directory/'local-update.pub'
 if public.exists():
  local_publisher_flags('local')
  if not private.is_file():raise RuntimeError('Local signing private key missing; restore it before building')
  return
 if private.exists():raise RuntimeError('Local private key exists without public file; preserve it and recover its public key')
 key=subprocess.check_output([GO,'run',profile_tags('local'),'./cmd/usb-link-local-update','--init-key',str(private)],cwd=ROOT,env=ENV,text=True).strip()
 if not re.fullmatch('[0-9a-f]{64}',key):raise RuntimeError('Local signing key generation failed')
 with public.open('x') as f:f.write(key+'\n')
 print('Local developer signing identity ready; private key stays in .local/secrets.',flush=True)

def go_build(target,path,windows=True,extra='',profile='release'):
 env={**ENV,'GOOS':'windows' if windows else 'darwin','GOARCH':'amd64','CGO_ENABLED':'0'}
 run([GO,'build',profile_tags(profile),'-trimpath','-buildvcs=false','-ldflags',f'-s -w -X suhang/usbnet/internal/buildinfo.Version={VERSION} '+extra+local_publisher_flags(profile),'-o',path,target],env)
def verify_release_surface(bridge, profile="release"):
 # Inspect a symbol-bearing twin built from the same source/assets/linker values.
 # The distributed launcher is then built with symbol stripping enabled.
 env={**ENV,'GOOS':'windows','GOARCH':'amd64','CGO_ENABLED':'0'}
 forbidden=['connectioninstall.RunUpdateWorker','usbrecovery.Run','filedrop.','webdav.(*Handler).ServeHTTP']
 if profile=='release':forbidden+=['remoteupdate.(*Server).ServeHTTP','connectioninstall.LaunchLocalRemoteElevation','connectioninstall.DispatchLocalRemoteInstall','connectioninstall.RunLocalRemoteInstall','launcher.handleLocalRemoteCommand', 'ipadncm.applyPhotoPolicy', 'ipadncm.(*localDirectRun).prepare', 'ipadncm.(*directNetworkTarget).mapping']
 if profile=='release':forbidden+=['deviceguard.SubscribeAppleChangeMetadata','deviceguard.(*ChangeMetadataStream).offer']
 if profile=='release':forbidden+=['connectioninstall.RunLocalRemoteRestart','connectioninstall.(*RemoteManager).AuthorizeLocalRestart','connectioninstall.(*RemoteManager).requestLocalRestart','connectioninstall.restartTask','connectioninstall.localRestartHandler']
 with tempfile.TemporaryDirectory(prefix='usb-link-release-check-') as directory:
  candidate=pathlib.Path(directory)/'launcher.exe'
  run([GO,'build',profile_tags(profile),'-trimpath','-buildvcs=false','-ldflags',f'-H windowsgui -X suhang/usbnet/internal/buildinfo.Version={VERSION} -X suhang/usbnet/internal/app/macconnection.expectedBridgeSHA={bridge} -X suhang/usbnet/internal/buildinfo.LocalDiagnostics={str(profile == "local").lower()}'+local_publisher_flags(profile),'-o',candidate,'./cmd/ipad-usb-easy'],env)
  symbols=subprocess.check_output([GO,'tool','nm',str(candidate)],cwd=ROOT,env=env,text=True)
  found=[name for name in forbidden if name in symbols]
  if found:raise RuntimeError('Forbidden '+profile+' functionality linked: '+', '.join(found))
 print(profile.capitalize()+' surface check passed: disallowed remote workers/servers and temporary file-transfer handlers absent.',flush=True)
def notices():
 parts=[(ROOT/'LICENSE').read_text(encoding='utf-8')+'\n'+(ROOT/'LICENSE-WINTUN-EXCEPTION').read_text(encoding='utf-8'),'USB Link '+VERSION+'\nGPL-3.0-only with the official Wintun DLL linking exception. See LICENSE and LICENSE-WINTUN-EXCEPTION.\n']
 for f in sorted((ROOT/'licenses').rglob('*')):
  if f.is_file() and f.suffix.lower()=='.txt':parts+=['\n--- '+f.relative_to(ROOT).as_posix()+' ---\n',f.read_text(encoding='utf-8')]
 (ASSETS/'notices.txt').write_text(''.join(parts), encoding='utf-8')
 wizard_terms=[(ROOT/'LICENSE').read_text(encoding='utf-8'),(ROOT/'LICENSE-WINTUN-EXCEPTION').read_text(encoding='utf-8'),(ROOT/'licenses/Wintun-Binary-LICENSE.txt').read_text(encoding='utf-8'),(ROOT/'licenses/libwdi-LGPL-LICENSE.txt').read_text(encoding='utf-8'),'Zadig 2.9 / libwdi 1.5.1: GPL-3.0-or-later / LGPL-3.0-or-later. Unmodified official binary. Source: https://github.com/pbatard/libwdi/archive/refs/tags/v1.5.1.zip\nComplete third-party notices can be exported with --licenses.\n']
 (ASSETS/'setup-license.txt').write_text('\n\n'.join(wizard_terms), encoding='utf-8')
 (ASSETS/'sources.json').write_text(json.dumps({'version':VERSION,'external_dependencies':json.loads((ROOT/'internal/dependencies/catalog.json').read_text(encoding='utf-8')),'go_module':'go.mod','go_lock':'go.sum','desktop_lock':'desktop/packages.lock.json'},indent=2)+'\n', encoding='utf-8')
def prepare_bundled_dependencies():
 # Official redistributable driver/tool bytes; no proprietary Apple package.
 for asset in json.loads((ROOT/'internal/dependencies/catalog.json').read_text(encoding='utf-8'))['assets']:
  if asset['id'] not in ('wintun','zadig'):continue
  name=asset['url'].rsplit('/',1)[1]
  target=ASSETS/name
  sources=[ROOT/'offline-components'/name,target]
  data=None
  for path in sources:
   if path.is_file() and not path.is_symlink():
    candidate=path.read_bytes()
    if len(candidate)<=asset['max_bytes'] and hashlib.sha256(candidate).hexdigest()==asset['digest']:
     data=candidate;break
  if data is None:
   with urllib.request.urlopen(asset['url'],timeout=60) as response:
    data=response.read(asset['max_bytes']+1)
  if len(data)>asset['max_bytes'] or hashlib.sha256(data).hexdigest()!=asset['digest']:
   raise ValueError('Official component hash mismatch: '+asset['id'])
  target.write_bytes(data)
  print('Verified redistributable official '+asset['id']+' package included.',flush=True)
def prepare(profile="release"):
 ASSETS.mkdir(parents=True,exist_ok=True);OUT.mkdir(exist_ok=True)
 prepare_bundled_dependencies()
 go_build('./cmd/suhang-usbnet',OUT/'suhang-usbnet.exe')
 go_build('./cmd/usb-resource',ASSETS/'usb-resource.exe')
 zipped(ASSETS/'mac-payload.zip',{'suhang-usbnet.exe':OUT/'suhang-usbnet.exe'})
 bridge=sha(OUT/'suhang-usbnet.exe')
 (ASSETS/'mac-sources.json').write_text(json.dumps({'version':VERSION,'files':{'suhang-usbnet.exe':bridge},'payload_sha256':sha(ASSETS/'mac-payload.zip')},indent=2)+'\n', encoding='utf-8')
 run([DOTNET,'restore','desktop/Suhang.Desktop.csproj','--locked-mode','-r','win-x64','-p:NuGetAudit=false'])
 # Publish into a fresh directory: stale DLLs from an earlier release must not
 # silently become authorized content in the next publisher inventory.
 with tempfile.TemporaryDirectory(prefix='desktop-publish-',dir=OUT) as directory:
  published=pathlib.Path(directory)
  run([DOTNET,'publish','desktop/Suhang.Desktop.csproj','--no-restore','-c','Release','-r','win-x64','--self-contained','false','-p:PublishSingleFile=false','-p:USBLinkDesignTools=false',f'-p:USBLinkLocalDiagnostics={str(profile == "local").lower()}','-p:DebugType=None','-p:DebugSymbols=false',f'-p:PathMap={ROOT}=/_/usb-link',f'-p:Version={VERSION}','-o',published])
  verify_icon(published/'USBLink.Desktop.exe',(ROOT/'desktop/Assets/usb-link.ico').read_bytes(),group_id=32512)
  files={f.relative_to(published).as_posix():f for f in published.rglob('*') if f.is_file() and f.suffix!='.pdb'}
  product=re.search(r'const ProductID = "([^"]+)"',(ROOT/'internal/app/connectioninstall/task.go').read_text(encoding='utf-8')).group(1)
  manifest=published/'desktop-ownership.json'
  manifest.write_text(json.dumps({'product':product,'files':{n:sha(f) for n,f in sorted(files.items())}},sort_keys=True,separators=(',',':'))+'\n', encoding='utf-8')
  files[manifest.name]=manifest
  zipped(ASSETS/'desktop.zip',files)
 # Mandatory production-consumer verification; a missing index used to pass
 # every ordinary unit test because the shipped-archive test was skipped.
 run([GO,'test','./internal/app/connectioninstall','-run','Test(IndexedDesktopShipped|InstallationShipped)','-count=1','-v'],{**ENV,'SUHANG_DESKTOP_BENCH_ARCHIVE':str(ASSETS/'desktop.zip'),'USBLINK_TEST_VERSION':VERSION})
 notices()
 return bridge
def check_desktop_contract():
 output=OUT/'desktop-contract'
 run([DOTNET,'build','desktop/Suhang.Desktop.csproj','-c','Release','-p:RuntimeIdentifiers=win-x64','-p:USBLinkDesignTools=true','-p:RestoreLockedMode=true','-p:NuGetAudit=false','-o',output])
 fixtures=ROOT/'internal/contracts/desktopipc/testdata'
 run([DOTNET,output/'USBLink.Desktop.dll','--device-status-smoke',fixtures/'device-status.json',fixtures/'producer-status.json'])
def check():
 run([sys.executable,'scripts/test_publication.py'])
 run([sys.executable,'scripts/test_windows_resource.py'])
 run([sys.executable,'scripts/test_local_installer_retention.py'])
 run([sys.executable,'scripts/test_build_profiles.py'])
 if os.name=='nt':prepare()
 run([GO,'test']+(['-race'] if os.name!='nt' else [])+['./...'])
 run([GO,'vet','./...'])
 check_desktop_contract()
 run([sys.executable,'scripts/check_architecture.py'])
 run([sys.executable,'scripts/audit_distribution.py','--source','--history'])
def setup():
 run(['git','config','--local','core.hooksPath','.githooks'])
 run(['git','config','--local','pull.ff','only'])
 print('Commit/push checks enabled; pulls require a fast-forward.')
def build(profile="release"):
 if profile=="local":ensure_local_publisher()
 bridge=prepare(profile)
 installer=OUT/f'USB-Link-{VERSION}-windows-x64{"-local" if profile == "local" else ""}.exe'
 resource=write_resource(ROOT)
 try:
  verify_release_surface(bridge, profile)
  go_build('./cmd/ipad-usb-easy',installer,True,'-H windowsgui -X suhang/usbnet/internal/app/macconnection.expectedBridgeSHA='+bridge+' -X suhang/usbnet/internal/buildinfo.LocalDiagnostics='+str(profile == 'local').lower(),profile=profile)
  verify_manifest(installer,(ROOT/'cmd/ipad-usb-easy/setup.manifest').read_bytes())
  verify_icon(installer,(ROOT/'desktop/Assets/usb-link.ico').read_bytes())
  run([GO,'test','./internal/app/connectioninstall','-run','TestInstallationShipped','-count=1','-v'],{**ENV,'SUHANG_DESKTOP_BENCH_ARCHIVE':str(ASSETS/'desktop.zip'),'USBLINK_TEST_VERSION':VERSION,'USBLINK_TEST_INSTALLER':str(installer)})
 finally:
  resource.unlink(missing_ok=True)
 go_build('./cmd/mac-usbnet',OUT/'usb-link-mac-x64',False)
 env={**ENV,'GOOS':'darwin','GOARCH':'arm64','CGO_ENABLED':'0'}
 run([GO,'build',profile_tags('release'),'-trimpath','-buildvcs=false','-ldflags',f'-s -w -X suhang/usbnet/internal/buildinfo.Version={VERSION}','-o',OUT/'usb-link-mac-arm64','./cmd/mac-usbnet'],env)
 run([GO,'vet',profile_tags(profile),'./...'],{**ENV,'GOOS':'windows','GOARCH':'amd64','CGO_ENABLED':'0'})
 if profile=='local':
  run([sys.executable,'scripts/audit_distribution.py','--artifact',str(installer)])
  retain_local_installers(ROOT,VERSION,os.environ.get('USBLINK_ROLLBACK_VERSION'))
  write_checksums()
def package():
 build();release=OUT/f'USB-Link-{VERSION}';release.mkdir(exist_ok=True)
 for name in [f'USB-Link-{VERSION}-windows-x64.exe','usb-link-mac-x64','usb-link-mac-arm64']:
  shutil.copyfile(OUT/name,release/name)
 shutil.copytree(ROOT/'licenses',release/'licenses',dirs_exist_ok=True)
 for name in ['LICENSE','LICENSE-WINTUN-EXCEPTION','README.md','README.zh-CN.md','VERSION']:
  shutil.copyfile(ROOT/name,release/name)
 shutil.copytree(ROOT/'docs',release/'docs',dirs_exist_ok=True)
 shutil.copyfile(ROOT/'internal/dependencies/catalog.json',release/'external-dependencies.json')
 zipped(OUT/f'USB-Link-{VERSION}-windows-mac.zip',{f.relative_to(release).as_posix():f for f in release.rglob('*') if f.is_file()})
 # Source archive uses the committed tree, independently of ignored local files.
 run(['git','archive','--format=zip','--prefix=usb-link/','--output',OUT/f'USB-Link-{VERSION}-source.zip','HEAD'])
 verify()
 retain_installers()
 deliver_installer()
 write_checksums()
def deliver_installer():
 # Publish only after verification; preserve the selected accepted rollback.
 source=OUT/f'USB-Link-{VERSION}-windows-x64.exe'
 target=ROOT/f'USB-Link-Setup-{VERSION}.exe'
 temporary=ROOT/f'.USB-Link-Setup-{VERSION}.exe.tmp'
 if target.is_symlink() or temporary.exists():raise ValueError('Redirected/occupied installer delivery path')
 shutil.copyfile(source,temporary)
 if sha(temporary)!=sha(source):raise ValueError('Installer delivery hash mismatch')
 temporary.replace(target)
 retention=json.loads((OUT/'installer-retention.json').read_text(encoding='utf-8'))
 removed=[]
 for item in retention['removed']:
  match=re.fullmatch(r'USB-Link-(\d+\.\d+\.\d+)-windows-x64\.exe',item['path'])
  if not match:continue
  old=ROOT/f'USB-Link-Setup-{match[1]}.exe'
  if old.is_file() and not old.is_symlink() and sha(old)==item['sha256']:
   removed.append({'name':old.name,'sha256':item['sha256']});old.unlink()
 (OUT/'installer-delivery.json').write_text(json.dumps({'version':VERSION,'name':target.name,'bytes':target.stat().st_size,'sha256':sha(target),'removed':removed},indent=2)+'\n', encoding='utf-8')
 print('Installer delivered at repository root: '+target.name,flush=True)
def retain_installers():
 # Run only after the complete package passes inspection. An explicitly chosen
 # rollback may be kept separately from public build output.
 pattern=re.compile(r'USB-Link-(\d+\.\d+\.\d+)-windows-x64\.exe')
 if OUT.is_symlink():raise ValueError('Refusing redirected build output')
 previous=os.environ.get('USBLINK_ROLLBACK_VERSION')
 selected=previous is not None
 receipt=OUT/'installer-retention.json'
 if receipt.is_symlink():raise ValueError('Refusing redirected installer receipt')
 if previous is None and receipt.is_file() and not receipt.is_symlink():
  saved=json.loads(receipt.read_text(encoding='utf-8'))
  if saved.get('previous_selection')=='selected':
   previous=saved.get('previous')
   if not isinstance(previous,str):raise ValueError('Invalid saved rollback selection')
   selected=True
 if previous is not None and not re.fullmatch(r'\d+\.\d+\.\d+',previous):
  raise ValueError('USBLINK_ROLLBACK_VERSION must be an exact numeric release')
 candidates=[]
 for path in OUT.iterdir():
  match=pattern.fullmatch(path.name)
  if match and path.is_file() and not path.is_symlink():candidates.append((match[1],path))
 if previous is None:
  older=[v for v,_ in candidates if tuple(map(int,v.split('.')))<tuple(map(int,VERSION.split('.')))]
  previous=max(older,key=lambda v:tuple(map(int,v.split('.'))),default=None)
 removed=[]
 for version,path in candidates:
  if version in (VERSION,previous):continue
  if tuple(map(int,version.split('.')))>=tuple(map(int,VERSION.split('.'))):continue
  # Only exact generated paths; preserve source archives, unknown files,
  # symlinks, runtime tools, evidence and external rollback storage.
  nested=OUT/f'USB-Link-{version}'/path.name
  binary_zip=OUT/f'USB-Link-{version}-windows-mac.zip'
  paths=[path]
  if not nested.parent.is_symlink():paths.append(nested)
  paths.append(binary_zip)
  for item in paths:
   if item.is_file() and not item.is_symlink():
    removed.append({'path':item.relative_to(OUT).as_posix(),'sha256':sha(item)})
    item.unlink()
 receipt.write_text(json.dumps({'current':VERSION,'previous':previous,'previous_selection':'selected' if selected else 'previous_build','removed':removed},indent=2)+'\n', encoding='utf-8')
 print(f'Installer retention: current={VERSION}, previous={previous}; removed {len(removed)} generated files.',flush=True)
def verify():
 run([sys.executable,'scripts/audit_distribution.py','--package',str(OUT)])
 write_checksums()
def write_checksums():
 files=sorted(f for f in OUT.iterdir() if f.is_file() and f.suffix in ['.zip','.exe'])
 (OUT/'SHA256SUMS').write_text(''.join(f'{sha(f)}  {f.name}\n' for f in files), encoding='utf-8')
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('command',choices=['setup','check','build','package','verify'])
 a.add_argument('--profile',choices=['local','release'],help='build defaults to local; package requires release')
 args=a.parse_args()
 if args.command=='build':build(args.profile or 'local')
 elif args.profile not in (None,'release') or (args.profile and args.command!='package'):
  a.error('--profile is supported by build; package only accepts release')
 else:globals()[args.command]()
