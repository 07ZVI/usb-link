#!/usr/bin/env python3
import pathlib,re,sys
root=pathlib.Path(__file__).resolve().parents[1]
allowed={'app','buildinfo','contracts','dependencies','diagnostics','platform','security','sharing','transport'}
errors=[]
for f in (root/'internal').rglob('*.go'):
 if 'assets' in f.parts:continue
 group=f.relative_to(root/'internal').parts[0]
 if group not in allowed:errors.append(str(f)+' unowned module')
 for imp in re.findall(r'"suhang/usbnet/internal/([^"\n]+)"',f.read_text()):
  dependency=imp.split('/')[0]
  if not f.name.endswith('_test.go') and group in {'contracts','buildinfo','dependencies','transport'} and dependency=='app':errors.append(str(f)+' lower layer imports app')
for f in (root/'cmd').glob('*/main*.go'):
 if f.parent.name in {'ipad-usb-easy','suhang-usbnet','mac-usbnet','suhang-update'} and len(f.read_text().splitlines())>16:errors.append(str(f)+' entry contains business logic')
if errors:print('\n'.join(errors));sys.exit(1)
print('Architecture ownership and lower-layer boundaries passed')
