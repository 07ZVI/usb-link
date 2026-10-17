#!/usr/bin/env python3
"""Run the local USB updater with this workspace's developer signing identity."""
import os
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
public = ROOT / '.local/secrets/local-update.pub'
if not public.is_file():
    raise SystemExit('Build a local installer first to initialize its developer signing identity.')
key = public.read_text().strip()
if not re.fullmatch('[0-9a-f]{64}', key):
    raise SystemExit('Invalid local developer public key.')
go = os.environ.get('USBLINK_GO') or shutil.which('go') or str(ROOT / '.local/tooling/go-1.26.0/go/bin/go')
env = {**os.environ, 'GOTOOLCHAIN': 'local', 'GOCACHE': str(ROOT / '.local/tooling/go-cache')}
args = [go, 'run', '-tags=usblink_local_remote', '-ldflags',
        '-X suhang/usbnet/internal/app/remoteupdate.LocalPublisherHex=' + key,
        './cmd/usb-link-local-update', *sys.argv[1:]]
raise SystemExit(subprocess.call(args, cwd=ROOT, env=env))
