#!/usr/bin/env python3
"""Serve one verified installer to the current USB peer; never execute it."""
import hashlib
import http.server
import json
from pathlib import Path
import shutil
import sys
import threading

installer = Path(sys.argv[1]).resolve()
manifest = json.loads(installer.with_suffix('.manifest.json').read_text())
digest = hashlib.sha256(installer.read_bytes()).hexdigest()
if digest != manifest['sha256'] or installer.stat().st_size != manifest['bytes']:
    raise SystemExit('Installer identity changed')
route = '/' + installer.name


class Handler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.serve(False)

    def do_GET(self):
        self.serve(True)

    def serve(self, body):
        if self.client_address[0] not in ('10.6.9.1', '10.6.9.2'):
            self.send_error(403)
            return
        if self.path != route or self.headers.get('Host') != '10.6.9.2:10690':
            self.send_error(404)
            return
        with installer.open('rb') as stream:
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(manifest['bytes']))
            self.send_header('Content-Disposition', 'attachment; filename="' + installer.name + '"')
            self.send_header('X-Checksum-SHA256', digest)
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            if body:
                try:
                    shutil.copyfileobj(stream, self.wfile, 256 * 1024)
                except (BrokenPipeError, ConnectionResetError):
                    pass


server = http.server.ThreadingHTTPServer(('10.6.9.2', 10690), Handler)
server.daemon_threads = True
timer = threading.Timer(1800, server.shutdown)
timer.daemon = True
timer.start()
print('USB installer download: http://10.6.9.2:10690' + route, flush=True)
try:
    server.serve_forever()
finally:
    timer.cancel()
    server.server_close()
