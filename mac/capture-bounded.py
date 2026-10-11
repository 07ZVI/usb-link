#!/usr/bin/env python3
"""Bounded, narrow packet capture for Codex-owned USB diagnostics."""
import re, signal, subprocess, sys, time
from pathlib import Path

iface = sys.argv[1]
seconds = int(sys.argv[2])
auto_test = len(sys.argv) == 4 and sys.argv[3] == '--auto-test'
if not re.fullmatch(r'(en|anpi)[0-9]+', iface) or not 5 <= seconds <= 60:
    raise SystemExit('invalid capture interface/duration')
root = Path(__file__).resolve().parent
if not (root/'.state'/f'{iface}.owned').is_file():
    raise SystemExit('interface has no owned test-address record')
deadline = time.monotonic() + (180 if auto_test else 0)
while True:
    status = subprocess.check_output(['/sbin/ifconfig', iface], text=True)
    if 'inet 10.77.0.1 netmask 0xffffff00' not in status:
        raise SystemExit('expected test alias missing')
    if not auto_test or 'status: active' in status:
        break
    if time.monotonic() >= deadline:
        raise SystemExit('USB interface did not become active; no capture/test sent')
    time.sleep(0.5)
packet_filter = '(arp and (host 10.77.0.1 or host 10.77.0.2)) or (icmp and host 10.77.0.1 and host 10.77.0.2)'
with (root/'logs'/f'mac-capture-{iface}-live.log').open('a') as output:
    process = subprocess.Popen(['/usr/sbin/tcpdump', '-i', iface, '-n', '-e', '-tttt', '-l', '-s', '128', packet_filter], stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
    try:
        if auto_test:
            # Capture is already running before generating the first peer ARP.
            time.sleep(1)
            output.flush()
            if process.poll() is not None:
                raise SystemExit('capture stopped before testing')
            subprocess.run(['/usr/sbin/arp', '-d', '10.77.0.2', 'ifscope', iface], stdout=output, stderr=subprocess.STDOUT)
            with (root/'logs'/f'mac-ping-{iface}-capture.log').open('w') as ping_log:
                result = subprocess.run(['/sbin/ping', '-S', '10.77.0.1', '-c', '5', '-W', '1000', '10.77.0.2'], stdout=ping_log, stderr=subprocess.STDOUT, timeout=10)
            print('ping exit='+str(result.returncode), flush=True)
            # Wait until dedicated Windows echo processing is recorded, then
            # request this run's first immutable diagnostic snapshot.
            with (root/'logs'/'mac-usb-log-collection.log').open('a') as collect_log:
                subprocess.run(['/usr/bin/python3', str(root/'collect-windows.py')], stdout=collect_log, stderr=subprocess.STDOUT, timeout=30)
        process.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            output.write('Capture reached its time limit; helper forced stop after SIGTERM timeout.\n')
            output.flush()
            process.kill()
            process.wait()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    if process.returncode not in (0, -signal.SIGINT, -signal.SIGTERM, -signal.SIGKILL):
        raise SystemExit('packet capture failed: '+str(process.returncode))
