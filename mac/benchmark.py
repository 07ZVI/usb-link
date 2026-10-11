#!/usr/bin/env python3
"""Bounded, integrity-checked TCP benchmark for the USB point-to-point link."""
import argparse, hashlib, json, secrets, socket, time
from pathlib import Path

CHUNK = 32768
PATTERN = bytes(i % 251 for i in range(CHUNK))

def measure(direction, size, address='10.77.0.2', source='10.77.0.1', port=47772):
    nonce = secrets.token_hex(16)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(20)
        sock.bind((source, 0))
        sock.connect((address, port))
        sock.sendall(f'SUHANG-USB-BENCH/1 {direction} {size} {nonce}\n'.encode())
        stream = sock.makefile('rb')
        if stream.readline(256) != f'READY {nonce}\n'.encode():
            raise RuntimeError('unexpected benchmark handshake')
        start = time.monotonic(); digest = hashlib.sha256(); transferred = 0
        while transferred < size:
            count = min(CHUNK, size - transferred)
            if direction == 'UP':
                part = PATTERN[:count]; sock.sendall(part)
            else:
                part = stream.read(count)
                if len(part) != count or part != PATTERN[:count]:
                    raise RuntimeError('incomplete or corrupt download')
            digest.update(part); transferred += count
        result = json.loads(stream.readline(4096))
        elapsed = time.monotonic() - start
        if result['nonce'] != nonce or result['direction'] != direction or result['bytes'] != size or result['sha256'] != digest.hexdigest():
            raise RuntimeError('benchmark integrity mismatch')
        return dict(direction=direction, bytes=size, sha256=digest.hexdigest(), seconds=elapsed,
                    mbps=size*8/elapsed/1e6, windows=result)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--mib', type=int, default=16)
    parser.add_argument('--rounds', type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.mib <= 64: parser.error('size must be 1–64 MiB')
    if not 1 <= args.rounds <= 5: parser.error('rounds must be 1–5')
    result = dict(protocol='SUHANG-USB-BENCH/1', timestamp=time.strftime('%Y-%m-%d %H:%M:%S %z'),
                  source='10.77.0.1', peer='10.77.0.2', results=[])
    for round_index in range(args.rounds):
        for direction in ['UP', 'DOWN']:
            measurement = measure(direction, args.mib*1024*1024)
            measurement['round'] = round_index + 1
            result['results'].append(measurement)
            print(f"Round {round_index+1} {direction}: {measurement['mbps']:.2f} Mbps; SHA256 OK", flush=True)
    path = Path(__file__).resolve().parent/'logs'/'mac-usb-benchmark.json'
    content = json.dumps(result, indent=2)+'\n'
    path.write_text(content)
    historical = path.with_name('mac-usb-benchmark-'+time.strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4)+'.json')
    historical.write_text(content)
    print('測速記錄：', path)
