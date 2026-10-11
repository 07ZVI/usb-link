#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
iface="${1:?用法：bash capture.sh en3}"
[[ "$iface" =~ ^(en|anpi)[0-9]+$ ]] || exit 2
bash anpi-up.sh --status
[ -f ".state/$iface.owned" ] || { echo '請先使用 anpi-up.sh 設定本次介面。'; exit 1; }
mkdir -p logs
# Capture only this point-to-point probe's ARP/ICMP; do not collect unrelated traffic.
echo "正在擷取 $iface 的測試封包；完成後按 Control-C。"
sudo /usr/sbin/tcpdump -i "$iface" -n -e -tttt -l -s 128 '(arp and (host 10.77.0.1 or host 10.77.0.2)) or (icmp and host 10.77.0.1 and host 10.77.0.2)' 2>&1 | tee -a "logs/mac-capture-$iface.log"
