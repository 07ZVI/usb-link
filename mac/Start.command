#!/bin/bash
cd "$(dirname "$0")"
bash anpi-up.sh --status
read -r -p '輸入上表中本次測試的介面（例如 en3 或 anpi0）：' iface
bash anpi-up.sh --interface "$iface" || { read -r -p '設定未完成；按 Enter 結束。' _; exit 1; }
echo "另開終端機：cd \"$PWD\" && bash capture.sh $iface"
echo 'Windows 探測程式按 Enter 後，在本視窗按 Enter 開始 ping；約 35 秒後結束。'
read -r _
/sbin/ping -c 35 -S 10.77.0.1 10.77.0.2 2>&1 | tee "logs/mac-ping-$iface.log"
bash anpi-up.sh --snapshot after-probe
read -r -p '按 Enter 結束。' _
