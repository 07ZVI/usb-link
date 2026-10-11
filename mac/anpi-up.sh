#!/bin/bash
# Only configure an interface proven to be under AppleUSBDeviceNCM.
set -euo pipefail
cd "$(dirname "$0")"
original_args=("$@")
mode=up
iface=
label=status
while [ "$#" -gt 0 ]; do
 case "$1" in
  --status) mode=status; shift ;;
  --down) mode=down; shift ;;
  --interface) iface="${2:?missing interface}"; shift 2 ;;
  --snapshot) mode=status; label="${2:?missing label}"; shift 2 ;;
  *) echo '用法：bash anpi-up.sh --status | --interface en3 | --down --interface en3 | --snapshot after-unplug'; exit 2 ;;
 esac
done
case "$label" in *[!a-zA-Z0-9_-]*) echo '快照名稱只允許英數、底線、減號'; exit 2;; esac
umask 077
mkdir -p logs .state
log="logs/mac-stage0-${label}.log"
if [ "${USBNET_LOGGING:-0}" != 1 ]; then
 set +e
 USBNET_LOGGING=1 bash "$PWD/$(basename "$0")" "${original_args[@]}" 2>&1 | tee -a "$log"
 result=${PIPESTATUS[0]}
 exit "$result"
fi
printf '\n%s\n' "$(date '+%Y-%m-%d %H:%M:%S %z') mode=$mode"
raw=$(mktemp)
trap 'rm -f "$raw"' EXIT
/usr/sbin/ioreg -r -c AppleT8103USBXDCI -l -w0 > "$raw"
map=$(awk '
 /\+-o AppleT8103USBXDCI@/ { c=$0; sub(/^.*AppleT8103USBXDCI@/,"",c); sub(/ .*$/,"",c); g=-1 }
 /\+-o AppleUSBNCMData@1 / {g=0}
 /\+-o AppleUSBNCMDataAux@3 / {g=1}
 /"BSD Name" = / { if(g==0||g==1){ n=$0;sub(/^.*"BSD Name" = "/,"",n);sub(/".*$/,"",n);printf "%s|%s|%s\n",c,g,n;g=-1 } }
 ' "$raw")
[ -n "$map" ] || { echo '找不到系統 NCM 對應介面；停止。'; exit 1; }
echo 'USB 裝置連線狀態（OnBus=Yes 的控制器才是本次插線埠）：'
awk '/\+-o AppleT8103USBXDCI@/ {c=$0;sub(/^.*AppleT8103USBXDCI@/,"",c);sub(/ .*$/,"",c)} /"CurrentState" = / {print "controller " c ": " $0}' "$raw"
echo 'USB 控制器 | Windows 介面組 | Mac 網路介面' 
while IFS='|' read -r ctl group name; do
 printf '%s | MI_%02d/MI_%02d | %s\n' "$ctl" "$((group*2))" "$((group*2+1))" "$name"
 /sbin/ifconfig "$name"
done <<< "$map"
# Retain only the scoped USB controller evidence, not a full-machine ioreg dump.
cp "$raw" "logs/mac-usb-controller-${label}.txt"
if [ "$mode" = status ]; then echo "記錄已存：$log"; exit 0; fi
[[ "$iface" =~ ^(anpi|en)[0-9]+$ ]] || { echo '請明確指定上表介面，例如 --interface en3；不可猜測接口。'; exit 2; }
count=$(printf '%s\n' "$map" | awk -F'|' -v n="$iface" '$3==n {i++} END{print i+0}')
[ "$count" = 1 ] || { echo '選擇的介面不在 AppleUSBDeviceNCM 對應表內；停止。'; exit 1; }
state=".state/$iface.owned"
if [ "$mode" = down ]; then
 [ -f "$state" ] || { echo '沒有本工具新增地址的紀錄；不移除既有設定。'; exit 1; }
 if /sbin/ifconfig "$iface" | awk '$1=="inet"&&$2=="10.77.0.1"{found=1} END{exit !found}'; then
  sudo /sbin/ifconfig "$iface" inet 10.77.0.1 -alias
 fi
 rm -f "$state"
 echo '已移除本工具新增的 10.77.0.1；未關閉整個介面。'
else
 if [ -f "$state" ] && /sbin/ifconfig "$iface" | awk '$1=="inet"&&$2=="10.77.0.1"&&$4=="0xffffff00"{found=1} END{exit !found}'; then
  echo '本工具的測試地址已存在。'
 else
  # macOS may self-assign a link-local address before the Windows probe starts.
  # Preserve that address and add our owned alias; refuse other existing IPv4.
  existing=$(/sbin/ifconfig "$iface" | awk '$1=="inet"&&$2!~/^169\.254\./{print $2}')
  [ -z "$existing" ] || { echo "介面已有其他 IPv4 設定：$existing；保留原設定並停止。"; exit 1; }
  conflict=$(/sbin/ifconfig -a | awk '/^[a-zA-Z0-9]+:/{n=$1} $1=="inet"&&$2~/^10\.77\.0\./{print n,$2}')
  [ -z "$conflict" ] || { echo "其他介面已有測試網段地址：$conflict；停止。"; exit 1; }
  # Write ownership intent before mutation so --down can recover interrupted runs.
  printf '10.77.0.1/24 %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$state"
  if ! sudo /sbin/ifconfig "$iface" inet 10.77.0.1 netmask 255.255.255.0 alias up; then rm -f "$state"; exit 1; fi
 fi
fi
/sbin/ifconfig "$iface"
echo "記錄已存：$log"
