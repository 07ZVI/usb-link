#!/bin/sh
# Temporary, one-interface experiment. No installation or persistent settings.
set -eu
[ "$(id -u)" = 0 ] || { echo 'Administrator approval is required for this temporary MTU experiment.' >&2; exit 1; }
case "${1:-}" in 9000|16000) target="$1" ;; *) exit 2 ;; esac
iface=en3
expected_mac='06:25:07:47:6a:b5'
state=$(/sbin/ifconfig "$iface")
printf '%s\n' "$state" | /usr/bin/grep -F "ether $expected_mac" >/dev/null
printf '%s\n' "$state" | /usr/bin/grep -F 'inet 10.6.9.2 netmask 0xffffff00' >/dev/null
printf '%s\n' "$state" | /usr/bin/grep -F 'mtu 1500' >/dev/null
# Schedule rollback before changing MTU. Do not overwrite a later manual MTU.
(
 /bin/sleep 180
 current=$(/sbin/ifconfig "$iface")
 if printf '%s\n' "$current" | /usr/bin/grep -F "ether $expected_mac" >/dev/null && printf '%s\n' "$current" | /usr/bin/grep -F "mtu $target" >/dev/null; then
  /sbin/ifconfig "$iface" mtu 1500
 fi
) </dev/null >/dev/null 2>&1 &
/sbin/ifconfig "$iface" mtu "$target"
/sbin/ifconfig "$iface"
echo 'Temporary USB MTU applied; automatic rollback is scheduled in 180 seconds.'
