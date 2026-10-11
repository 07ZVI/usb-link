package ipadncm

import (
	"encoding/json"
	"suhang/usbnet/internal/security/appfirewall"
	"suhang/usbnet/internal/security/securitypolicy"
)

// Display limits apply to observation only, never to firewall enforcement or
// stored grants. Keep rules first, then USB records, then a bounded TCP sample.
func securityUIMessage(action, id string, rules []appfirewall.Rule, connections []appfirewall.Connection, devices []securitypolicy.DeviceRecord, problem, summary string) map[string]any {
	m := map[string]any{"event": "security", "action": action, "request_id": id, "problem": problem, "firewall_summary": summary, "mode": "USB 網關 · 應用程式授權；全機手動規則由 Windows 防火牆執行", "rules_total": len(rules), "connections_total": len(connections), "usb_devices_total": len(devices)}
	if len(connections) > 200 {
		connections = connections[:200]
	}
	if len(devices) > 128 {
		devices = devices[:128]
	}
	for {
		m["rules"], m["connections"], m["usb_devices"] = rules, connections, devices
		m["truncated"] = len(connections) != m["connections_total"].(int) || len(devices) != m["usb_devices_total"].(int) || len(rules) != m["rules_total"].(int)
		b, err := json.Marshal(m)
		if err == nil && len(b) <= desktopUIResultLimit {
			return m
		}
		if len(connections) > 0 {
			connections = connections[:len(connections)-1]
			continue
		}
		if len(devices) > 0 {
			devices = devices[:len(devices)-1]
			continue
		}
		// Do not present a partial rule list as the complete managed set.
		rules = nil
		m["rules_unavailable"] = true
		m["problem"] = "安全資料超過顯示限制，未取得完整規則列表。"
		summary = ""
		m["firewall_summary"] = summary
	}
}
