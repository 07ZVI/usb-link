package macconnection

func boundedServiceText(s string) string {
	if len(s) <= 384 {
		return s
	}
	end := 0
	for i := range s {
		if i > 384 {
			break
		}
		end = i
	}
	return s[:end]
}

// The fixed raw USB log has an 8 KiB record limit. Keep the full developer
// API snapshot separate and never include credentials in this log.
func boundedGatewayEvidence(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	for _, k := range []string{"permitted_applications", "pending_applications", "recent_drops"} {
		if rows, ok := m[k].([]map[string]any); ok {
			bounded := []map[string]any{}
			for _, row := range rows[:min(2, len(rows))] {
				copyRow := map[string]any{}
				for key, value := range row {
					if text, ok := value.(string); ok {
						value = boundedServiceText(text)
					}
					copyRow[key] = value
				}
				bounded = append(bounded, copyRow)
			}
			out[k] = bounded
			out[k+"_log_truncated"] = len(rows) > 2
		}
	}
	return out
}
