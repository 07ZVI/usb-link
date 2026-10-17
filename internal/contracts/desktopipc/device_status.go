// Package desktopipc defines display data exchanged with the desktop renderer.
// Connection state describes peer evidence; Connected preserves transport state.
package desktopipc

type DeviceStatus struct {
	Device              string  `json:"device"`
	ConnectionState     string  `json:"connection_state"`
	Title               string  `json:"title"`
	Subtitle            string  `json:"subtitle"`
	Detail              string  `json:"detail,omitempty"`
	WindowsIPv4         string  `json:"windows_ipv4"`
	Connected           bool    `json:"connected"`
	PeerIPv4            string  `json:"peer_ipv4"`
	PeerAddressState    string  `json:"peer_address_state"`
	RetryAvailable      bool    `json:"retry_available"`
	TX                  float64 `json:"tx"`
	RX                  float64 `json:"rx"`
	Speed               string  `json:"speed"`
	Health              string  `json:"health"`
	Latency             string  `json:"latency"`
	BenchmarkURL        string  `json:"benchmark_url"`
	BenchmarkSummary    string  `json:"benchmark_summary"`
	BenchmarkReady      bool    `json:"benchmark_ready"`
	BenchmarkAvailable  bool    `json:"benchmark_available"`
	MeasurementBusy     bool    `json:"measurement_busy"`
	MeasurementProgress int     `json:"measurement_progress"`
	BenchmarkVisible    bool    `json:"benchmark_visible"`
}
