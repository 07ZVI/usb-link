package netconfig

import "testing"

func TestBridgeScriptTimingsRejectFalseAbsenceAndArbitraryPayload(t *testing.T) {
	for _, b := range []string{`{"operation":"setup","count":1,"duration_ms":23.75,"success":false}`, `{"operation":"cleanup","count":1,"duration_ms":0,"success":true}`} {
		if _, e := DecodeBridgeNetworkScriptTiming([]byte(b)); e != nil {
			t.Fatal(e)
		}
	}
	for _, b := range []string{`{"operation":"setup","count":1,"duration_ms":2}`, `{"operation":"setup","count":1,"duration_ms":2,"success":null}`, `{"operation":"setup","count":1,"duration_ms":2,"success":false,"success":true}`, `{"operation":"script contents","count":1,"duration_ms":2,"success":true}`, `{"operation":"setup","count":0,"duration_ms":2,"success":true}`, `{"operation":"setup","count":1,"duration_ms":120001,"success":true}`, `{"operation":"setup","count":1,"duration_ms":-1,"success":true}`, `{"operation":"setup","count":1,"duration_ms":2,"success":true,"path":"C:\\file"}`} {
		if _, e := DecodeBridgeNetworkScriptTiming([]byte(b)); e == nil {
			t.Fatal("invalid diagnostic accepted", b)
		}
	}
}
