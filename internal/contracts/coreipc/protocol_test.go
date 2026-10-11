package coreipc

import (
	"encoding/json"
	"strings"
	"testing"
)

const testID = "0123456789abcdef0123456789abcdef"

func TestRequestRejectsAmbiguousOrUnboundedMessages(t *testing.T) {
	good := `{"version":1,"id":"` + testID + `","method":"snapshot","payload":{}}`
	if _, e := ParseRequest([]byte(good)); e != nil {
		t.Fatal(e)
	}
	for name, input := range map[string]string{
		"duplicate":         strings.Replace(good, `"version":1`, `"version":1,"version":1`, 1),
		"unknown":           strings.Replace(good, `"payload":{}`, `"payload":{},"executable":"foreign"`, 1),
		"missing":           strings.Replace(good, `,"payload":{}`, ``, 1),
		"trailing":          good + `{}`,
		"wrong_version":     strings.Replace(good, `"version":1`, `"version":2`, 1),
		"arbitrary_command": strings.Replace(good, `snapshot`, `run`, 1),
		"mixed_case_id":     strings.Replace(good, testID, strings.ToUpper(testID), 1),
		"oversize":          strings.Replace(good, `{}}`, `{"data":"`+strings.Repeat("a", MaxMessage)+`"}}`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := ParseRequest([]byte(input)); e == nil {
				t.Fatal("accepted invalid request")
			}
		})
	}
}

func TestPeerRequiresBoundInteractiveIdentityAndAdministrativeMutations(t *testing.T) {
	owner := "S-1-5-21-1-2-3-1001"
	peer := Peer{PID: 42, Session: 1, SID: owner}
	if e := AuthorizePeer(owner, peer, "snapshot"); e != nil {
		t.Fatal(e)
	}
	for _, method := range []string{"consent", "settings", "action", "update-notice-ack"} {
		if AuthorizePeer(owner, peer, method) == nil {
			t.Fatalf("unelevated %s accepted", method)
		}
		admin := peer
		admin.Elevated = true
		if e := AuthorizePeer(owner, admin, method); e != nil {
			t.Fatal(e)
		}
	}
	for name, p := range map[string]Peer{
		"foreign_user":   {PID: 42, Session: 1, SID: "S-1-5-21-4-5-6-1001", Elevated: true},
		"system_session": {PID: 42, Session: 0, SID: owner, Elevated: true},
		"no_session":     {PID: 42, Session: 0xffffffff, SID: owner, Elevated: true},
		"no_pid":         {PID: 0, Session: 1, SID: owner, Elevated: true},
	} {
		t.Run(name, func(t *testing.T) {
			if AuthorizePeer(owner, p, "snapshot") == nil {
				t.Fatal("accepted foreign identity")
			}
		})
	}
	peer.Elevated = true
	if AuthorizePeer(owner, peer, "execute") == nil || AuthorizePeer("", peer, "snapshot") == nil {
		t.Fatal("accepted unknown command or unbound owner")
	}
}

func TestResponseRequiresMatchingRequestAndSingleCompleteMessage(t *testing.T) {
	b, _ := json.Marshal(Response{Version: 1, ID: testID, Payload: json.RawMessage(`{"ready":true}`)})
	good := string(b)
	if _, e := ParseResponse(b, testID); e != nil {
		t.Fatal(e)
	}
	for name, input := range map[string]string{
		"duplicate":     strings.Replace(good, `"version":1`, `"version":1,"version":1`, 1),
		"trailing":      good + `{}`,
		"unknown":       strings.Replace(good, `"version":1`, `"version":1,"pid":42`, 1),
		"missing_id":    `{"version":1}`,
		"mismatched_id": strings.Replace(good, testID, strings.Repeat("1", 32), 1),
		"oversize":      strings.Repeat(" ", MaxMessage) + good,
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := ParseResponse([]byte(input), testID); e == nil {
				t.Fatal("accepted invalid response")
			}
		})
	}
}
