package ipadncm

import (
	"os"
	"strings"
	"testing"
)

func TestProductMoonlightNoticeUsesServerEndpointNotDhcpSender(t *testing.T) {
	b, e := os.ReadFile("application_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	at := strings.Index(s, "networkOnly.notice =")
	if at < 0 {
		t.Fatal("actual address notice missing")
	}
	line := strings.SplitN(s[at:], "\n", 2)[0]
	if !strings.Contains(line, "plan.ServerIP") || strings.Contains(line, "plan.LocalAddress()") {
		t.Fatal("DHCP-only local /32 exported as Moonlight endpoint", line)
	}
}
