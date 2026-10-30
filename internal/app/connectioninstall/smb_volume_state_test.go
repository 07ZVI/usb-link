package connectioninstall

import (
	"fmt"
	"strings"
	"testing"
)

func TestVolumeJournalCapacityAndBounds(t *testing.T) {
	moves := map[string]smbVolumeMove{}
	for i := 0; i < 32; i++ {
		moves[fmt.Sprintf("%024x", i)] = smbVolumeMove{OldPath: `D:\` + strings.Repeat("a", 3900), Path: `\\?\Volume{12345678-1234-1234-1234-123456789abc}\` + strings.Repeat("a", 3900), Identity: "win:12345678:1234567812345678", Published: true}
	}
	data, err := encodeSMBVolumeMoves(moves)
	if err != nil || len(data) <= 32768 || len(data) > 1<<20 {
		t.Fatal("valid long-path recovery journal cannot round trip", len(data), err)
	}
	moves["extra"] = smbVolumeMove{}
	if _, err = encodeSMBVolumeMoves(moves); err == nil {
		t.Fatal("excess entries accepted")
	}
	if _, err = encodeSMBVolumeMoves(map[string]smbVolumeMove{"one": {Path: strings.Repeat("x", 1<<20)}}); err == nil {
		t.Fatal("unreadable journal accepted")
	}
}
