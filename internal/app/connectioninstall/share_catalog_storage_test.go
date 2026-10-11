package connectioninstall

import (
	"bytes"
	"encoding/json"
	"suhang/usbnet/internal/sharing/fileshare"
	"testing"
)

func TestSharedMembershipRemainsReadableByLegacyStrictDecoder(t *testing.T) {
	f := fileshare.Folder{ID: "123456789012345678901234", Name: "Drive", Path: "selected", Available: true, Identity: "binding", Problem: "runtime diagnostic", ManagedConflict: true}
	data, e := json.Marshal(storedSharedFolders([]fileshare.Folder{f}))
	if e != nil {
		t.Fatal(e)
	}
	type oldFolder struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Path      string `json:"path"`
		URL       string `json:"url"`
		SMBURL    string `json:"smb_url"`
		Available bool   `json:"available"`
	}
	var rows []oldFolder
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e = d.Decode(&rows); e != nil || len(rows) != 1 || rows[0].ID != f.ID || bytes.Contains(data, []byte("binding")) || bytes.Contains(data, []byte("runtime diagnostic")) {
		t.Fatal("legacy rollback cannot read membership", string(data), e)
	}
}
