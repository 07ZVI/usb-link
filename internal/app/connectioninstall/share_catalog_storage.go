package connectioninstall

import "suhang/usbnet/internal/sharing/fileshare"

// Runtime diagnostics/ownership and identity bindings do not change the legacy
// version-1 membership schema. A rollback can still read the selected folders.
type storedShareFolder struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Path      string `json:"path"`
	URL       string `json:"url"`
	SMBURL    string `json:"smb_url"`
	Available bool   `json:"available"`
}

func storedSharedFolders(rows []fileshare.Folder) []storedShareFolder {
	out := make([]storedShareFolder, 0, len(rows))
	for _, f := range rows {
		out = append(out, storedShareFolder{f.ID, f.Name, f.Path, f.URL, f.SMBURL, f.Available})
	}
	return out
}

func publishSharedMembership(stage, publish, prune func() error) error {
	if e := stage(); e != nil {
		return e
	}
	if e := publish(); e != nil {
		return e
	}
	_ = prune()
	return nil
}
