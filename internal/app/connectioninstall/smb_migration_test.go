package connectioninstall

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const migrationTestID = "123456780000000000000002"
const migrationTestFileID = "12345678:0123456789abcdef"

func migrationTestOriginal() nativeSMBConfiguration {
	return nativeSMBConfiguration{Version: 1, Shares: []nativeSMBShare{{ID: migrationTestID, Name: "USB-12345678", Path: `D:\Movies`, SID: "S-1-5-18", AccountAccess: "modify", GuestAccess: "none"}}}
}
func TestSMBMigrationEveryFailureWindowKeepsAliasTrackedAndCanResume(t *testing.T) {
	boom := errors.New("injected crash")
	for step := 0; step < 5; step++ {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("step%d_after%v", step, after), func(t *testing.T) {
				durable := migrationTestOriginal()
				oldExists, newExists := true, false
				readback := false
				run := func(fault bool) error {
					if durable.Shares[0].Name == "Movies" && durable.Shares[0].MigrationName == "" {
						return nil
					}
					pending := durable.Shares[0]
					pending.MigrationName = "Movies"
					pending.MigrationFileID = migrationTestFileID
					persist := func(s nativeSMBShare) error {
						next := durable
						next.Shares = []nativeSMBShare{s}
						next.Version = nativeSMBStateVersion(next)
						return persistSMBMigration(next, func(c nativeSMBConfiguration) error {
							data, _ := json.Marshal(c)
							var loaded nativeSMBConfiguration
							e := json.Unmarshal(data, &loaded)
							if e == nil {
								durable = loaded
							}
							return e
						}, func() (nativeSMBConfiguration, error) { return durable, nil })
					}
					action := func(index int, fn func() error) func() error {
						return func() error {
							if fault && index == step && !after {
								return boom
							}
							if e := fn(); e != nil {
								return e
							}
							if fault && index == step && after {
								return boom
							}
							return nil
						}
					}
					return migrateSMBShare(action(0, func() error { return nil }), action(1, func() error { return persist(pending) }), action(2, func() error {
						if durable.Version != 2 || durable.Shares[0].MigrationName != "Movies" {
							t.Fatal("create before durable dual-name intent")
						}
						newExists = true
						readback = true
						return nil
					}), action(3, func() error {
						if !newExists || !readback {
							t.Fatal("old share removed before new readback")
						}
						oldExists = false
						return nil
					}), action(4, func() error {
						done := pending
						done.Name = done.MigrationName
						done.MigrationName = ""
						done.MigrationFileID = ""
						return persist(done)
					}))
				}
				if e := run(true); !errors.Is(e, boom) {
					t.Fatal(e)
				}
				receipt := durable.Shares[0]
				if newExists && receipt.Name != "Movies" && receipt.MigrationName != "Movies" {
					t.Fatal("untracked alias", durable)
				}
				if !oldExists && !newExists {
					t.Fatal("both shares lost")
				}
				if e := run(false); e != nil {
					t.Fatal(e)
				}
				receipt = durable.Shares[0]
				if oldExists || !newExists || durable.Version != 1 || receipt.Name != "Movies" || receipt.MigrationName != "" || receipt.MigrationFileID != "" {
					t.Fatal(durable, oldExists, newExists)
				}
				data, _ := json.Marshal(durable)
				if strings.Contains(string(data), "Migration") {
					t.Fatal("completed fields not omitted", string(data))
				}
			})
		}
	}
}

func TestSMBMigrationRequiresJournalReadbackBeforeNextStep(t *testing.T) {
	expected := migrationTestOriginal()
	expected.Shares[0].MigrationName = "Movies"
	expected.Shares[0].MigrationFileID = migrationTestFileID
	for _, mismatch := range []string{"name", "root", "version", "read_error", "write_error"} {
		t.Run(mismatch, func(t *testing.T) {
			var durable nativeSMBConfiguration
			creates := 0
			e := migrateSMBShare(func() error { return nil }, func() error {
				return persistSMBMigration(expected, func(c nativeSMBConfiguration) error {
					if mismatch == "write_error" {
						return errors.New("disk")
					}
					b, _ := json.Marshal(c)
					return json.Unmarshal(b, &durable)
				}, func() (nativeSMBConfiguration, error) {
					switch mismatch {
					case "name":
						durable.Shares[0].MigrationName = "Other"
					case "root":
						durable.Shares[0].MigrationFileID = "87654321:0123456789abcdef"
					case "version":
						durable.Version = 1
					case "read_error":
						return durable, errors.New("read")
					}
					return durable, nil
				})
			}, func() error { creates++; return nil }, func() error { return nil }, func() error { return nil })
			if e == nil || creates != 0 {
				t.Fatal(e, creates)
			}
		})
	}
}

func TestSMBMigrationCleanupProtectsForeignAndChangedRootAndRetriesPartialRemoval(t *testing.T) {
	names := []string{"Movies", "USB-12345678"}
	for _, failure := range []string{"foreign_new", "foreign_old", "root_changed", "partial_delete", "readback_failed"} {
		t.Run(failure, func(t *testing.T) {
			present := map[string]bool{names[0]: true, names[1]: true}
			deletes := 0
			run := func(fault bool) error {
				return retireSMBMigration(func() error {
					if fault && failure == "root_changed" {
						return errors.New("root changed")
					}
					return nil
				}, names, func(n string) error {
					if fault && (failure == "foreign_new" && n == names[0] || failure == "foreign_old" && n == names[1]) {
						return errors.New("foreign ACL or path")
					}
					return nil
				}, func(n string) error {
					if fault && failure == "partial_delete" && n == names[1] {
						return errors.New("busy")
					}
					delete(present, n)
					deletes++
					if fault && failure == "readback_failed" {
						return errors.New("unconfirmed")
					}
					return nil
				})
			}
			if e := run(true); e == nil {
				t.Fatal("failure not reported")
			}
			if strings.HasPrefix(failure, "foreign") || failure == "root_changed" {
				if deletes != 0 || len(present) != 2 {
					t.Fatal("preflight failed after deletion")
				}
			}
			if e := run(false); e != nil || len(present) != 0 {
				t.Fatal(e, present)
			}
		})
	}
}

func TestSMBMigrationSchemaDefaultsValidationAndVersionFence(t *testing.T) {
	legacy := `{"Version":1,"Shares":[{"ID":"123456780000000000000002","Name":"USB-12345678","Path":"D:\\Movies","SID":"S-1-5-18"}]}`
	var c nativeSMBConfiguration
	if e := json.Unmarshal([]byte(legacy), &c); e != nil {
		t.Fatal(e)
	}
	s := c.Shares[0]
	if !validSMBMigration(s.ID, s.Name, s.Path, s.MigrationName, s.MigrationFileID, false) || nativeSMBStateVersion(c) != 1 {
		t.Fatal(c)
	}
	s.MigrationName = "Movies (2)"
	s.MigrationFileID = migrationTestFileID
	if !validSMBMigration(s.ID, s.Name, s.Path, s.MigrationName, s.MigrationFileID, false) {
		t.Fatal(s)
	}
	c.Shares[0] = s
	if nativeSMBStateVersion(c) != 2 {
		t.Fatal("old binaries must reject pending Version 2")
	}
	for _, change := range []func(*nativeSMBShare){
		func(s *nativeSMBShare) { s.MigrationName = s.Name }, func(s *nativeSMBShare) { s.MigrationName = "Other" },
		func(s *nativeSMBShare) { s.MigrationFileID = "" }, func(s *nativeSMBShare) { s.MigrationFileID = "12345678:0123456789abcdeg" },
		func(s *nativeSMBShare) { s.MigrationFileID = "12345678:01234567:9abcdef" },
		func(s *nativeSMBShare) { s.Name = "Foreign" }, func(s *nativeSMBShare) { s.MigrationName = "" },
	} {
		bad := s
		change(&bad)
		if validSMBMigration(bad.ID, bad.Name, bad.Path, bad.MigrationName, bad.MigrationFileID, false) {
			t.Fatal(bad)
		}
	}
	if validSMBMigration(s.ID, s.Name, s.Path, s.MigrationName, s.MigrationFileID, true) {
		t.Fatal("overlapping ACL transaction accepted")
	}
	done := s
	done.Name = s.MigrationName
	done.MigrationName = ""
	done.MigrationFileID = ""
	c.Shares[0] = done
	c.Version = nativeSMBStateVersion(c)
	if c.Version != 1 {
		t.Fatal(c)
	}
	b, _ := json.Marshal(c)
	var roundtrip nativeSMBConfiguration
	if json.Unmarshal(b, &roundtrip) != nil || !reflect.DeepEqual(c, roundtrip) || strings.Contains(string(b), "Migration") {
		t.Fatal(string(b))
	}
}

func TestSMBRecoveryIgnoresOnlyProvenDifferentFolder(t *testing.T) {
	for _, tc := range []struct {
		path, id  string
		unrelated bool
	}{
		{`E:\Movies`, "12345678:1111111111111111", true},
		{`d:/MOVIES/`, migrationTestFileID, false},
		{`E:\Alias`, migrationTestFileID, false},
		{`D:\Movies`, "12345678:1111111111111111", false},
		{`E:\Movies`, "", false}, {"", "12345678:1111111111111111", false},
	} {
		if got := smbRecoveryShareUnrelated(`D:\Movies`, migrationTestFileID, tc.path, tc.id); got != tc.unrelated {
			t.Fatal(tc, got)
		}
	}
}

func TestSMBMigrationMissingOrChangedACLReceiptPreservesOriginal(t *testing.T) {
	good := smbMigrationACLIdentity{ID: migrationTestID, Path: `D:\Movies`, FileID: migrationTestFileID}
	for _, tc := range []struct {
		name  string
		roots []smbMigrationACLIdentity
		valid bool
	}{
		{"missing", nil, false},
		{"foreign_id", []smbMigrationACLIdentity{{ID: "another", Path: good.Path, FileID: good.FileID}}, false},
		{"changed_path", []smbMigrationACLIdentity{{ID: good.ID, Path: `E:\Movies`, FileID: good.FileID}}, false},
		{"legacy_unbound", []smbMigrationACLIdentity{{ID: good.ID, Path: good.Path}}, false},
		{"changed_file", []smbMigrationACLIdentity{{ID: good.ID, Path: good.Path, FileID: "12345678:1111111111111111"}}, false},
		{"matched", []smbMigrationACLIdentity{good}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutations := 0
			step := func() error { mutations++; return nil }
			e := migrateSMBShare(func() error { _, e := selectSMBMigrationACLRoot(good.ID, good.Path, good.FileID, tc.roots); return e }, step, step, step, step)
			if tc.valid {
				if e != nil || mutations != 4 {
					t.Fatal(e, mutations)
				}
			} else if e == nil || mutations != 0 {
				t.Fatal("changed/unknown baseline mutated", e, mutations)
			}
		})
	}
}
