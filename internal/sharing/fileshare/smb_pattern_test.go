package fileshare

import "testing"

func TestSMBWindowsFilenameExpressions(t *testing.T) {
	for _, v := range []struct {
		pattern, name string
		match         bool
	}{
		{"Photo [1].jpg", "Photo [1].jpg", true}, {"Photo [1].jpg", "Photo 1.jpg", false},
		{"PHOTO [1].JPG", "Photo [1].jpg", true}, {"*[*].jpg", "Photo [1].jpg", true},
		{"*.*", "README", true}, {"a?c", "abc", true}, {"a?c", "ac", false},
		{"<.txt", "notes.old.txt", true}, {"<.txt", "notes.old.pdf", false},
		{"readme\"", "readme", true}, {"readme\"", "readme.", true},
		{"file>>>.txt", "file.txt", true}, {"file>>>.txt", "fileab.txt", true},
		{"file>>>.txt", "fileabcd.txt", false}, {"中文?.txt", "中文一.txt", true},
	} {
		if got := smbMatchName(v.pattern, v.name); got != v.match {
			t.Errorf("%q / %q: got %v", v.pattern, v.name, got)
		}
	}
}
