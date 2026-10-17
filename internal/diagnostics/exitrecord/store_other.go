//go:build !windows || !amd64

package exitrecord

func Read(string) (Record, bool, error) { return Record{}, false, nil }
func Write(string, Record) error        { return ErrWrite }
