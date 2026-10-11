package bench

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

func TestUploadDownloadIntegrity(t *testing.T) {
	for _, dir := range []string{"UP", "DOWN"} {
		t.Run(dir, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			done := make(chan error, 1)
			go func() { _, err := Handle(server); done <- err }()
			data := append(append([]byte(nil), Pattern()...), Pattern()[:123]...)
			nonce := "0123456789abcdef0123456789abcdef"
			fmt.Fprintf(client, "SUHANG-USB-BENCH/1 %s %d %s\n", dir, len(data), nonce)
			reader := bufio.NewReader(client)
			line, _ := reader.ReadString('\n')
			if line != "READY "+nonce+"\n" {
				t.Fatal(line)
			}
			if dir == "UP" {
				if _, err := client.Write(data); err != nil {
					t.Fatal(err)
				}
			} else {
				got := make([]byte, len(data))
				if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, data) {
					t.Fatal("download mismatch", err)
				}
			}
			var result Result
			if err := json.NewDecoder(reader).Decode(&result); err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(data)
			if result.Bytes != int64(len(data)) || result.SHA256 != hex.EncodeToString(hash[:]) || result.Nonce != nonce {
				t.Fatal(result)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPythonClientInteroperability(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python unavailable")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		for j := 0; j < 2; j++ {
			conn, e := listener.Accept()
			if e != nil {
				done <- e
				return
			}
			if _, e = Handle(conn); e != nil {
				done <- e
				return
			}
		}
		done <- nil
	}()
	client, err := filepath.Abs("../../../mac/benchmark.py")
	if err != nil {
		t.Fatal(err)
	}
	script := `import importlib.util,sys
spec=importlib.util.spec_from_file_location('benchmark',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
for direction in ['UP','DOWN']:
 r=m.measure(direction,32768*2+123,address='127.0.0.1',source='127.0.0.1',port=int(sys.argv[2]))
 assert r['bytes']==32768*2+123 and r['mbps']>0
print('Go/Python benchmark integrity OK')`
	output, err := exec.Command(python, "-c", script, client, strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)).CombinedOutput()
	if err != nil {
		t.Fatalf("Python client: %v %s", err, output)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	t.Log(string(output))
}
func TestRejectOversizeAndCommands(t *testing.T) {
	for _, line := range []string{"SUHANG-USB-BENCH/1 UP 67108865 0123456789abcdef0123456789abcdef\n", "SUHANG-USB-BENCH/1 EXEC 1 0123456789abcdef0123456789abcdef\n", "SUHANG-USB-BENCH/1 UP 1 x\n"} {
		client, server := net.Pipe()
		done := make(chan error, 1)
		go func() { _, err := Handle(server); done <- err }()
		io.WriteString(client, line)
		if err := <-done; err == nil {
			t.Fatal("bad request accepted")
		}
		client.Close()
	}
}
