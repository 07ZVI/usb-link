package connectioninstall

import "fmt"

const coreLogLimit = 1 << 20
const coreLogEventLimit = 16 << 10

func coreLogMessage(b []byte) []byte {
	if len(b) <= coreLogEventLimit {
		return b
	}
	suffix := []byte(" [core log event truncated]\n")
	result := make([]byte, coreLogEventLimit)
	copy(result, b[:coreLogEventLimit-len(suffix)])
	copy(result[coreLogEventLimit-len(suffix):], suffix)
	return result
}
func coreLogRotation(size int64, next int) (bool, error) {
	if size < 0 || size > coreLogLimit || next < 0 || next > coreLogEventLimit {
		return false, fmt.Errorf("CORE_LOG_BOUND_UNPROVEN")
	}
	return size+int64(next) > coreLogLimit, nil
}
