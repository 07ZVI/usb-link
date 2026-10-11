package macconnection

import (
	"os"
	"testing"
)

// Tests use a source fixture identity; release builds inject the actual bridge hash.
func TestMain(m *testing.M) {
	expectedBridgeSHA = "8e3afb957eb8744556bfa9e63ddcb7cc9c307afe81d88bab75a5b5afba1f811f"
	runtimeName = runtimeDirectoryName(expectedBridgeSHA)
	os.Exit(m.Run())
}
