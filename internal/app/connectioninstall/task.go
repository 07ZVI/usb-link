package connectioninstall

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"
)

const ProductID = "suhang-ipad-usb-7c494949-9688-4bd4-90c6-257e315f9550"
const BinaryName = "USB-Link.exe"
const LegacyBinaryName = "Suhang-iPad-USB.exe"

var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
var sidPattern = regexp.MustCompile(`^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$`)

func escape(s string) string { var b bytes.Buffer; xml.EscapeText(&b, []byte(s)); return b.String() }
func TaskXML(path, sid string) (string, error) {
	if !sidPattern.MatchString(sid) || len(path) > 1024 {
		return "", fmt.Errorf("invalid startup identity")
	}
	// RegisterTask receives an already-decoded Unicode BSTR, not UTF-8
	// bytes. Leave the declaration encoding-neutral, as in the documented
	// Task Scheduler logon XML example; the XML body and policy are unchanged.
	return `<?xml version="1.0"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Description>` + ProductID + `</Description></RegistrationInfo><Triggers><LogonTrigger><Enabled>true</Enabled><UserId>` + sid + `</UserId><Delay>PT5S</Delay></LogonTrigger></Triggers><Principals><Principal id="Owner"><UserId>` + sid + `</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Enabled>true</Enabled></Settings><Actions Context="Owner"><Exec><Command>` + escape(path) + `</Command><Arguments>--resident</Arguments></Exec></Actions></Task>`, nil
}

func validInstallLocation(parent, binary, root, legacy string) bool {
	return (strings.EqualFold(parent, root) && binary == BinaryName) || (strings.EqualFold(parent, legacy) && binary == LegacyBinaryName)
}
