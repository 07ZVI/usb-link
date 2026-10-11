package connectioninstall

import (
	"fmt"
	"regexp"
)

var measurementNonce = regexp.MustCompile(`^[0-9a-f]{32}$`)

func validMeasurement(kind string, seconds int, nonce string) error {
	if !measurementNonce.MatchString(nonce) {
		return fmt.Errorf("invalid measurement id")
	}
	switch kind {
	case "CSTREAMING", "CIPC":
		if seconds != 900 {
			return fmt.Errorf("fixed desktop experiment duration required")
		}
	case "UPGRADEGUARDON":
		if seconds != 900 {
			return fmt.Errorf("fixed upgrade guard lease required")
		}
	case "UPGRADEGUARDOFF", "UPGRADEGUARDSTATE":
		if seconds != 0 {
			return fmt.Errorf("unexpected duration")
		}
	case "UIBASELINE", "GUARDBASELINE", "ROOTBASELINE":
		if seconds != 120 {
			return fmt.Errorf("fixed baseline duration required")
		}
	case "UIDEFAULT", "GUARDDEFAULT", "ROOTDEFAULT":
		if seconds != 0 {
			return fmt.Errorf("unexpected duration")
		}
	case "PARENTCPU":
		if seconds < 1 || seconds > 30 {
			return fmt.Errorf("CPU duration out of bounds")
		}
	case "PARENTFREEMEMORY", "PARENTHEAP", "PARENTALLOCS", "PARENTSTATE", "PARENTMEMORY", "UDPRESULT":
		if seconds != 0 {
			return fmt.Errorf("unexpected duration")
		}
	case "RESOURCESTART", "RESOURCEDETAIL":
		if seconds < 1 || seconds > 7200 || (kind == "RESOURCEDETAIL" && seconds > 120) {
			return fmt.Errorf("resource duration out of bounds")
		}
	case "CDEFAULT", "IPADWINTUNMODULEOFF", "IPADWINTUNMODULEON", "RESOURCESTATUS", "RESOURCERESULT", "RESOURCEDELETE", "UDPSTOP", "UICLOSE", "UIOPEN", "USBSTARTUPON", "USBHOSTSTARTUPSTATE", "IPADSIMPLIFIEDNATIVE", "IPADTRUSTRECYCLESELFTEST", "IPADUNPAIREDPREFLIGHT", "IPADUNPAIREDPREP", "IPADUNPAIREDSTATE", "IPADUNPAIREDFINISH", "IPADUNPAIREDREPLIED", "IPADAMDSRUNNING", "IPADAMDSSTOPPED", "IPADDIAGNOSTICRESULT", "IPADDIAGNOSTICCANCEL", "IPADDIAGNOSTICHOLD", "IPADSTARTUPSTATE", "IPADNETWORKONLYON", "IPADNETWORKONLYOFF", "IPADNETWORKONLYSTATE", "IPADNETWORKONLYPHASEON", "IPADNETWORKONLYPHASEOFF", "IPADSOFTRECONNECT", "IPADSOFTRECONNECTON", "IPADSOFTRECONNECTOFF", "IPADSOFTRECONNECTCANCEL", "IPADSOFTRECONNECTSTATE", "IPADCANDIDATE3", "IPADCANDIDATE41", "IPADCANDIDATE42", "IPADCANDIDATE43", "IPADCANDIDATE5", "IPADCANDIDATEDEFAULT", "IPADCANDIDATESTATE":
		if seconds != 0 {
			return fmt.Errorf("unexpected duration")
		}
	case "UDPSTART", "BRIDGEUDPSTART", "ICMPSTART":
		if seconds < 1 || seconds > 120 {
			return fmt.Errorf("UDP duration out of bounds")
		}
	default:
		return fmt.Errorf("unknown measurement")
	}
	return nil
}
