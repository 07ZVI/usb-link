package connectioninstall

import (
	"strings"
	"testing"
)

func TestInspectionDoesNotTreatUnreadableAsAbsent(t *testing.T) {
	r := InstallationInspection{Errors: []string{"核心服务：拒绝访问"}}
	s := r.Summary()
	if !strings.Contains(s, "核心服务：无法确认") || strings.Contains(s, "核心服务：不存在") || strings.Contains(s, "发现程序文件已删除") {
		t.Fatal(s)
	}
}
func TestInspectionReportsOrphanedRegistrationAndService(t *testing.T) {
	yes, no := true, false
	for _, r := range []InstallationInspection{
		{RegistrationPresent: &yes, RegisteredExecutablePresent: &no},
		{ServicePresent: &yes, ServiceExecutablePresent: &no},
	} {
		if !strings.Contains(r.Summary(), "发现程序文件已删除的残留登记") {
			t.Fatal(r.Summary())
		}
	}
	r := InstallationInspection{RegistrationPresent: &no, ServicePresent: &no}
	if strings.Contains(r.Summary(), "发现程序文件已删除") {
		t.Fatal(r.Summary())
	}
}
