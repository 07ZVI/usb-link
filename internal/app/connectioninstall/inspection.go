package connectioninstall

import "strings"

// InstallationInspection records observations only. It does not prove ownership
// or authorize repair. Unknown values are never represented as absent.
type InstallationInspection struct {
	InspectedAt                 string   `json:"inspectedAt"`
	ChangesMade                 bool     `json:"changesMade"`
	ProgramDirectory            string   `json:"programDirectory"`
	ProgramDirectoryPresent     *bool    `json:"programDirectoryPresent"`
	RegistrationPresent         *bool    `json:"registrationPresent"`
	RegistrationSecurity        string   `json:"registrationSecurity,omitempty"`
	RegisteredVersion           string   `json:"registeredVersion,omitempty"`
	RegisteredExecutable        string   `json:"registeredExecutable,omitempty"`
	RegisteredExecutablePresent *bool    `json:"registeredExecutablePresent"`
	ServiceSecurity             string   `json:"serviceSecurity,omitempty"`
	ServicePresent              *bool    `json:"servicePresent"`
	ServiceState                string   `json:"serviceState,omitempty"`
	ServicePID                  uint32   `json:"servicePID"`
	ServiceExecutable           string   `json:"serviceExecutable,omitempty"`
	ServiceExecutablePresent    *bool    `json:"serviceExecutablePresent"`
	BindingPresent              *bool    `json:"bindingPresent"`
	LegacyBindingPresent        *bool    `json:"legacyBindingPresent"`
	Errors                      []string `json:"errors,omitempty"`
}

func inspectionPresence(v *bool) string {
	if v == nil {
		return "无法确认"
	}
	if *v {
		return "存在"
	}
	return "不存在"
}

func (r InstallationInspection) Summary() string {
	lines := []string{"现有安装检查（只读）", "", "程序目录：" + inspectionPresence(r.ProgramDirectoryPresent), "卸载登记：" + inspectionPresence(r.RegistrationPresent)}
	if r.RegisteredVersion != "" {
		lines = append(lines, "登记版本："+r.RegisteredVersion)
	}
	if r.RegisteredExecutable != "" {
		lines = append(lines, "登记程序："+r.RegisteredExecutable, "登记程序文件："+inspectionPresence(r.RegisteredExecutablePresent))
	}
	lines = append(lines, "核心服务："+inspectionPresence(r.ServicePresent))
	if r.ServiceState != "" {
		lines = append(lines, "服务状态："+r.ServiceState)
	}
	if r.ServiceExecutable != "" {
		lines = append(lines, "服务程序："+r.ServiceExecutable, "服务程序文件："+inspectionPresence(r.ServiceExecutablePresent))
	}
	lines = append(lines, "当前安装凭据："+inspectionPresence(r.BindingPresent), "旧版安装凭据："+inspectionPresence(r.LegacyBindingPresent))
	if (r.RegistrationPresent != nil && *r.RegistrationPresent && r.RegisteredExecutablePresent != nil && !*r.RegisteredExecutablePresent) || (r.ServicePresent != nil && *r.ServicePresent && r.ServiceExecutablePresent != nil && !*r.ServiceExecutablePresent) {
		lines = append(lines, "", "发现程序文件已删除的残留登记。请保存检查报告，核对后再处理。")
	}
	if len(r.Errors) > 0 {
		lines = append(lines, "", "部分项目无法读取：", strings.Join(r.Errors, "\r\n"))
	}
	return strings.Join(lines, "\r\n")
}
