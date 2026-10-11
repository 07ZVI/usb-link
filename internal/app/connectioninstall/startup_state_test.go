package connectioninstall

import (
	"strings"
	"testing"
)

func TestStartupReadbackCannotSynthesizeSuccess(t *testing.T) {
	good := `{"code":"OK","phase":"READBACK","native_error":0,"task_count":1,"enabled":true}`
	if v, e := parseStartupTaskObservation([]byte(good), false); e != nil || !v.Available || !v.Enabled {
		t.Fatal("valid fixed readback rejected")
	}
	if _, e := parseStartupTaskObservation([]byte(strings.Replace(good, `"code":"OK"`, `"code":"STARTUP_PRINCIPAL_CHANGED","code":"OK"`, 1)), false); e == nil {
		t.Fatal("accepted duplicate status fields")
	}
	for _, v := range []string{`{}`, `{"code":"OK","phase":"READBACK","native_error":0,"task_count":1}`, strings.Replace(good, `"native_error":0`, `"native_error":5`, 1), strings.Replace(good, `"task_count":1`, `"task_count":0`, 1), strings.Replace(good, `"task_count":1`, `"task_count":3`, 1), good + `{}`, strings.Replace(good, `"phase":"READBACK"`, `"phase":"S-1-5-21-user"`, 1), strings.Replace(good, `"code":"OK"`, `"code":"raw error containing account"`, 1)} {
		if _, e := parseStartupTaskObservation([]byte(v), false); e == nil {
			t.Fatalf("accepted ambiguous output %s", v)
		}
	}
	if v, e := parseStartupTaskObservation([]byte(good), true); e == nil || v.Available || v.Enabled {
		t.Fatal("failed process admitted OK")
	}
	failed := `{"code":"STARTUP_PRINCIPAL_CHANGED","phase":"QUERY","native_error":2147942405,"task_count":0,"enabled":false}`
	if v, e := parseStartupTaskObservation([]byte(failed), true); e == nil || v.Available || v.Code != "STARTUP_PRINCIPAL_CHANGED" || v.NativeError != 2147942405 {
		t.Fatal("fixed reason lost")
	}
}

func TestStartupFixedInnerFailureSurvivesWrapper(t *testing.T) {
	failure := `{"code":"STARTUP_REGISTER_FAILED","phase":"REGISTER","native_error":2148734208,"task_count":0,"enabled":false,"operation":"CREATE","exception_kind":"METHOD_INVOCATION","inner_exception_kind":"COM","inner_native_error":2147942405,"exception_depth":2,"cim_native_error":0,"cim_status":0}`
	v, e := parseStartupTaskObservation([]byte(failure), true)
	if e == nil || v.Available || v.ExceptionKind != "METHOD_INVOCATION" || v.InnerNativeError != 2147942405 || v.NativeError != 2148734208 || v.Operation != "CREATE" {
		t.Fatalf("wrapped native failure lost: %+v %v", v, e)
	}
	for _, bad := range []string{
		strings.Replace(failure, `"operation":"CREATE"`, `"operation":"C:\\Users\\private"`, 1),
		strings.Replace(failure, `"exception_kind":"METHOD_INVOCATION"`, `"exception_kind":"raw account label"`, 1),
		strings.Replace(failure, `"exception_depth":2`, `"exception_depth":5`, 1),
		strings.Replace(failure, `"exception_depth":2`, `"exception_depth":1`, 1),
		strings.Replace(failure, `"inner_native_error":2147942405,`, "", 1),
		strings.Replace(failure, `"cim_status":0`, `"cim_status":0,"cim_status":5`, 1),
	} {
		if _, err := parseStartupTaskObservation([]byte(bad), true); err == nil {
			t.Fatal("unsafe or partial diagnostic accepted")
		}
	}
	success := `{"code":"OK","phase":"READBACK","native_error":0,"task_count":1,"enabled":true,"operation":"READBACK","exception_kind":"NONE","inner_exception_kind":"NONE","inner_native_error":0,"exception_depth":0,"cim_native_error":0,"cim_status":0}`
	if v, e := parseStartupTaskObservation([]byte(success), false); e != nil || !v.Available || !v.Enabled {
		t.Fatal("fixed diagnostic success rejected")
	}
	for _, bad := range []string{strings.Replace(success, `"exception_kind":"NONE"`, `"exception_kind":"COM"`, 1), strings.Replace(success, `"inner_native_error":0`, `"inner_native_error":5`, 1), strings.Replace(success, `"cim_status":0`, `"cim_status":5`, 1)} {
		if _, err := parseStartupTaskObservation([]byte(bad), false); err == nil {
			t.Fatal("success with native failure accepted")
		}
	}
}
