//go:build windows && amd64 && usblink_local_remote

package connectioninstall

import (
	"errors"
	"strings"
	"suhang/usbnet/internal/platform/windows/wincom"
)

// The task has no trigger. Registration grants only one fixed, receipt-bound
// helper launch in the existing interactive owner session, never a new login policy.
func restartTask(j *localRestartJob, operation string) error {
	return restartTaskObserved(j, operation, nil)
}
func restartTaskObserved(j *localRestartJob, operation string, inspection *LocalRestartTaskInspection) (result error) {
	stage := "apartment"
	defer func() {
		if result != nil {
			result = &restartTaskFailure{diagnostic: restartDiagnostic(operation, stage, result), err: result}
		}
	}()
	return wincom.WithApartment(func() error {
		stage = "activate"
		scheduler, e := wincom.Create("{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}")
		if e != nil {
			return e
		}
		defer scheduler.Close()
		stage = "connect"
		v, e := scheduler.Call("Connect")
		v.Clear()
		if e != nil {
			return e
		}
		stage = "folder"
		folder, e := nativeObject(scheduler, "GetFolder", true, wincom.String(`\`))
		if e != nil {
			return e
		}
		defer folder.Close()
		find := func() (*wincom.Dispatch, error) {
			stage = "enumerate"
			tasks, e := nativeObject(folder, "GetTasks", true, wincom.Int(1))
			if e != nil {
				return nil, e
			}
			defer tasks.Close()
			stage = "count"
			n, e := nativeInt(tasks, "Count")
			if e != nil {
				return nil, e
			}
			if n < 0 || n > 4096 {
				return nil, errors.New("LOCAL_RESTART_TASK_QUERY_FAILED")
			}
			var found *wincom.Dispatch
			for i := int32(1); i <= n; i++ {
				stage = "item"
				task, e := nativeObject(tasks, "Item", false, wincom.Int(i))
				if e != nil {
					if found != nil {
						found.Close()
					}
					return nil, e
				}
				stage = "name"
				name, e := nativeString(task, "Name")
				if e != nil {
					task.Close()
					if found != nil {
						found.Close()
					}
					return nil, e
				}
				if strings.EqualFold(name, restartTaskName(j.ID)) {
					if found != nil {
						found.Close()
						task.Close()
						return nil, errors.New("LOCAL_RESTART_TASK_AMBIGUOUS")
					}
					found = task
				} else {
					task.Close()
				}
			}
			return found, nil
		}
		verify := func(task *wincom.Dispatch) error {
			stage = "query_name"
			name, e := nativeString(task, "Name")
			if e != nil {
				return e
			}
			if name != restartTaskName(j.ID) {
				return errors.New("LOCAL_RESTART_TASK_CHANGED")
			}
			stage = "query_path"
			path, e := nativeString(task, "Path")
			if e != nil {
				return e
			}
			if path != `\`+name {
				return errors.New("LOCAL_RESTART_TASK_CHANGED")
			}
			stage = "query_xml"
			text, e := nativeString(task, "Xml")
			if e != nil {
				return e
			}
			stage = "xml_validate"
			if mask, _, _ := restartResolvedTaskMismatch(text, *j, nativeExactSID); mask != 0 {
				return restartTaskMismatchError(mask)
			}
			stage = "hash"
			if operation == "create" {
				j.TaskSHA = restartTaskHash(text)
			} else if j.TaskSHA == "" || restartTaskHash(text) != j.TaskSHA {
				return errors.New("LOCAL_RESTART_TASK_CHANGED")
			}
			stage = "enabled"
			enabled, e := nativeBool(task, "Enabled")
			if e != nil {
				return e
			}
			if !enabled {
				return errors.New("LOCAL_RESTART_TASK_DISABLED")
			}
			return nil
		}
		task, e := find()
		if e != nil {
			return e
		}
		if operation == "create" {
			if task != nil {
				task.Close()
				return errors.New("LOCAL_RESTART_TASK_EXISTS")
			}
			// CREATE, never CREATE_OR_UPDATE. Foreign same-name tasks are untouched.
			stage = "register"
			v, e = folder.Call("RegisterTask", wincom.String(restartTaskName(j.ID)), wincom.String(restartTaskXML(*j)), wincom.Int(2), wincom.String(j.Binding.OwnerSID), wincom.Null(), wincom.Int(3), wincom.String("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;"+j.Binding.OwnerSID+")"))
			v.Clear()
			if e != nil {
				return e
			}
			task, e = find()
			if e != nil {
				return e
			}
		}
		if task == nil {
			if operation == "inspect" && inspection != nil {
				inspection.ReadComplete = true
				return nil
			}
			if operation == "delete" {
				return nil
			}
			return errors.New("LOCAL_RESTART_TASK_MISSING")
		}
		defer task.Close()
		if operation == "inspect" && inspection != nil {
			inspection.Exists = true
			inspection.ReceiptHashPresent = j.TaskSHA != ""
			stage = "query_name"
			name, err := nativeString(task, "Name")
			if err != nil {
				return err
			}
			inspection.NameMatches = name == restartTaskName(j.ID)
			stage = "query_path"
			path, err := nativeString(task, "Path")
			if err != nil {
				return err
			}
			inspection.PathMatches = path == `\`+restartTaskName(j.ID)
			stage = "query_enabled"
			enabled, err := nativeBool(task, "Enabled")
			if err != nil {
				return err
			}
			inspection.Enabled = enabled
			stage = "query_state"
			state, err := nativeInt(task, "State")
			if err != nil {
				return err
			}
			if state < 0 || state > 4 {
				return errors.New("LOCAL_RESTART_TASK_QUERY_FAILED")
			}
			inspection.State = state
			stage = "query_xml"
			text, err := nativeString(task, "Xml")
			if err != nil {
				return err
			}
			if len(text) > 65536 {
				return errors.New("LOCAL_RESTART_TASK_QUERY_FAILED")
			}
			inspection.TaskMismatch, inspection.PrincipalResolutionChecked, inspection.PrincipalSIDMatches = restartResolvedTaskMismatch(text, *j, nativeExactSID)
			inspection.PrincipalUserForm = restartPrincipalUserForm(text)
			inspection.HashMatches = j.TaskSHA != "" && j.TaskSHA == restartTaskHash(text)
			inspection.ReadComplete = true
			return nil
		}
		if e = verify(task); e != nil {
			return e
		}
		switch operation {
		case "create", "verify":
			return nil
		case "run":
			// TASK_RUN_USE_SESSION_ID, with no substituted command arguments.
			stage = "run"
			v, e = task.Call("RunEx", wincom.Null(), wincom.Int(12), wincom.Int(int32(j.Session)), wincom.String(j.Binding.OwnerSID))
			v.Clear()
			return e
		case "delete":
			stage = "delete"
			v, e = folder.Call("DeleteTask", wincom.String(restartTaskName(j.ID)), wincom.Int(0))
			v.Clear()
			if e != nil {
				return e
			}
			last, e := find()
			if last != nil {
				stage = "absence"
				last.Close()
				return errors.New("LOCAL_RESTART_TASK_DELETE_UNCONFIRMED")
			}
			return e
		}
		return errors.New("LOCAL_RESTART_TASK_OPERATION_INVALID")
	})
}

func inspectLocalRestartTask(j localRestartJob) LocalRestartTaskInspection {
	out := LocalRestartTaskInspection{ReceiptHashPresent: j.TaskSHA != "", PrincipalUserForm: "unreadable"}
	if err := restartTaskObserved(&j, "inspect", &out); err != nil {
		out.Diagnostic = restartDiagnostic("inspect", "apartment", err)
	}
	return out
}
