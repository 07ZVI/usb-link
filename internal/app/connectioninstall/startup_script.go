package connectioninstall

// Only the two current-user product task names are selected. Query errors are
// never confused with missing tasks, and an account label grants no authority
// until Windows resolves it to the exact current token SID.
const startupTaskScript = `$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);$phase='QUERY';$operation='QUERY';$code='';$native=0;$scheduler=$null;$folder=$null;$registered=$null
function Exact-Sid($value){if([string]::IsNullOrEmpty($value)){throw 'STARTUP_PRINCIPAL_CHANGED'};try{if($value -match '^S-[0-9]-'){return ([System.Security.Principal.SecurityIdentifier]::new($value)).Value};return ([System.Security.Principal.NTAccount]::new($value)).Translate([System.Security.Principal.SecurityIdentifier]).Value}catch{throw 'STARTUP_PRINCIPAL_CHANGED'}}
function Product-Tasks {$all=@(Get-ScheduledTask -ErrorAction Stop);if($all.Count -gt 4096){throw 'STARTUP_QUERY_UNBOUNDED'};$selected=@($all|Where-Object {$_.TaskPath -ceq '\' -and ($_.TaskName -ieq $env:SUHANG_TASK_NAME -or $_.TaskName -ieq $env:SUHANG_LEGACY_TASK_NAME)});foreach($n in @($env:SUHANG_TASK_NAME,$env:SUHANG_LEGACY_TASK_NAME)){if(@($selected|Where-Object {$_.TaskName -ieq $n}).Count -gt 1){throw 'STARTUP_TASK_AMBIGUOUS'}};return $selected}
function Check-Owned($t){
 if($t.TaskName -cnotin @($env:SUHANG_TASK_NAME,$env:SUHANG_LEGACY_TASK_NAME) -or $t.TaskPath -cne '\' -or $t.Description -cne $env:SUHANG_PRODUCT){throw 'STARTUP_TASK_OWNERSHIP_CHANGED'}
 if((Exact-Sid $t.Principal.UserId) -cne $env:SUHANG_SID){throw 'STARTUP_PRINCIPAL_CHANGED'}
 if([string]$t.Principal.LogonType -cne 'Interactive'){throw 'STARTUP_TASK_LOGON_TYPE_CHANGED'}
 if([string]$t.Principal.RunLevel -cne 'Highest'){throw 'STARTUP_TASK_RUN_LEVEL_CHANGED'}
 if(@($t.Actions).Count -ne 1){throw 'STARTUP_TASK_ACTION_CHANGED'}
 $a=$t.Actions[0];$p=[IO.Path]::GetFullPath($a.Execute);$d=[IO.Path]::GetDirectoryName($p)
 if($a.Arguments -cne '--resident' -or -not [string]::IsNullOrEmpty($a.WorkingDirectory) -or -not (([IO.Path]::GetDirectoryName($d) -ieq $env:SUHANG_ROOT -and [IO.Path]::GetFileName($p) -ceq 'USB-Link.exe') -or ([IO.Path]::GetDirectoryName($d) -ieq $env:SUHANG_LEGACY_ROOT -and [IO.Path]::GetFileName($p) -ceq 'Suhang-iPad-USB.exe'))){throw 'STARTUP_TASK_PATH_CHANGED'}
 foreach($q in @([IO.Path]::GetDirectoryName($d),$d,$p,(Join-Path $d 'ownership.json'))){if((Get-Item -LiteralPath $q -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'STARTUP_TASK_REPARSE'}}
 $r=Get-Content -Raw -LiteralPath (Join-Path $d 'ownership.json') -ErrorAction Stop|ConvertFrom-Json
 if($r.product -cne $env:SUHANG_PRODUCT -or $r.version -cne [IO.Path]::GetFileName($d) -or (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -cne $r.sha256){throw 'STARTUP_TASK_RECEIPT_CHANGED'}
 $tr=@($t.Triggers);if($tr.Count -ne 1 -or $tr[0].CimClass.CimClassName -cne 'MSFT_TaskLogonTrigger' -or (Exact-Sid $tr[0].UserId) -cne $env:SUHANG_SID -or $tr[0].Delay -cne 'PT5S'){throw 'STARTUP_TASK_TRIGGER_CHANGED'}
 if([string]$t.State -cnotin @('Disabled','Ready','Running','Queued')){throw 'STARTUP_TASK_STATE_UNKNOWN'}
 return [bool]($t.Settings.Enabled -and $tr[0].Enabled -and [string]$t.State -cne 'Disabled')
}
# Only fixed metadata is exported. A RuntimeException HRESULT can wrap a
# useful COM/CIM code, so retain bounded numeric inner codes without messages.
function Failure-Kind($e){
 if($null -eq $e){return 'NONE'}
 switch -CaseSensitive ($e.GetType().FullName){
  'System.Runtime.InteropServices.COMException' {return 'COM'}
  'Microsoft.Management.Infrastructure.CimException' {return 'CIM'}
  'System.Management.Automation.RuntimeException' {return 'RUNTIME'}
  'System.Management.Automation.MethodInvocationException' {return 'METHOD_INVOCATION'}
  'System.Management.Automation.CmdletInvocationException' {return 'CMDLET_INVOCATION'}
  'System.Management.Automation.ActionPreferenceStopException' {return 'ACTION_PREFERENCE_STOP'}
  'System.Management.Automation.ParameterBindingException' {return 'PARAMETER_BINDING'}
  'System.UnauthorizedAccessException' {return 'ACCESS_DENIED'}
  'System.Xml.XmlException' {return 'XML'}
  default {return 'OTHER'}
 }
}
try{
 $tasks=@(Product-Tasks);$enabled=$false;foreach($t in $tasks){$enabled=(Check-Owned $t) -or $enabled}
 if($env:SUHANG_STARTUP_MODE -eq 'ON'){
  $phase='REGISTER';$operation='CONNECT';$scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect()
  $operation='ROOT_FOLDER';$folder=$scheduler.GetFolder('\')
  # ValidateOnly does not register or change a task. All credentials remain the
  # exact token SID, empty password, InteractiveToken (3), original task XML.
  $operation='VALIDATE_XML';$registered=$folder.RegisterTask($env:SUHANG_TASK_NAME,$env:SUHANG_TASK_XML,1,$env:SUHANG_SID,$null,3,$null)
  if($null -ne $registered){$null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($registered);$registered=$null}
  $operation='PREWRITE';$prewrite=@(Product-Tasks);foreach($t in $prewrite){$null=Check-Owned $t};$current=@($prewrite|Where-Object {$_.TaskName -ceq $env:SUHANG_TASK_NAME})
  # CREATE (2) fails if a task raced into this name. UPDATE (4) is used only
  # after fresh proof of ownership; never CREATE_OR_UPDATE or a Force fallback.
  if($current.Count -eq 0){$operation='CREATE';$flags=2}else{if($current.Count -ne 1){throw 'STARTUP_TASK_AMBIGUOUS'};$operation='UPDATE';$flags=4}
  $registered=$folder.RegisterTask($env:SUHANG_TASK_NAME,$env:SUHANG_TASK_XML,$flags,$env:SUHANG_SID,$null,3,$null)
  if($null -ne $registered){$null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($registered);$registered=$null}
  $phase='READBACK';$operation='READBACK';$verify=@(Product-Tasks);$v=@($verify|Where-Object {$_.TaskName -ceq $env:SUHANG_TASK_NAME});if($v.Count -ne 1 -or -not (Check-Owned $v[0]) -or [IO.Path]::GetFullPath($v[0].Actions[0].Execute) -ine $env:SUHANG_EXE){throw 'STARTUP_READBACK_CHANGED'}
  $phase='REMOVE';$operation='REMOVE';foreach($t in $tasks){if($t.TaskName -cne $env:SUHANG_TASK_NAME){$fresh=@(Product-Tasks|Where-Object {$_.TaskName -ceq $t.TaskName});if($fresh.Count -ne 1){throw 'STARTUP_READBACK_CHANGED'};$null=Check-Owned $fresh[0];$fresh[0]|Unregister-ScheduledTask -Confirm:$false -ErrorAction Stop}}
 }elseif($env:SUHANG_STARTUP_MODE -eq 'OFF'){
  $phase='REMOVE';$operation='REMOVE';foreach($t in $tasks){$fresh=@(Product-Tasks|Where-Object {$_.TaskName -ceq $t.TaskName});if($fresh.Count -ne 1){throw 'STARTUP_READBACK_CHANGED'};$null=Check-Owned $fresh[0];$fresh[0]|Unregister-ScheduledTask -Confirm:$false -ErrorAction Stop}
 }elseif($env:SUHANG_STARTUP_MODE -cne 'QUERY'){throw 'STARTUP_MODE_INVALID'}
 $phase='READBACK';$operation='READBACK';$final=@(Product-Tasks);$enabled=$false;foreach($t in $final){$enabled=(Check-Owned $t) -or $enabled}
 if($env:SUHANG_STARTUP_MODE -eq 'ON' -and ($final.Count -ne 1 -or $final[0].TaskName -cne $env:SUHANG_TASK_NAME -or -not $enabled -or [IO.Path]::GetFullPath($final[0].Actions[0].Execute) -ine $env:SUHANG_EXE)){throw 'STARTUP_READBACK_CHANGED'}
 if($env:SUHANG_STARTUP_MODE -eq 'OFF' -and $final.Count -ne 0){throw 'STARTUP_READBACK_CHANGED'}
 @{code='OK';phase=$phase;native_error=0;task_count=$final.Count;enabled=[bool]$enabled;operation=$operation;exception_kind='NONE';inner_exception_kind='NONE';inner_native_error=0;exception_depth=0;cim_native_error=0;cim_status=0}|ConvertTo-Json -Compress
}catch{
 $allowed=@('STARTUP_PRINCIPAL_CHANGED','STARTUP_QUERY_UNBOUNDED','STARTUP_TASK_AMBIGUOUS','STARTUP_TASK_OWNERSHIP_CHANGED','STARTUP_TASK_LOGON_TYPE_CHANGED','STARTUP_TASK_RUN_LEVEL_CHANGED','STARTUP_TASK_ACTION_CHANGED','STARTUP_TASK_PATH_CHANGED','STARTUP_TASK_REPARSE','STARTUP_TASK_RECEIPT_CHANGED','STARTUP_TASK_TRIGGER_CHANGED','STARTUP_TASK_STATE_UNKNOWN','STARTUP_READBACK_CHANGED','STARTUP_MODE_INVALID')
 $outer=$_.Exception;$code=[string]$outer.Message;if($code -cnotin $allowed){$code='STARTUP_'+$phase+'_FAILED'};$native=[long]$outer.HResult -band 4294967295
 $kind=Failure-Kind $outer;$innerKind='NONE';$inner=0;$depth=0;$cimNative=0;$cimStatus=0;$cursor=$outer
 while($null -ne $cursor -and $depth -lt 4){
  $depth++;$cursorKind=Failure-Kind $cursor
  if($depth -gt 1){$innerKind=$cursorKind;$inner=[long]$cursor.HResult -band 4294967295}
  if($cursorKind -ceq 'CIM'){$cimNative=[long]$cursor.NativeErrorCode -band 4294967295;$cimStatus=[long]$cursor.StatusCode -band 4294967295}
  $cursor=$cursor.InnerException
 }
 @{code=$code;phase=$phase;native_error=$native;task_count=0;enabled=$false;operation=$operation;exception_kind=$kind;inner_exception_kind=$innerKind;inner_native_error=$inner;exception_depth=$depth;cim_native_error=$cimNative;cim_status=$cimStatus}|ConvertTo-Json -Compress;exit 1
}finally{
 foreach($o in @($registered,$folder,$scheduler)){if($null -ne $o -and [Runtime.InteropServices.Marshal]::IsComObject($o)){try{$null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($o)}catch{}}}
}`
