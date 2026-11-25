$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$r=[Console]::In.ReadToEnd() | ConvertFrom-Json
$service=Get-CimInstance Win32_Service -Filter "Name='sshd'"
$exe=''
if($service){
    $exe=$service.PathName.Trim('"')
    $allowed=@((Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'),(Join-Path $env:ProgramFiles 'OpenSSH\sshd.exe'))
    if($exe -notin $allowed){throw '現有 sshd 使用自訂位置或啟動參數，請先手動檢查，USB Link 不會修改這套安裝。'}
}
if($r.action -eq 'start'){
    if(!$service){throw '尚未安裝 OpenSSH Server。'}
    & $exe -t 2>&1 | Out-Null
    if($LASTEXITCODE -ne 0){throw 'OpenSSH 設定檢查失敗，服務未啟動。'}
    Start-Service sshd
} elseif($r.action -eq 'stop'){
    if(!$service){throw '尚未安裝 OpenSSH Server。'}
    Stop-Service sshd
} elseif($r.action -eq 'automatic' -or $r.action -eq 'manual'){
    if(!$service){throw '尚未安裝 OpenSSH Server。'}
    $mode=if($r.action -eq 'automatic'){'Automatic'}else{'Manual'}
    Set-Service sshd -StartupType $mode
} elseif($r.action -eq 'install-online'){
    if($service){throw '已存在 SSH 服務，不會混裝另一套 OpenSSH。'}
    $result=Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
    if($result.RestartNeeded){throw 'OpenSSH 安裝需要重新啟動 Windows；重啟後請重新整理。'}
}
$service=Get-CimInstance Win32_Service -Filter "Name='sshd'"
if($r.action -eq 'install-online' -and !$service){throw 'Windows 安裝程序已結束，但未找到 SSH 服務。請檢查 Windows 可選功能。'}
$accounts=@(Get-LocalUser | Where-Object Enabled | Sort-Object Name | ForEach-Object {
    [ordered]@{sid=$_.SID.Value;name=$_.Name}
})
$out=[ordered]@{installed=[bool]$service;state='NotInstalled';start_mode='';accounts=$accounts;sid='';username='';path='';shared=$false}
if($service){$out.state=$service.State;$out.start_mode=$service.StartMode}
if($r.sid){
    $user=Get-LocalUser -SID ([Security.Principal.SecurityIdentifier]$r.sid)
    if(!$user.Enabled){throw '這個 Windows 帳戶已停用。'}
    $out.sid=$user.SID.Value;$out.username=$user.Name
    if($user.Name -match '[,=\r\n]'){throw '此帳戶名稱含不支援的字元，請手動管理公鑰。'}
    if(!$service){throw '請先安裝 OpenSSH Server，再管理公鑰。'}
    $exe=$service.PathName.Trim('"')
    # Resolve using sshd itself so the default administrator Match block is
    # respected. Refuse custom paths instead of writing an ineffective file.
    $config=@(& $exe -T -C ('user='+$user.Name.ToLowerInvariant()+',host=localhost,addr=10.6.9.2,laddr=10.6.9.1,lport=22') 2>&1)
    if($LASTEXITCODE -ne 0){throw '無法讀取 OpenSSH 的有效設定，請先檢查 sshd_config 與主機金鑰。'}
    $entry=@($config | Where-Object {"$_" -match '^authorizedkeysfile '})
    if($entry.Count -ne 1){throw '無法確認 OpenSSH 公鑰檔案位置。'}
    $relative=("$($entry[0])".Substring(19)).Trim().Replace('\','/')
    $shared=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ssh\administrators_authorized_keys'
    if($relative -ieq '__PROGRAMDATA__/ssh/administrators_authorized_keys' -or $relative -ieq $shared.Replace('\','/')){
        $out.path=$shared;$out.shared=$true
    } elseif($relative -eq '.ssh/authorized_keys'){
        $profile=Get-ItemPropertyValue -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'+$user.SID.Value) -Name ProfileImagePath
        $profile=[Environment]::ExpandEnvironmentVariables($profile)
        if(![IO.Path]::IsPathRooted($profile) -or !(Test-Path -LiteralPath $profile -PathType Container)){throw '此帳戶尚無本機使用者資料夾，請先登入 Windows 一次。'}
        $out.path=Join-Path $profile '.ssh\authorized_keys'
    }else{throw '此帳戶使用自訂或多個公鑰檔案，請手動管理，避免寫入錯誤位置。'}
}
$out | ConvertTo-Json -Depth 5 -Compress
