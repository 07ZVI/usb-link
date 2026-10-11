@echo off
setlocal
chcp 65001 >nul
set "KIT_SYS=%SystemRoot%\System32"
if exist "%SystemRoot%\Sysnative\cmd.exe" set "KIT_SYS=%SystemRoot%\Sysnative"
"%KIT_SYS%\fltmc.exe" >nul 2>&1
if not errorlevel 1 goto install
set "KIT_BAT=%~f0"
"%KIT_SYS%\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$p=Start-Process -FilePath $env:KIT_BAT -Verb RunAs -Wait -PassThru; exit $p.ExitCode"
exit /b %ERRORLEVEL%

:install
set "KIT_REBOOT=0"
set "KIT_DOTNET=%ProgramW6432%\dotnet"
if not defined ProgramW6432 set "KIT_DOTNET=%ProgramFiles%\dotnet"
for /f "tokens=2,*" %%A in ('"%KIT_SYS%\reg.exe" query "HKLM\SOFTWARE\dotnet\Setup\InstalledVersions\x64" /v InstallLocation /reg:64 2^>nul') do if "%%A"=="REG_SZ" set "KIT_DOTNET=%%B"

echo [1/2] .NET Runtime
"%KIT_DOTNET%\dotnet.exe" --list-runtimes 2>nul | "%KIT_SYS%\findstr.exe" /r /b /c:"Microsoft\.NETCore\.App 10\.0\.[0-9][0-9]* " >nul
if not errorlevel 1 goto apple
echo 安装 .NET Runtime...
start /wait "" "%~dp0dotnet-runtime-10.0.12-win-x64.exe" /install /passive /norestart
call :result %ERRORLEVEL%
if errorlevel 1 goto failed

:apple
echo [2/2] Apple Mobile Device Support
"%KIT_SYS%\sc.exe" query "Apple Mobile Device Service" >nul 2>&1
if not errorlevel 1 goto cache
echo 请按 Apple 官方安装向导完成安装。
start /wait "" "%~dp0iTunes64Setup.exe" /norestart
call :result %ERRORLEVEL%
if errorlevel 1 goto failed

:cache
rem Wintun / Zadig / CAB are portable packages, not runtime installers.
rem Keep them available for USB Link; do not launch arbitrary device replacement.
set "KIT_CACHE=%ProgramData%\USB-Link Components"
if not exist "%KIT_CACHE%" mkdir "%KIT_CACHE%"
for %%F in (wintun-0.14.1.zip zadig-2.9.exe 01d96dfd-2f6f-46f7-8bc3-fd82088996d2_a31ff7000e504855b3fa124bf27b3fe5bc4d0893.cab) do if not exist "%KIT_CACHE%\%%F" copy /b "%~dp0%%F" "%KIT_CACHE%\%%F" >nul || goto failed
echo.
echo 已完成。已有组件已跳过；可以安装或启动 USB Link。
if "%KIT_REBOOT%"=="1" echo 请先重启 Windows。
if /i not "%~1"=="--no-pause" pause
if "%KIT_REBOOT%"=="1" exit /b 3010
exit /b 0

:result
if "%~1"=="0" exit /b 0
if "%~1"=="3010" set "KIT_REBOOT=1"
if "%~1"=="3010" exit /b 0
if "%~1"=="1641" set "KIT_REBOOT=1"
if "%~1"=="1641" exit /b 0
echo 安装未完成，退出代码：%~1
exit /b 1

:failed
echo 安装未全部完成，请查看上方错误后再次运行。
if /i not "%~1"=="--no-pause" pause
exit /b 1
