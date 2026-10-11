package netconfig

// Explicit completion markers distinguish a completed script from a host that
// failed before executing it. Stop catches provider failures; cleanup scripts
// must not suppress the errors used to establish resource absence.
func diagnosticScript(script string) string {
	return `$ErrorActionPreference='Stop';
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false);
Write-Output 'SUHANG_NETWORK_SCRIPT_BEGIN';
try {
` + script + `
Write-Output 'SUHANG_NETWORK_SCRIPT_OK';
exit 0;
} catch {
Write-Output ('SUHANG_NETWORK_SCRIPT_FAILED: '+$_.Exception.Message);
Write-Output ('ErrorId: '+$_.FullyQualifiedErrorId);
Write-Output ('Position: '+$_.InvocationInfo.PositionMessage);
exit 1;
}`
}
