param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
)

$action = New-ScheduledTaskAction -Execute "python" -Argument "-m security_audit" -WorkingDirectory $RepoRoot
$trigger = New-ScheduledTaskTrigger -Daily -At 2:00am
Register-ScheduledTask -TaskName "PortfolioSecurityAudit" -Action $action -Trigger $trigger -Description "Daily local security audit. Reports stay in the repository and omit secret values."
Write-Output "Registered PortfolioSecurityAudit at 02:00 local time in $RepoRoot"
