param(
    [ValidateRange(15, 86400)]
    [int]$IntervalSeconds = 300,
    [string]$DatabasePath = "",
    [string]$PythonPath = ""
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
if ($PythonPath) {
    $python = (Resolve-Path -LiteralPath $PythonPath -ErrorAction Stop).Path
} else {
    $python = (Get-Command python.exe -ErrorAction Stop).Source
}
$previousLocation = Get-Location
try {
    Set-Location -LiteralPath $projectRoot
    & $python -m difftrail --version | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "The selected Python interpreter cannot import Difftrail: $python"
    }
} finally {
    Set-Location -LiteralPath $previousLocation
}
$arguments = "-m difftrail"
if ($DatabasePath) {
    $arguments = "$arguments --db `"$DatabasePath`""
}
$arguments = "$arguments watch --interval $IntervalSeconds"
$taskName = "Difftrail Watcher"
$action = New-ScheduledTaskAction -Execute $python -Argument $arguments -WorkingDirectory $projectRoot
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Days 3650)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description "Difftrail local-first change journal watcher" -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Write-Host "Installed and started $taskName. It will also start at logon."
