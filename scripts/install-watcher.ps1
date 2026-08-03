param(
    [ValidateRange(15, 86400)]
    [int]$IntervalSeconds = 300,
    [string]$DatabasePath = "",
    [string]$PythonPath = "",
    [string]$ExecutablePath = "",
    [string]$WorkingDirectory = ""
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

if ($ExecutablePath) {
    $executable = (Resolve-Path -LiteralPath $ExecutablePath -ErrorAction Stop).Path
    if (-not $WorkingDirectory) {
        $WorkingDirectory = Split-Path -Parent $executable
    } else {
        $WorkingDirectory = (Resolve-Path -LiteralPath $WorkingDirectory -ErrorAction Stop).Path
    }
    $arguments = ""
} else {
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

    $pythonDirectory = Split-Path -Parent $python
    $windowlessPython = Join-Path $pythonDirectory "pythonw.exe"
    if (-not (Test-Path -LiteralPath $windowlessPython -PathType Leaf)) {
        throw "A windowless Python interpreter (pythonw.exe) is required to install the Difftrail watcher. Install Python for Windows with pythonw.exe and retry."
    }
    $executable = (Resolve-Path -LiteralPath $windowlessPython).Path
    $WorkingDirectory = $projectRoot
    $arguments = "-m difftrail.watcher"
}

if ($DatabasePath) {
    $arguments = "$arguments --db `"$DatabasePath`"".Trim()
}
$scheduledIntervalSeconds = [Math]::Max(60, $IntervalSeconds)
$taskName = "Difftrail Watcher"
$action = New-ScheduledTaskAction -Execute $executable -Argument $arguments -WorkingDirectory $WorkingDirectory
$startTime = (Get-Date).AddSeconds($scheduledIntervalSeconds)
$periodicTrigger = New-ScheduledTaskTrigger `
    -Once `
    -At $startTime `
    -RepetitionInterval (New-TimeSpan -Seconds $scheduledIntervalSeconds) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$periodicTrigger.Repetition.StopAtDurationEnd = $false
$logonTrigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -Hidden `
    -MultipleInstances IgnoreNew `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($periodicTrigger, $logonTrigger) -Settings $settings -Description "Difftrail local-first background journal scans" -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Write-Host "Installed and started $taskName. It will also scan every $scheduledIntervalSeconds seconds and start at logon."
