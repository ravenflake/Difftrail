$ErrorActionPreference = "Stop"

$task = $null
try {
    $task = Get-ScheduledTask -TaskName "Difftrail Watcher" -ErrorAction Stop
} catch {
    $message = [string]$_.Exception.Message
    if ($message -notmatch "cannot find|does not exist|not found|0x80070002") {
        throw
    }
}

if ($task) {
    if ([string]$task.State -eq "Running") {
        Stop-ScheduledTask -TaskName "Difftrail Watcher" -ErrorAction Stop
    }
    Unregister-ScheduledTask -TaskName "Difftrail Watcher" -Confirm:$false -ErrorAction Stop
}

Write-Host "Removed Difftrail Watcher if it was installed."
