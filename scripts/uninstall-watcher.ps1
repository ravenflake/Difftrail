$ErrorActionPreference = "Stop"

$task = $null
try {
    $task = Get-ScheduledTask -TaskName "Difftrail Watcher" -ErrorAction Stop
} catch {
    $message = [string]$_.Exception.Message
    $notFound =
        $_.CategoryInfo.Category -eq "ObjectNotFound" -or
        $_.FullyQualifiedErrorId -like "CmdletizationQuery_NotFound*" -or
        $message -match "cannot find|does not exist|not found|0x80070002"
    if (-not $notFound) {
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
