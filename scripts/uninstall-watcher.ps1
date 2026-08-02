$ErrorActionPreference = "Stop"
Unregister-ScheduledTask -TaskName "Difftrail Watcher" -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "Removed Difftrail Watcher if it was installed."
