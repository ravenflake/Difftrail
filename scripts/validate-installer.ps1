param(
    [Parameter(Mandatory = $true)]
    [string]$InstallerPath
)

$ErrorActionPreference = "Stop"
$installer = (Resolve-Path -LiteralPath $InstallerPath -ErrorAction Stop).Path
if ([IO.Path]::GetExtension($installer) -ine ".exe") {
    throw "InstallerPath must point to a Windows executable: $installer"
}

$smokeRoot = $null
$installRoot = $null
$installerTimeoutMilliseconds = 120000
$processTreeWaitMilliseconds = 5000
$uninstallCleanupTimeoutMilliseconds = 30000
$uninstallRegistryKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Difftrail"
$productRegistryKey = "HKCU:\Software\difftrail\Difftrail"

function Assert-NoExistingDifftrailRegistration {
    if (
        (Test-Path -LiteralPath $uninstallRegistryKey) -or
        (Test-Path -LiteralPath $productRegistryKey)
    ) {
        throw "Installer smoke validation requires a machine without an existing Difftrail registration. Use an isolated runner or VM."
    }
}

function Remove-SmokeInstallerState {
    param(
        [string]$ExpectedInstallRoot
    )

    if ([string]::IsNullOrWhiteSpace($ExpectedInstallRoot)) {
        return
    }

    if (Test-Path -LiteralPath $uninstallRegistryKey) {
        $registeredLocation = [string](
            Get-ItemPropertyValue -LiteralPath $uninstallRegistryKey -Name "InstallLocation" -ErrorAction SilentlyContinue
        )
        if ($registeredLocation.Trim().Trim('"') -ieq $ExpectedInstallRoot) {
            Remove-Item -LiteralPath $uninstallRegistryKey -Recurse -Force -ErrorAction Stop
        }
    }

    if (Test-Path -LiteralPath $productRegistryKey) {
        $registeredLocation = [string](Get-Item -LiteralPath $productRegistryKey).GetValue("")
        if ($registeredLocation.Trim().Trim('"') -ieq $ExpectedInstallRoot) {
            Remove-Item -LiteralPath $productRegistryKey -Recurse -Force -ErrorAction Stop
        }
    }

    $shortcutPath = Join-Path ([Environment]::GetFolderPath("Programs")) "Difftrail.lnk"
    if (Test-Path -LiteralPath $shortcutPath -PathType Leaf) {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $expectedTarget = Join-Path $ExpectedInstallRoot "difftrail-desktop.exe"
        if ($shortcut.TargetPath -ieq $expectedTarget) {
            Remove-Item -LiteralPath $shortcutPath -Force -ErrorAction Stop
        }
    }
}

function Get-DescendantProcessIds {
    param(
        [int]$RootProcessId
    )

    $pending = [Collections.Generic.Queue[int]]::new()
    $seen = [Collections.Generic.HashSet[int]]::new()
    $descendantIds = [Collections.Generic.List[int]]::new()
    $pending.Enqueue($RootProcessId)

    while ($pending.Count -gt 0) {
        $parentId = $pending.Dequeue()
        try {
            $children = @(Get-CimInstance -ClassName Win32_Process -Filter "ParentProcessId = $parentId" -ErrorAction Stop)
        }
        catch {
            return $descendantIds.ToArray()
        }
        foreach ($child in $children) {
            $childId = [int]$child.ProcessId
            if ($seen.Add($childId)) {
                $descendantIds.Add($childId)
                $pending.Enqueue($childId)
            }
        }
    }
    return $descendantIds.ToArray()
}

function Wait-ForProcessIdsToExit {
    param(
        [int[]]$ProcessIds
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($processTreeWaitMilliseconds)
    foreach ($processId in $ProcessIds) {
        while ([DateTime]::UtcNow -lt $deadline) {
            $running = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if ($null -eq $running) {
                break
            }
            Start-Sleep -Milliseconds 100
        }
        if ($null -ne (Get-Process -Id $processId -ErrorAction SilentlyContinue)) {
            throw "Timed out waiting for installer descendant process $processId to exit"
        }
    }
}

function Stop-InstallerProcess {
    param(
        [Diagnostics.Process]$Process
    )

    $descendantIds = @(Get-DescendantProcessIds -RootProcessId $Process.Id)

    if (-not $Process.HasExited) {
        try {
            $killTree = [Diagnostics.Process].GetMethod("Kill", [type[]]@([bool]))
            if ($null -ne $killTree) {
                $Process.Kill($true)
            }
            else {
                $Process.Kill()
            }
        }
        catch {
            # The process may have exited between HasExited and Kill. Preserve any
            # real termination failure, but do not replace the timeout diagnosis
            # with a race-dependent exception.
            if (-not $Process.HasExited) {
                throw
            }
        }
        if (-not $Process.HasExited) {
            $Process.WaitForExit()
        }
    }
    Wait-ForProcessIdsToExit -ProcessIds $descendantIds
}

function Invoke-Installer {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$RawArguments
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    if ($null -ne $RawArguments) {
        $startInfo.Arguments = $RawArguments
    }
    else {
        foreach ($argument in $ArgumentList) {
            [void]$startInfo.ArgumentList.Add($argument)
        }
    }
    $process = $null
    try {
        $process = [Diagnostics.Process]::Start($startInfo)
        if (-not $process.WaitForExit($installerTimeoutMilliseconds)) {
            Stop-InstallerProcess -Process $process
            throw "Installer process timed out after ${installerTimeoutMilliseconds} ms: $FilePath"
        }
        $exitCode = $process.ExitCode
    }
    finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
    if ($exitCode -ne 0) {
        throw "Installer process failed with exit code ${exitCode}: $FilePath"
    }
}

try {
    Assert-NoExistingDifftrailRegistration
    $smokeRoot = Join-Path ([IO.Path]::GetTempPath()) ("Difftrail Installer Smoke " + [Guid]::NewGuid().ToString("N"))
    $installRoot = Join-Path $smokeRoot "install"
    New-Item -ItemType Directory -Path $installRoot -Force | Out-Null

    Write-Host "Installing into isolated smoke-test directory: $installRoot"
    # NSIS requires /D= to be the final, unquoted raw argument. The deliberate
    # space in $smokeRoot exercises this contract on the Windows runner.
    Invoke-Installer -FilePath $installer -RawArguments "/S /D=$installRoot"

    $installedExecutable = Get-ChildItem -LiteralPath $installRoot -Filter "difftrail-desktop.exe" -File -Recurse |
        Select-Object -First 1
    if ($null -eq $installedExecutable) {
        throw "Silent installation completed but difftrail-desktop.exe was not found under $installRoot"
    }

    $uninstaller = Get-ChildItem -LiteralPath $installRoot -Filter "uninstall.exe" -File -Recurse |
        Select-Object -First 1
    if ($null -eq $uninstaller) {
        throw "Silent installation completed but uninstall.exe was not found under $installRoot"
    }

    Write-Host "Uninstalling isolated installation: $($uninstaller.FullName)"
    # NSIS requires _?= to be the final, unquoted raw argument so the
    # uninstaller does not copy itself before running.
    Invoke-Installer -FilePath $uninstaller.FullName -RawArguments "/S _?=$installRoot"
    $uninstallDeadline = [DateTime]::UtcNow.AddMilliseconds($uninstallCleanupTimeoutMilliseconds)
    while ((Test-Path -LiteralPath $installedExecutable.FullName) -and [DateTime]::UtcNow -lt $uninstallDeadline) {
        Start-Sleep -Milliseconds 250
    }
    if (Test-Path -LiteralPath $installedExecutable.FullName) {
        throw "Silent uninstall left the application executable in place: $($installedExecutable.FullName)"
    }
}
catch {
    $failure = $_
}
finally {
    if ($null -ne $installRoot) {
        try {
            Remove-SmokeInstallerState -ExpectedInstallRoot $installRoot
        }
        catch {
            $cleanupMessage = "Installer smoke-test registration cleanup failed: $($_.Exception.Message)"
            if ($null -eq $failure) {
                $failure = $_
            }
            else {
                Write-Warning "$cleanupMessage (preserving the original installer failure)"
            }
        }
    }
    if ($null -ne $smokeRoot -and (Test-Path -LiteralPath $smokeRoot)) {
        try {
            Remove-Item -LiteralPath $smokeRoot -Recurse -Force -ErrorAction Stop
        }
        catch {
            $cleanupMessage = "Installer smoke-test cleanup failed: $($_.Exception.Message)"
            if ($null -eq $failure) {
                $failure = $_
            }
            else {
                Write-Warning "$cleanupMessage (preserving the original installer failure)"
            }
        }
    }
}

if ($null -ne $failure) {
    throw $failure
}
Write-Host "Installer silent install/uninstall smoke test passed."
