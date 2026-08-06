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

function Invoke-Installer {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    foreach ($argument in $ArgumentList) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    $process = $null
    try {
        $process = [Diagnostics.Process]::Start($startInfo)
        if (-not $process.WaitForExit($installerTimeoutMilliseconds)) {
            $process.Kill()
            $process.WaitForExit()
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
    $smokeRoot = Join-Path ([IO.Path]::GetTempPath()) ("Difftrail-installer-smoke-" + [Guid]::NewGuid().ToString("N"))
    $installRoot = Join-Path $smokeRoot "install"
    New-Item -ItemType Directory -Path $installRoot -Force | Out-Null

    Write-Host "Installing into isolated smoke-test directory: $installRoot"
    # NSIS requires /D= to be the final argument and rejects a quoted value.
    Invoke-Installer -FilePath $installer -ArgumentList @("/S", "/D=$installRoot")

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
    Invoke-Installer -FilePath $uninstaller.FullName -ArgumentList @("/S")
    for ($attempt = 0; $attempt -lt 20 -and (Test-Path -LiteralPath $installedExecutable.FullName); $attempt++) {
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
