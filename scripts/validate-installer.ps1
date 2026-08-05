param(
    [Parameter(Mandatory = $true)]
    [string]$InstallerPath
)

$ErrorActionPreference = "Stop"
$installer = (Resolve-Path -LiteralPath $InstallerPath -ErrorAction Stop).Path
if ([IO.Path]::GetExtension($installer) -ine ".exe") {
    throw "InstallerPath must point to a Windows executable: $installer"
}

$smokeRoot = Join-Path ([IO.Path]::GetTempPath()) ("Difftrail-installer-smoke-" + [Guid]::NewGuid().ToString("N"))
$installRoot = Join-Path $smokeRoot "install"
New-Item -ItemType Directory -Path $installRoot -Force | Out-Null

function Invoke-Installer {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList
    )

    $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0) {
        throw "Installer process failed with exit code $($process.ExitCode): $FilePath"
    }
}

try {
    Write-Host "Installing into isolated smoke-test directory: $installRoot"
    Invoke-Installer -FilePath $installer -ArgumentList @("/S", "/D=`"$installRoot`"")

    $installedExecutable = Get-ChildItem -LiteralPath $installRoot -Filter "*.exe" -File -Recurse |
        Where-Object { $_.Name -ine "uninstall.exe" } |
        Select-Object -First 1
    if ($null -eq $installedExecutable) {
        throw "Silent installation completed but no application executable was found under $installRoot"
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
    Write-Host "Installer silent install/uninstall smoke test passed."
}
finally {
    if (Test-Path -LiteralPath $smokeRoot) {
        Remove-Item -LiteralPath $smokeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
