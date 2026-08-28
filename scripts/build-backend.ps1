param(
    [string]$PythonPath = "python"
)

$ErrorActionPreference = "Stop"
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$entryPoint = Join-Path $repositoryRoot "scripts\difftrail_backend.py"
$watcherEntryPoint = Join-Path $repositoryRoot "scripts\difftrail_watcher.py"
$desktopManifest = Join-Path $repositoryRoot "ui\src-tauri\Cargo.toml"
$statusEntryPoint = Join-Path $repositoryRoot "ui\src-tauri\src\bin\difftrail-status.rs"
$outputDirectory = Join-Path $repositoryRoot "ui\src-tauri\resources\backend"
$workDirectory = Join-Path $repositoryRoot "ui\src-tauri\resources\backend-build"
$backendWorkDirectory = Join-Path $workDirectory "backend"
$watcherWorkDirectory = Join-Path $workDirectory "watcher"

if (-not (Test-Path -LiteralPath $entryPoint -PathType Leaf)) {
    throw "Difftrail backend entry point was not found at $entryPoint"
}
if (-not (Test-Path -LiteralPath $watcherEntryPoint -PathType Leaf)) {
    throw "Difftrail watcher entry point was not found at $watcherEntryPoint"
}
if (-not (Test-Path -LiteralPath $statusEntryPoint -PathType Leaf)) {
    throw "Difftrail status-icon entry point was not found at $statusEntryPoint"
}

& $PythonPath -c "import PyInstaller" 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller 6.22.0 is required to build the bundled backend. Install it with: $PythonPath -m pip install pyinstaller==6.22.0"
}

New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
if (Test-Path -LiteralPath $workDirectory) {
    Remove-Item -LiteralPath $workDirectory -Recurse -Force
}

& $PythonPath -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --console `
    --name difftrail-backend `
    --paths $repositoryRoot `
    --collect-submodules difftrail `
    --distpath $outputDirectory `
    --workpath $backendWorkDirectory `
    --specpath $backendWorkDirectory `
    $entryPoint

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed to build the Difftrail backend"
}

$backendBinary = Join-Path $outputDirectory "difftrail-backend.exe"
if (-not (Test-Path -LiteralPath $backendBinary -PathType Leaf)) {
    throw "PyInstaller did not produce the bundled backend at $backendBinary"
}

& $PythonPath -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --name difftrail-watcher `
    --paths $repositoryRoot `
    --collect-submodules difftrail `
    --distpath $outputDirectory `
    --workpath $watcherWorkDirectory `
    --specpath $watcherWorkDirectory `
    $watcherEntryPoint

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed to build the bundled background watcher"
}

$watcherBinary = Join-Path $outputDirectory "difftrail-watcher.exe"
if (-not (Test-Path -LiteralPath $watcherBinary -PathType Leaf)) {
    throw "PyInstaller did not produce the bundled background watcher at $watcherBinary"
}

& cargo build --manifest-path $desktopManifest --release --bin difftrail-status --locked
if ($LASTEXITCODE -ne 0) {
    throw "Cargo failed to build the Difftrail notification-area companion"
}

$statusBuildBinary = Join-Path $repositoryRoot "ui\src-tauri\target\release\difftrail-status.exe"
$statusBinary = Join-Path $outputDirectory "difftrail-status.exe"
if (-not (Test-Path -LiteralPath $statusBuildBinary -PathType Leaf)) {
    throw "Cargo did not produce the Difftrail notification-area companion at $statusBuildBinary"
}
Copy-Item -LiteralPath $statusBuildBinary -Destination $statusBinary -Force

Copy-Item -LiteralPath (Join-Path $PSScriptRoot "install-watcher.ps1") -Destination $outputDirectory -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "uninstall-watcher.ps1") -Destination $outputDirectory -Force
