param(
    [string]$PythonPath = "python"
)

$ErrorActionPreference = "Stop"
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$entryPoint = Join-Path $repositoryRoot "scripts\difftrail_backend.py"
$outputDirectory = Join-Path $repositoryRoot "ui\src-tauri\resources\backend"
$workDirectory = Join-Path $repositoryRoot "ui\src-tauri\resources\backend-build"

if (-not (Test-Path -LiteralPath $entryPoint -PathType Leaf)) {
    throw "Difftrail backend entry point was not found at $entryPoint"
}

& $PythonPath -c "import PyInstaller" 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller is required to build the bundled backend. Install it with: $PythonPath -m pip install pyinstaller"
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
    --workpath $workDirectory `
    --specpath $workDirectory `
    $entryPoint

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed to build the Difftrail backend"
}

$backendBinary = Join-Path $outputDirectory "difftrail-backend.exe"
if (-not (Test-Path -LiteralPath $backendBinary -PathType Leaf)) {
    throw "PyInstaller did not produce the bundled backend at $backendBinary"
}
