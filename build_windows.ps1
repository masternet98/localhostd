# Build script for Windows to produce a single-file .exe via PyInstaller
param(
    [string]$Python = "python",
    [string]$Name = "CloudflaredTunnelManager"
)

Write-Host "Verifying PyInstaller availability..." -ForegroundColor Cyan
try {
    & $Python -m PyInstaller --version | Out-Null
} catch {
    Write-Error "PyInstaller not found. Install it with: `n    $Python -m pip install --upgrade pip pyinstaller"
    exit 1
}

$argsList = @(
    "--onefile",
    "--noconsole",
    "--optimize=2",
    "--strip",            # no-op on Windows but harmless
    "--name", $Name,
    "--exclude-module=PIL",
    "--exclude-module=numpy",
    "--exclude-module=matplotlib",
    "tunnel_manager.py"
)

Write-Host "Running PyInstaller..." -ForegroundColor Cyan
& $Python -m PyInstaller @argsList
if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed (exit code $LASTEXITCODE)."
    exit $LASTEXITCODE
}

$exePath = Join-Path -Path (Join-Path -Path (Get-Location) -ChildPath "dist") -ChildPath ("{0}.exe" -f $Name)
if (Test-Path $exePath) {
    Write-Host "Build succeeded:" -ForegroundColor Green
    Write-Host "  $exePath"
} else {
    Write-Warning "Build completed but .exe not found at expected location. Check the 'dist' folder."
}

