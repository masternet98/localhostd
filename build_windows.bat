@echo off
setlocal

set NAME=CloudflaredTunnelManager

where pyinstaller >nul 2>nul
if errorlevel 1 (
  echo PyInstaller not found. Install it with:
  echo     python -m pip install --upgrade pip pyinstaller
  exit /b 1
)

echo Building %NAME%.exe ...
pyinstaller --onefile --noconsole --optimize=2 --strip ^
  --exclude-module PIL --exclude-module numpy --exclude-module matplotlib ^
  --name %NAME% ^
  tunnel_manager.py

if errorlevel 1 (
  echo Build failed.
  exit /b 1
)

echo.
echo Build completed. Check dist\%NAME%.exe
exit /b 0

