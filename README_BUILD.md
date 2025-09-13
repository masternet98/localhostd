# Build Instructions (Windows, .exe)

This project provides a lightweight Tkinter app to manage Cloudflared tunnels and can be packaged into a single-file Windows executable (.exe) using PyInstaller.

## Prerequisites
- Python 3.8+ installed and on PATH (verify: `python --version`)
- PyInstaller installed: `python -m pip install --upgrade pip pyinstaller`

## Quick Build
- PowerShell: `./build_windows.ps1`
- CMD: `build_windows.bat`

The executable will be at `dist/CloudflaredTunnelManager.exe`.

## CI Build (GitHub Actions)
- Workflow: `.github/workflows/windows-build.yml`
- Triggers: push to `main`, tags starting with `v`, or manual dispatch

How to use:
- Push to `main`: `git push`
- Manual run: GitHub → Actions → `build-windows` → `Run workflow`
- Tag release: `git tag -a v0.1.1 -m "New release" && git push --tags`

Outputs:
- Download the built `.exe` from the workflow run’s Artifacts section: `CloudflaredTunnelManager`

## Manual PyInstaller Command
```
pyinstaller --onefile --noconsole --optimize=2 --strip \
  --exclude-module PIL --exclude-module numpy --exclude-module matplotlib \
  --name CloudflaredTunnelManager \
  tunnel_manager.py
```

Notes:
- `--noconsole` removes the console window for the Tkinter app.
- `--strip` is a no-op on Windows but harmless; keeps flags consistent.
- Excluded modules help minimize size; this app uses only stdlib.

## Run
- After build: `dist/CloudflaredTunnelManager.exe`
- If Cloudflared is not installed, use the app’s “설치” button for automatic download.

## Troubleshooting
- If the app doesn’t start and no window appears, try running without packaging first: `python tunnel_manager.py`.
- Antivirus/SmartScreen may flag new binaries; you may need to allow the app.
- If PyInstaller misses Tk assets, ensure Python’s Tcl/Tk is present (standard Python includes it).

## Git
- Initialize: `git init`
- Ignore build/cache: see `.gitignore` included in this repo
- First commit: `git add . && git commit -m "Init: tunnel manager + build scripts"`
- Add remote: `git remote add origin <your-repo-url>` then `git push -u origin main`
- Tag a release (optional):
  - `git tag -a v0.1.0 -m "First minimal release"`
  - `git push --tags`
