@echo off
setlocal ENABLEDELAYEDEXPANSION

REM Demo for Windows: map → check → probe → analyze against the local mock API.
REM Usage:
REM   1) In one terminal:  python scripts\mock_api.py
REM   2) In another terminal (project root):  scripts\demo_win.bat

REM Change to repo root (this script sits in scripts\)
cd /d "%~dp0\.."

REM Ensure venv is activated (optional). If not using venv, comment these two lines.
if exist ".venv\Scripts\activate.bat" call ".venv\Scripts\activate.bat"

REM Make sure package is installed (editable mode is fine)
python -m pip install -U pip >NUL
pip install -e . >NUL

set OUT_DIR=out
set RUN_DIR=%OUT_DIR%\run_demo

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"
if exist "%RUN_DIR%" rmdir /s /q "%RUN_DIR%"

echo [1/4] Mapping endpoints from examples\openapi_local.json...
python -m amac.cli map ^
  --openapi examples\openapi_local.json ^
  --scope   examples\scope_local.yml ^
  --out     %OUT_DIR%\local_endpoints.json

if errorlevel 1 (
  echo [!] map failed
  exit /b 1
)

echo.
echo [2/4] Validating configs and endpoints...
python -m amac.cli check ^
  --endpoints %OUT_DIR%\local_endpoints.json ^
  --scope     examples\scope_local.yml ^
  --auth      examples\auth.yml

if errorlevel 1 (
  echo [!] check failed
  exit /b 1
)

echo.
echo [3/4] Probing (no-auth vs first auth)...
echo     Tip: set token in examples\auth.yml to match the mock server (default: "demo")
python -m amac.cli probe ^
  --endpoints %OUT_DIR%\local_endpoints.json ^
  --scope     examples\scope_local.yml ^
  --auth      examples\auth.yml ^
  --out-dir   %RUN_DIR%

if errorlevel 1 (
  echo [!] probe failed
  exit /b 1
)

echo.
echo [4/4] Analyzing probe run...
python -m amac.cli analyze --run-dir %RUN_DIR%

if errorlevel 1 (
  echo [!] analyze failed
  exit /b 1
)

echo.
echo ✅ Done.
echo   Endpoints: %OUT_DIR%\local_endpoints.json
echo   Probe run: %RUN_DIR%
echo   Findings:  %RUN_DIR%\findings.json and %RUN_DIR%\findings.md

endlocal
