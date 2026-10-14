@echo off
rem Starts the VulnPath launcher window. Requires Python 3.9+ (the python.org installer includes tkinter).
cd /d "%~dp0"
where pythonw >nul 2>nul
if %errorlevel%==0 (
  start "" pythonw launcher.py
) else (
  where pyw >nul 2>nul
  if not errorlevel 1 (start "" pyw launcher.py) else (python launcher.py & pause)
)
