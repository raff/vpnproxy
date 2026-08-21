@echo off
rem Double-click launcher for run-with-hosts.ps1: opens a new, elevated
rem (Administrator) PowerShell window and runs the script there. Two
rem things a plain double-click on the .ps1 itself won't get you: raising
rem a real WireGuard interface needs Administrator, and Windows' default
rem PowerShell execution policy blocks unsigned .ps1 scripts from running
rem at all (it would just open in a text editor instead).
setlocal

if "%~1"=="" (
	echo usage: %~nx0 ^<region^> [vpnproxy args...]
	echo   e.g.: %~nx0 FR
	pause
	exit /b 1
)

rem -Verb RunAs always starts the elevated process in %windir%\System32
rem (Start-Process's -WorkingDirectory is unreliable here -- Windows'
rem elevation path often just ignores it), so run-with-hosts.ps1 passes
rem vpnproxy.exe an explicit -config-dir instead of counting on the
rem working directory to land anywhere in particular.
powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoExit -NoProfile -ExecutionPolicy Bypass -File \"%~dp0run-with-hosts.ps1\" %*'"
