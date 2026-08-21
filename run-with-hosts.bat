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

rem -Verb RunAs always starts the elevated process in %windir%\System32,
rem ignoring the caller's current directory -- without -WorkingDirectory,
rem run-with-hosts.ps1 (and vpnproxy.exe's own <region>.conf lookup, which
rem is relative to its process's working directory) would look for files
rem there instead of next to this script. The trailing "." keeps %~dp0's
rem own trailing backslash from swallowing the closing quote once this is
rem threaded through the extra layer of quoting below.
powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -WorkingDirectory \"%~dp0.\" -ArgumentList '-NoExit -NoProfile -ExecutionPolicy Bypass -File \"%~dp0run-with-hosts.ps1\" %*'"
