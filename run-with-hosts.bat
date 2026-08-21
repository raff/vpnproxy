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

powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoExit -NoProfile -ExecutionPolicy Bypass -File \"%~dp0run-with-hosts.ps1\" %*'"
