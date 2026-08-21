<#
.SYNOPSIS
Wraps vpnproxy.exe so the caller doesn't have to manage the Windows hosts
file by hand: adds the masqueraded hostname below, runs vpnproxy.exe, and
always removes the entry again on exit (normal exit, error, or Ctrl+C).

.EXAMPLE
# From an elevated (Administrator) PowerShell prompt:
.\run-with-hosts.ps1 FR
.\run-with-hosts.ps1 FR 203.0.113.10
#>
param(
	[string]$Region,
	[Parameter(ValueFromRemainingArguments = $true)]
	[string[]]$VpnproxyArgs
)

$ScriptName = Split-Path -Leaf $PSCommandPath
$ScriptDir = Split-Path -Parent $PSCommandPath

# Hardcoded on purpose: edit this to point at whatever service you're
# masquerading, so the caller never has to touch the hosts file themselves.
$HostsEntryHost = "adobeid-na1-stg1.services.adobe.com"
$HostsEntryIP = "127.0.0.1"

# Marks lines this script added, so cleanup only ever removes exactly
# those - never a pre-existing entry a human put there some other way.
$HostsMarker = "# vpnproxy-managed-entry"

$HostsPath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"

if (-not $Region) {
	Write-Error "usage: $ScriptName <region> [vpnproxy args...]  (run from an elevated prompt)"
	exit 1
}

$VpnproxyBin = Join-Path $ScriptDir "vpnproxy.exe"
if (-not (Test-Path -LiteralPath $VpnproxyBin -PathType Leaf)) {
	$found = Get-Command "vpnproxy.exe" -ErrorAction SilentlyContinue
	if ($found) {
		$VpnproxyBin = $found.Source
	}
	else {
		Write-Error "$ScriptName`: vpnproxy.exe not found next to this script or on PATH (build it with 'go build .' first)"
		exit 1
	}
}

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Write-Error "$ScriptName`: must run elevated (vpnproxy.exe needs it too); right-click PowerShell and choose 'Run as Administrator'"
	exit 1
}

function Remove-HostsEntry {
	$lines = @(Get-Content -LiteralPath $HostsPath)
	if (-not ($lines -match [regex]::Escape($HostsMarker))) {
		return
	}
	$kept = $lines | Where-Object { $_ -notmatch [regex]::Escape($HostsMarker) }
	[System.IO.File]::WriteAllLines($HostsPath, $kept, [System.Text.Encoding]::ASCII)
	Write-Host "$ScriptName`: removed $HostsEntryHost from the hosts file"
}

function Add-HostsEntry {
	$content = [System.IO.File]::ReadAllText($HostsPath)
	if ($content -match [regex]::Escape($HostsMarker)) {
		Write-Warning "$ScriptName`: a stale entry from a previous run is still in the hosts file, removing it first"
		Remove-HostsEntry
		$content = [System.IO.File]::ReadAllText($HostsPath)
	}
	if ($content -match "(?im)(?:^|\s)$([regex]::Escape($HostsEntryHost))(?:\s|$)") {
		Write-Warning "$ScriptName`: the hosts file already has an unrelated entry for $HostsEntryHost - the one this script adds may not take effect if it resolves first"
	}

	# Guards against appending onto the same line as the file's last entry
	# if it happens to be missing a trailing newline - but only when
	# that's actually true, so this never leaves behind a blank line of
	# its own (which Remove-HostsEntry has no way to know is ours to clean
	# up).
	$prefix = ""
	if ($content.Length -gt 0 -and -not $content.EndsWith("`n")) {
		$prefix = "`r`n"
	}
	$entry = "$prefix$HostsEntryIP`t$HostsEntryHost`t$HostsMarker`r`n"
	[System.IO.File]::AppendAllText($HostsPath, $entry, [System.Text.Encoding]::ASCII)
	Write-Host "$ScriptName`: added $HostsEntryHost -> $HostsEntryIP to the hosts file"
}

# try/finally alone isn't reliably run on Ctrl+C by every PowerShell
# host/version, unlike bash's EXIT/INT/TERM trap - this CancelKeyPress
# handler is the belt-and-braces equivalent, guarded so cleanup only ever
# runs once regardless of which path triggers it.
$cleanedUp = $false
function Invoke-CleanupOnce {
	if (-not $script:cleanedUp) {
		$script:cleanedUp = $true
		Remove-HostsEntry
	}
}
[Console]::add_CancelKeyPress({
		param($eventSender, $eventArgs)
		Invoke-CleanupOnce
	})

Add-HostsEntry
try {
	& $VpnproxyBin --listen $HostsEntryIP $Region @VpnproxyArgs
	$rc = $LASTEXITCODE
}
finally {
	Invoke-CleanupOnce
}

exit $rc
