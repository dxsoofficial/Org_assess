<#
DXSO Endpoint Configuration, Software, and Browser Audit Script
Language: PowerShell
Requirement: Admin privileges

Objective: Extract OS version, Installed software, Running processes, 
           AND Internet/Browser Security (Proxy, DNS, Extensions).
#>

$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrEmpty($ScriptPath)) { $ScriptPath = "." }
$TranscriptPath = "$ScriptPath\$env:COMPUTERNAME_audit.txt"

Start-Transcript -Path $TranscriptPath -NoClobber -Force

Write-Output "=== System Information ==="
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture, CSName | Format-List

Write-Output "=== Domain Identity ==="
Get-CimInstance Win32_ComputerSystem | Select-Object Domain, Manufacturer, Model, SystemType | Format-List

Write-Output "=== Current User Login ==="
Write-Output "$env:USERNAME - $env:USERDOMAIN"
Write-Output ""

Write-Output "=== Installed Software (excerpt) ==="
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion | Where-Object {$_.DisplayName -ne $null} | Sort-Object DisplayName | Format-Table -AutoSize

Write-Output "=== Active TCP Connections ==="
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | Format-Table -AutoSize

Write-Output "=== Running Processes (Top 15 by CPU) ==="
Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 Name, Id, CPU, WorkingSet | Format-Table -AutoSize

# ---------------------------------------------------------
# PHASE 5 MERGE: INTERNET & BROWSER SECURITY PROTOCOLS
# ---------------------------------------------------------
Write-Output "@@@ BROWSER_START @@@"

Write-Output "=== System Proxy Configurations ==="
Try {
    Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop | Select-Object ProxyEnable, ProxyServer, AutoConfigURL | Format-List
} Catch {
    Write-Output "No custom user proxy settings forced."
}

Write-Output "=== DNS Client Configurations ==="
Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object {$_.ServerAddresses -ne $null} | Select-Object InterfaceAlias, ServerAddresses | Format-List

Write-Output "=== Detected Browser Extension Directories ==="
$ChromeExt = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
$EdgeExt = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"

if (Test-Path $ChromeExt) {
    Write-Output "`n[Google Chrome Extensions Installed]"
    Get-ChildItem -Path $ChromeExt | Select-Object Name | Format-Table -AutoSize
} else {
    Write-Output "`n[Google Chrome] No default extensions folder found."
}

if (Test-Path $EdgeExt) {
    Write-Output "`n[Microsoft Edge Extensions Installed]"
    Get-ChildItem -Path $EdgeExt | Select-Object Name | Format-Table -AutoSize
} else {
    Write-Output "`n[Microsoft Edge] No default extensions folder found."
}

Write-Output "@@@ BROWSER_END @@@"

Write-Output "[+] Audit for $env:COMPUTERNAME successfully executed."

Stop-Transcript
