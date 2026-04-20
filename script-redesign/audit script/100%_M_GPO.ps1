# ================= CONFIG =================

$hostname = $env:COMPUTERNAME

# ✅ Always-writable local path (works for user + SYSTEM)

$outputDir = "C:\ProgramData\VA_Audit"

if (!(Test-Path $outputDir)) {
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$txtFile = Join-Path $outputDir "$hostname.txt"
$csvFile = Join-Path $outputDir "$hostname-software.csv"

# Optional: central share (comment if not needed)

$centralShare = "\SERVER\AuditLogs"

# ================= START =================

"==== VA AUDIT START ====" | Out-File $txtFile
"Hostname: $hostname" | Out-File $txtFile -Append
"Date: $(Get-Date)" | Out-File $txtFile -Append

# ================= SYSTEM =================

"==== SYSTEM INFO ====" | Out-File $txtFile -Append
Get-CimInstance Win32_OperatingSystem |
Select Caption, Version, OSArchitecture |
Out-File $txtFile -Append

# ================= PATCHES =================

"==== PATCHES ====" | Out-File $txtFile -Append
Get-HotFix | Select HotFixID, InstalledOn | Out-File $txtFile -Append

# ================= USERS =================

"==== LOCAL ADMINS ====" | Out-File $txtFile -Append
Get-LocalGroupMember -Group "Administrators" |
Select Name | Out-File $txtFile -Append

# ================= FIREWALL =================

"==== FIREWALL STATUS ====" | Out-File $txtFile -Append
$fw = Get-NetFirewallProfile
$fw | Select Name, Enabled | Out-File $txtFile -Append

if ($fw.Enabled -contains $false) {
"WARNING: Firewall Disabled" | Out-File $txtFile -Append
}

# ================= DEFENDER =================

"==== DEFENDER STATUS ====" | Out-File $txtFile -Append
$def = Get-MpComputerStatus
$def | Select AntivirusEnabled, RealTimeProtectionEnabled | Out-File $txtFile -Append

if ($def.AntivirusEnabled -eq $false) {
"WARNING: Antivirus Disabled" | Out-File $txtFile -Append
}

# ================= SOFTWARE =================

"==== INSTALLED SOFTWARE ====" | Out-File $txtFile -Append

function Get-InstalledPrograms {
param($regPath)

```
$list = @()

try {
    $baseKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($regPath)
    if ($baseKey) {
        foreach ($sub in $baseKey.GetSubKeyNames()) {
            $subKey = $baseKey.OpenSubKey($sub)
            if ($subKey) {
                $name = $subKey.GetValue("DisplayName")

                if ($name -and $name -notmatch "Update|Hotfix|Visual C\+\+") {
                    $list += [PSCustomObject]@{
                        Name      = $name
                        Version   = $subKey.GetValue("DisplayVersion")
                        Publisher = $subKey.GetValue("Publisher")
                    }
                }
            }
        }
    }
} catch {}

return $list
```

}

$apps = @()
$apps += Get-InstalledPrograms "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
$apps += Get-InstalledPrograms "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

# Save CSV

$apps | Sort-Object Name -Unique | Export-Csv $csvFile -NoTypeInformation

# Save TXT

$apps | Sort-Object Name -Unique |
ForEach-Object {
"$($*.Name) | $($*.Version) | $($_.Publisher)"
} | Out-File $txtFile -Append

# ================= NETWORK =================

"==== LISTENING PORTS ====" | Out-File $txtFile -Append

$ports = Get-NetTCPConnection -State Listen |
Select LocalAddress, LocalPort

$ports | Out-File $txtFile -Append

foreach ($p in $ports) {
if ($p.LocalPort -in 21,22,3389,27017) {
"WARNING: Sensitive port open -> $($p.LocalPort)" | Out-File $txtFile -Append
}
}

# ================= SERVICES =================

"==== CRITICAL SERVICES ====" | Out-File $txtFile -Append

Get-Service |
Where-Object {
$*.Status -eq "Running" -and
$*.DisplayName -match "Mongo|SQL|Remote|SSH|Wazuh"
} |
Select Name, DisplayName |
Out-File $txtFile -Append

# ================= STARTUP =================

"==== STARTUP PROGRAMS ====" | Out-File $txtFile -Append
Get-CimInstance Win32_StartupCommand |
Select Name, Command |
Out-File $txtFile -Append

# ================= END =================

"==== VA AUDIT END ====" | Out-File $txtFile -Append

# ================= OPTIONAL CENTRAL COPY =================

try {
if (Test-Path $centralShare) {
Copy-Item $txtFile -Destination "$centralShare$hostname.txt" -Force
Copy-Item $csvFile -Destination "$centralShare$hostname-software.csv" -Force
}
} catch {}
