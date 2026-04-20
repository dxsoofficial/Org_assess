# ================= CONFIG =================

$hostname  = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

# Change this to network share for GPO later

$outputDir = "$PSScriptRoot\output"

if (!(Test-Path $outputDir)) {
New-Item -ItemType Directory -Path $outputDir | Out-Null
}

$outputFile = "$outputDir$hostname-$timestamp.txt"

# ================= START =================

"==== VULNERABILITY AUDIT START ====" | Out-File $outputFile
"Hostname: $hostname" | Out-File $outputFile -Append
"Date: $(Get-Date)" | Out-File $outputFile -Append

# ================= SYSTEM =================

"==== SYSTEM INFO ====" | Out-File $outputFile -Append
Get-ComputerInfo | Out-File $outputFile -Append

# ================= PATCHES =================

"==== PATCHES ====" | Out-File $outputFile -Append
Get-HotFix | Out-File $outputFile -Append

# ================= USERS =================

"==== USERS ====" | Out-File $outputFile -Append
Get-LocalUser | Out-File $outputFile -Append

"==== ADMINISTRATORS ====" | Out-File $outputFile -Append
Get-LocalGroupMember -Group "Administrators" | Out-File $outputFile -Append

# ================= SECURITY =================

"==== FIREWALL ====" | Out-File $outputFile -Append
Get-NetFirewallProfile | Out-File $outputFile -Append

"==== DEFENDER ====" | Out-File $outputFile -Append
Get-MpComputerStatus | Out-File $outputFile -Append

# ================= SOFTWARE (REGISTRY - FINAL WORKING) =================

"==== INSTALLED PROGRAMS ====" | Out-File $outputFile -Append

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
                if ($name) {
                    $version = $subKey.GetValue("DisplayVersion")
                    $publisher = $subKey.GetValue("Publisher")

                    $list += "$name | Version: $version | Publisher: $publisher"
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

if ($apps.Count -eq 0) {
"No applications found" | Out-File $outputFile -Append
} else {
$apps | Sort-Object -Unique | Out-File $outputFile -Append
}

# ================= NETWORK =================

"==== NETWORK CONFIG ====" | Out-File $outputFile -Append
Get-NetIPConfiguration | Out-File $outputFile -Append

"==== ACTIVE CONNECTIONS ====" | Out-File $outputFile -Append
Get-NetTCPConnection | Out-File $outputFile -Append

# ================= SERVICES =================

"==== SERVICES ====" | Out-File $outputFile -Append
Get-Service | Out-File $outputFile -Append

# ================= STARTUP =================

"==== STARTUP PROGRAMS ====" | Out-File $outputFile -Append
Get-CimInstance Win32_StartupCommand |
Select Name, Command, Location |
Out-File $outputFile -Append

# ================= TASKS =================

"==== SCHEDULED TASKS ====" | Out-File $outputFile -Append
Get-ScheduledTask | Out-File $outputFile -Append

# ================= SHARES =================

"==== SHARED FOLDERS ====" | Out-File $outputFile -Append
Get-SmbShare | Out-File $outputFile -Append

# ================= RDP =================

"==== RDP STATUS ====" | Out-File $outputFile -Append
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server").fDenyTSConnections |
Out-File $outputFile -Append

# ================= AUDIT =================

"==== AUDIT POLICY ====" | Out-File $outputFile -Append
auditpol /get /category:* | Out-File $outputFile -Append

# ================= END =================

"==== VULNERABILITY AUDIT END ====" | Out-File $outputFile -Append
