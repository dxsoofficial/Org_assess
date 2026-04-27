# ================= CONFIG =================

$hostname = $env:COMPUTERNAME

# Get script execution directory

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptPath) { $scriptPath = Get-Location }

# Output folder (same location as script)

$outputDir = Join-Path $scriptPath "output"

# Create output folder if not exists

if (!(Test-Path $outputDir)) {
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# Output file

$outputFile = Join-Path $outputDir "$hostname.txt"

# ================= START =================

"==== VULNERABILITY AUDIT START ====" | Out-File $outputFile -Encoding UTF8
"Hostname: $hostname" | Out-File $outputFile -Append -Encoding UTF8
"Date: $(Get-Date)" | Out-File $outputFile -Append -Encoding UTF8

# ================= SYSTEM =================

"==== SYSTEM INFO ====" | Out-File $outputFile -Append -Encoding UTF8
Get-ComputerInfo | Out-File $outputFile -Append -Encoding UTF8

# ================= PATCHES =================

"==== PATCHES ====" | Out-File $outputFile -Append -Encoding UTF8
Get-HotFix | Out-File $outputFile -Append -Encoding UTF8

# ================= USERS =================

"==== USERS ====" | Out-File $outputFile -Append -Encoding UTF8
Get-LocalUser | Out-File $outputFile -Append -Encoding UTF8

"==== ADMINISTRATORS ====" | Out-File $outputFile -Append -Encoding UTF8
Get-LocalGroupMember -Group "Administrators" | Out-File $outputFile -Append -Encoding UTF8

# ================= FIREWALL =================

"==== FIREWALL ====" | Out-File $outputFile -Append -Encoding UTF8
Get-NetFirewallProfile | Out-File $outputFile -Append -Encoding UTF8

# ================= DEFENDER =================

"==== DEFENDER ====" | Out-File $outputFile -Append -Encoding UTF8
Get-MpComputerStatus | Out-File $outputFile -Append -Encoding UTF8

# ================= SOFTWARE (FINAL FIXED) =================

"==== INSTALLED PROGRAMS ====" | Out-File $outputFile -Append -Encoding UTF8

function Get-InstalledPrograms {
param($baseKey)

```
$results = @()

try {
    foreach ($subKeyName in $baseKey.GetSubKeyNames()) {
        try {
            $subKey = $baseKey.OpenSubKey($subKeyName)

            if ($subKey) {
                $name = $subKey.GetValue("DisplayName")

                if ($name -and $name.Trim() -ne "") {
                    $results += [PSCustomObject]@{
                        Name      = $name
                        Version   = $subKey.GetValue("DisplayVersion")
                        Publisher = $subKey.GetValue("Publisher")
                    }
                }
            }
        } catch {}
    }
} catch {}

return $results
```

}

$apps = @()

# HKLM 64-bit

$reg1 = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
[Microsoft.Win32.RegistryHive]::LocalMachine,
[Microsoft.Win32.RegistryView]::Registry64
).OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")

if ($reg1) { $apps += Get-InstalledPrograms $reg1 }

# HKLM 32-bit

$reg2 = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
[Microsoft.Win32.RegistryHive]::LocalMachine,
[Microsoft.Win32.RegistryView]::Registry32
).OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")

if ($reg2) { $apps += Get-InstalledPrograms $reg2 }

# HKCU (user installs)

$reg3 = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
)

if ($reg3) { $apps += Get-InstalledPrograms $reg3 }

# Remove duplicates

$apps = $apps | Sort-Object Name -Unique

# Output

foreach ($app in $apps) {
"$($app.Name) | Version: $($app.Version) | Publisher: $($app.Publisher)" |
Out-File $outputFile -Append -Encoding UTF8
}

# ================= NETWORK =================

"==== NETWORK CONFIG ====" | Out-File $outputFile -Append -Encoding UTF8
Get-NetIPConfiguration | Out-File $outputFile -Append -Encoding UTF8

"==== ACTIVE CONNECTIONS ====" | Out-File $outputFile -Append -Encoding UTF8
Get-NetTCPConnection | Out-File $outputFile -Append -Encoding UTF8

# ================= SERVICES =================

"==== SERVICES ====" | Out-File $outputFile -Append -Encoding UTF8
Get-Service | Out-File $outputFile -Append -Encoding UTF8

# ================= STARTUP =================

"==== STARTUP PROGRAMS ====" | Out-File $outputFile -Append -Encoding UTF8
Get-CimInstance Win32_StartupCommand | Out-File $outputFile -Append -Encoding UTF8

# ================= TASKS =================

"==== SCHEDULED TASKS ====" | Out-File $outputFile -Append -Encoding UTF8
Get-ScheduledTask | Out-File $outputFile -Append -Encoding UTF8

# ================= SHARES =================

"==== SHARED FOLDERS ====" | Out-File $outputFile -Append -Encoding UTF8
Get-SmbShare | Out-File $outputFile -Append -Encoding UTF8

# ================= RDP =================

"==== RDP STATUS ====" | Out-File $outputFile -Append -Encoding UTF8
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server").fDenyTSConnections |
Out-File $outputFile -Append -Encoding UTF8

# ================= AUDIT POLICY =================

"==== AUDIT POLICY ====" | Out-File $outputFile -Append -Encoding UTF8
auditpol /get /category:* | Out-File $outputFile -Append -Encoding UTF8

# ================= END =================

"==== VULNERABILITY AUDIT END ====" | Out-File $outputFile -Append -Encoding UTF8
