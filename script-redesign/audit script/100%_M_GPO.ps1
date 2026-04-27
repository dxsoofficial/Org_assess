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

# ================= FIREWALL =================

"==== FIREWALL ====" | Out-File $outputFile -Append
Get-NetFirewallProfile | Out-File $outputFile -Append

# ================= DEFENDER =================

"==== DEFENDER ====" | Out-File $outputFile -Append
Get-MpComputerStatus | Out-File $outputFile -Append

# ================= SOFTWARE (FIXED) =================

"==== INSTALLED PROGRAMS ====" | Out-File $outputFile -Append

function Get-InstalledPrograms {
param([string]$regPath)

```
$results = @()

try {
    $baseKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($regPath)

    if ($baseKey) {
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
    }
} catch {}

return $results
```

}

$apps = @()
$apps += Get-InstalledPrograms "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
$apps += Get-InstalledPrograms "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

# Remove duplicates

$apps = $apps | Sort-Object Name -Unique

# Output clean format

foreach ($app in $apps) {
"$($app.Name) | Version: $($app.Version) | Publisher: $($app.Publisher)" |
Out-File $outputFile -Append
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
Get-CimInstance Win32_StartupCommand | Out-File $outputFile -Append

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

# ================= AUDIT POLICY =================

"==== AUDIT POLICY ====" | Out-File $outputFile -Append
auditpol /get /category:* | Out-File $outputFile -Append

# ================= END =================

"==== VULNERABILITY AUDIT END ====" | Out-File $outputFile -Append
