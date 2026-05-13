# ================= CONFIG =================

$hostname = $env:COMPUTERNAME

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptPath) { $scriptPath = Get-Location }

$outputDir = Join-Path $scriptPath "output"

if (!(Test-Path $outputDir)) {
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

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

# ================= MAIL MODULE (MULTI-ENV OPTIMIZED) =================

"==== MAIL USAGE ANALYSIS ====" | Out-File $outputFile -Append -Encoding UTF8
"INFO: Scanning mail-related artifacts..." | Out-File $outputFile -Append -Encoding UTF8

# -------- PST / OST (SAFE PATHS ONLY) --------

"---- Mail Data Files (PST/OST) ----" | Out-File $outputFile -Append -Encoding UTF8

$pstPaths = @(
"$env:LOCALAPPDATA\Microsoft\Outlook",
"$env:APPDATA\Microsoft\Outlook",
"$env:USERPROFILE\Documents"
)

$pstFound = $false

foreach ($path in $pstPaths) {
if (Test-Path $path) {
Get-ChildItem $path -Filter *.pst -ErrorAction SilentlyContinue | ForEach-Object {
$pstFound = $true
$sizeMB = [math]::Round($_.Length / 1MB, 2)

```
        "INFO: PST Found → $($_.FullName) ($sizeMB MB)" | Out-File $outputFile -Append -Encoding UTF8

        if ($sizeMB -gt 500) {
            "RISK: Large PST file (>500MB) - possible data exposure" | Out-File $outputFile -Append -Encoding UTF8
        }
    }

    Get-ChildItem $path -Filter *.ost -ErrorAction SilentlyContinue | ForEach-Object {
        $pstFound = $true
        $sizeMB = [math]::Round($_.Length / 1MB, 2)

        "INFO: OST Found → $($_.FullName) ($sizeMB MB)" | Out-File $outputFile -Append -Encoding UTF8
    }
}
```

}

if (-not $pstFound) {
"INFO: No PST/OST files found (low local email storage)" | Out-File $outputFile -Append -Encoding UTF8
}

# -------- MAIL CLIENTS --------

"---- Mail Clients ----" | Out-File $outputFile -Append -Encoding UTF8

$mailClients = $apps | Where-Object {
$_.Name -match "(?i)outlook|thunderbird|mail|zoho"
}

if ($mailClients) {
foreach ($app in $mailClients) {
"INFO: Mail Client → $($app.Name)" | Out-File $outputFile -Append -Encoding UTF8
}

```
if ($mailClients.Count -gt 1) {
    "RISK: Multiple email clients detected" | Out-File $outputFile -Append -Encoding UTF8
}
```

} else {
"INFO: No mail client detected via installed programs" | Out-File $outputFile -Append -Encoding UTF8
}

# -------- OUTLOOK PROFILE CHECK (FINAL) --------

"---- Outlook Configuration ----" | Out-File $outputFile -Append -Encoding UTF8

$outlookDetected = $false

$profilePaths = @(
"HKCU:\Software\Microsoft\Office\16.0\Outlook\Profiles",
"HKCU:\Software\Microsoft\Office\Outlook\Profiles"
)

foreach ($path in $profilePaths) {
if (Test-Path $path) {
$profiles = Get-ChildItem $path -ErrorAction SilentlyContinue

```
    if ($profiles) {
        $outlookDetected = $true
        foreach ($p in $profiles) {
            "INFO: Outlook Profile → $($p.PSChildName)" | Out-File $outputFile -Append -Encoding UTF8
        }
    }
}
```

}

# fallback (modern Outlook)

if (-not $outlookDetected) {
$identityPath = "HKCU:\Software\Microsoft\Office\16.0\Common\Identity\Identities"

```
if (Test-Path $identityPath) {
    "INFO: Outlook configured (modern identity detected)" | Out-File $outputFile -Append -Encoding UTF8
    $outlookDetected = $true
}
```

}

if (-not $outlookDetected) {
"INFO: Outlook not configured" | Out-File $outputFile -Append -Encoding UTF8
}

# -------- BROWSER MAIL (DEDUPLICATED) --------

"---- Browser Mail Usage ----" | Out-File $outputFile -Append -Encoding UTF8

$mailDomains = @("mail.google.com", "outlook.office.com", "mail.yahoo.com")

$browserPaths = @(
"$env:LOCALAPPDATA\Google\Chrome\User Data\Default",
"$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
)

$detectedDomains = @()

foreach ($dir in $browserPaths) {
if (Test-Path $dir) {
try {
$files = Get-ChildItem $dir -Recurse -Include *.log, *.txt -ErrorAction SilentlyContinue

```
        foreach ($file in $files) {
            $content = Get-Content $file.FullName -ErrorAction SilentlyContinue

            foreach ($domain in $mailDomains) {
                if ($content -match $domain -and $detectedDomains -notcontains $domain) {
                    $detectedDomains += $domain
                    "INFO: Browser Mail Usage → $domain" | Out-File $outputFile -Append -Encoding UTF8
                }
            }
        }
    } catch {}
}
```

}

if ($detectedDomains.Count -gt 0) {
"RISK: Web-based email usage detected (possible personal email access)" | Out-File $outputFile -Append -Encoding UTF8
} else {
"INFO: No browser-based mail usage detected" | Out-File $outputFile -Append -Encoding UTF8
}

# -------- MAIL NETWORK --------

"---- Mail Network Activity ----" | Out-File $outputFile -Append -Encoding UTF8

$mailPorts = @(25,587,110,995,143,993)

$connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
Where-Object { $mailPorts -contains $_.RemotePort }

if ($connections) {
foreach ($c in $connections) {
"INFO: Mail Port Activity → $($c.RemoteAddress):$($c.RemotePort)" |
Out-File $outputFile -Append -Encoding UTF8
}
} else {
"INFO: No active mail connections (system may be idle)" | Out-File $outputFile -Append -Encoding UTF8
}

# -------- SUMMARY --------

"---- Mail Risk Summary ----" | Out-File $outputFile -Append -Encoding UTF8

if ($mailClients.Count -gt 1 -or $detectedDomains.Count -gt 0) {
"RISK: Multiple mail access methods detected (client + web)" | Out-File $outputFile -Append -Encoding UTF8
} else {
"INFO: Single or limited mail usage observed" | Out-File $outputFile -Append -Encoding UTF8
}
# ================= END =================

"==== VULNERABILITY AUDIT END ====" | Out-File $outputFile -Append -Encoding UTF8
