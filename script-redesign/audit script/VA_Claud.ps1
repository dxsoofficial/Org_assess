#Requires -Version 3.0
<#
.SYNOPSIS
    Vulnerability Assessment - System Data Collector
.DESCRIPTION
    Production-safe, GPO-ready system information collector for vulnerability assessments.
    Read-only. No system changes. Low-priority execution to avoid impacting workloads.
    Outputs structured JSON + human-readable TXT report per host.
.NOTES
    - Run as Administrator for full data collection
    - Safe for production/operational environments
    - GPO deployment: Computer Config > Windows Settings > Scripts > Startup
    - Manual run: powershell.exe -ExecutionPolicy Bypass -File .\VA_Collect.ps1
    - Output: .\output\<HOSTNAME>_<DATE>.json  and  .\output\<HOSTNAME>_<DATE>.txt
#>

[CmdletBinding()]
param(
    # Override output directory (useful for GPO UNC path e.g. \\server\va_share\)
    [string]$OutputPath = "",

    # Skip sections if not needed (comma-separated section names)
    [string[]]$SkipSections = @(),

    # Force re-run even if today's output already exists
    [switch]$Force
)

# ============================================================
#  PRODUCTION SAFETY — Lower this process priority immediately
# ============================================================
try {
    $process = Get-Process -Id $PID
    $process.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
} catch { <# Non-critical, continue #> }

# ============================================================
#  SETUP — Paths, logging, duplicate-run guard
# ============================================================
$ScriptVersion  = "2.0"
$Hostname       = $env:COMPUTERNAME
$DateStamp      = Get-Date -Format "yyyyMMdd"
$TimeStamp      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Resolve output directory
if ($OutputPath -eq "") {
    $OutputPath = Join-Path $PSScriptRoot "output"
}
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$BaseFile   = Join-Path $OutputPath "${Hostname}_${DateStamp}"
$JsonFile   = "${BaseFile}.json"
$TxtFile    = "${BaseFile}.txt"
$ErrorLog   = "${BaseFile}_errors.log"

# Duplicate-run guard (skip if already ran today, unless -Force)
if ((Test-Path $JsonFile) -and (-not $Force)) {
    Write-Host "[INFO] Output for today already exists: $JsonFile — use -Force to re-run." -ForegroundColor Yellow
    exit 0
}

# Error accumulator
$ErrorAccumulator = [System.Collections.Generic.List[string]]::new()

# Helper: safe data collector — catches errors, logs them, returns $null gracefully
function Invoke-Safe {
    param([string]$Section, [scriptblock]$Block)
    if ($SkipSections -contains $Section) {
        return [PSCustomObject]@{ Skipped = $true }
    }
    try {
        & $Block
    } catch {
        $msg = "[ERROR] Section '$Section': $($_.Exception.Message)"
        $ErrorAccumulator.Add($msg)
        Write-Verbose $msg
        return $null
    }
}

# Helper: registry value reader — returns $null silently if key missing
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
    } catch { return $null }
}

function Get-RegKey {
    param([string]$Path)
    try {
        return Get-ItemProperty -Path $Path -ErrorAction Stop
    } catch { return $null }
}

Write-Host "[*] VA Collector v$ScriptVersion starting on $Hostname at $TimeStamp" -ForegroundColor Cyan

# ============================================================
#  DATA COLLECTION — Each section isolated with Invoke-Safe
# ============================================================
$VA = [ordered]@{}

# ── 1. METADATA ──────────────────────────────────────────────
$VA.Metadata = [ordered]@{
    Hostname        = $Hostname
    CollectedAt     = $TimeStamp
    CollectedBy     = $env:USERNAME
    ScriptVersion   = $ScriptVersion
    IsAdmin         = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    PSVersion       = $PSVersionTable.PSVersion.ToString()
    OSArchitecture  = $env:PROCESSOR_ARCHITECTURE
}

# ── 2. SYSTEM INFO ────────────────────────────────────────────
Write-Host "  [+] System Info" -ForegroundColor Gray
$VA.SystemInfo = Invoke-Safe "SystemInfo" {
    $os   = Get-CimInstance Win32_OperatingSystem  -ErrorAction Stop
    $cs   = Get-CimInstance Win32_ComputerSystem   -ErrorAction Stop
    $bios = Get-CimInstance Win32_BIOS             -ErrorAction Stop
    $cpu  = Get-CimInstance Win32_Processor        -ErrorAction Stop
    $mem  = Get-CimInstance Win32_PhysicalMemory   -ErrorAction Stop

    [ordered]@{
        Hostname            = $cs.Name
        Domain              = $cs.Domain
        DomainRole          = $cs.DomainRole  # 0=standalone,1=member,2=BDC,3=PDC,4=member DC,5=PDC
        PartOfDomain        = $cs.PartOfDomain
        Manufacturer        = $cs.Manufacturer
        Model               = $cs.Model
        SystemType          = $cs.SystemType
        OSCaption           = $os.Caption
        OSVersion           = $os.Version
        OSBuildNumber       = $os.BuildNumber
        OSArchitecture      = $os.OSArchitecture
        ServicePack         = $os.ServicePackMajorVersion
        InstallDate         = $os.InstallDate
        LastBootTime        = $os.LastBootUpTime
        UptimeDays          = ([math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1))
        BIOSManufacturer    = $bios.Manufacturer
        BIOSVersion         = $bios.SMBIOSBIOSVersion
        BIOSReleaseDate     = $bios.ReleaseDate
        BIOSSerialNumber    = $bios.SerialNumber
        CPUName             = ($cpu | Select-Object -First 1).Name
        CPUCores            = ($cpu | Select-Object -First 1).NumberOfCores
        CPULogicalProcs     = ($cpu | Select-Object -First 1).NumberOfLogicalProcessors
        TotalRAM_GB         = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        RAMModules          = @($mem | ForEach-Object { [ordered]@{
            Bank     = $_.BankLabel
            Capacity = "$([math]::Round($_.Capacity/1GB,1)) GB"
            Speed    = "$($_.Speed) MHz"
        }})
    }
}

# ── 3. DISK INFO ──────────────────────────────────────────────
Write-Host "  [+] Disk Info" -ForegroundColor Gray
$VA.Disks = Invoke-Safe "Disks" {
    $logical  = Get-CimInstance Win32_LogicalDisk -ErrorAction Stop
    $physical = Get-CimInstance Win32_DiskDrive   -ErrorAction Stop
    [ordered]@{
        LogicalDisks = @($logical | ForEach-Object { [ordered]@{
            Drive       = $_.DeviceID
            FileSystem  = $_.FileSystem
            VolumeName  = $_.VolumeName
            Size_GB     = if ($_.Size) { [math]::Round($_.Size / 1GB, 2) } else { $null }
            FreeSpace_GB= if ($_.FreeSpace) { [math]::Round($_.FreeSpace / 1GB, 2) } else { $null }
            FreePercent = if ($_.Size -and $_.Size -gt 0) { [math]::Round(($_.FreeSpace / $_.Size) * 100, 1) } else { $null }
            DriveType   = $_.DriveType
        }})
        PhysicalDisks = @($physical | ForEach-Object { [ordered]@{
            Model         = $_.Model
            InterfaceType = $_.InterfaceType
            Size_GB       = [math]::Round($_.Size / 1GB, 2)
            SerialNumber  = $_.SerialNumber
        }})
    }
}

# ── 4. USER ACCOUNTS ──────────────────────────────────────────
Write-Host "  [+] User Accounts" -ForegroundColor Gray
$VA.UserAccounts = Invoke-Safe "UserAccounts" {
    $users    = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop
    $admGroup = (net localgroup administrators 2>$null) -match "^[^-\s\\]" | Where-Object { $_ -notmatch "command completed" -and $_ -ne "" }

    [ordered]@{
        LocalUsers = @($users | ForEach-Object { [ordered]@{
            Name        = $_.Name
            FullName    = $_.FullName
            Disabled    = $_.Disabled
            Lockout     = $_.Lockout
            PasswordRequired        = $_.PasswordRequired
            PasswordChangeable      = $_.PasswordChangeable
            PasswordExpires         = $_.PasswordExpires
            Description = $_.Description
            SID         = $_.SID
        }})
        LocalAdministrators = $admGroup
        AllGroups = @((net localgroup 2>$null) -match "^\*" | ForEach-Object { $_.TrimStart("*") })
        CurrentUserPrivileges = (whoami /priv 2>$null) -join "`n"
        LoggedOnUsers = @(try {
            query user 2>$null | Select-Object -Skip 1 | ForEach-Object {
                if ($_ -match "^\s*(\S+)\s+(\S+)\s+(\d+)\s+(\S+)") {
                    [ordered]@{ Username = $Matches[1]; SessionName = $Matches[2]; ID = $Matches[3]; State = $Matches[4] }
                }
            }
        } catch { $null })
    }
}

# ── 5. PASSWORD POLICY ────────────────────────────────────────
Write-Host "  [+] Password Policy" -ForegroundColor Gray
$VA.PasswordPolicy = Invoke-Safe "PasswordPolicy" {
    $netAccounts = net accounts 2>$null
    $policy = [ordered]@{}
    foreach ($line in $netAccounts) {
        if ($line -match "^(.+?):\s+(.+)$") {
            $policy[$Matches[1].Trim()] = $Matches[2].Trim()
        }
    }
    $policy
}

# ── 6. NETWORK CONFIG ─────────────────────────────────────────
Write-Host "  [+] Network Config" -ForegroundColor Gray
$VA.NetworkConfig = Invoke-Safe "NetworkConfig" {
    $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop
    [ordered]@{
        Adapters = @($adapters | ForEach-Object { [ordered]@{
            Description     = $_.Description
            MACAddress      = $_.MACAddress
            IPAddresses     = $_.IPAddress
            SubnetMask      = $_.IPSubnet
            DefaultGateway  = $_.DefaultIPGateway
            DNSServers      = $_.DNSServerSearchOrder
            DHCPEnabled     = $_.DHCPEnabled
            DHCPServer      = $_.DHCPServer
            DHCPLeaseExpiry = $_.DHCPLeaseExpires
            WINSPrimary     = $_.WINSPrimaryServer
        }})
        DNSCache    = @(try { Get-DnsClientCache -ErrorAction Stop | Select-Object Entry, RecordType, Data } catch { $null })
        ARPTable    = (arp -a 2>$null) -join "`n"
        RoutingTable= (route print 2>$null) -join "`n"
        HostsFile   = (Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue) -join "`n"
        ProxyEnabled= Get-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyEnable"
        ProxyServer = Get-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyServer"
    }
}

# ── 7. OPEN PORTS & CONNECTIONS ───────────────────────────────
Write-Host "  [+] Open Ports & Connections" -ForegroundColor Gray
$VA.NetworkConnections = Invoke-Safe "NetworkConnections" {
    $connections = @()
    try {
        $netstat = netstat -ano 2>$null
        foreach ($line in $netstat) {
            if ($line -match "^\s+(TCP|UDP)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)") {
                $connections += [ordered]@{
                    Protocol    = $Matches[1]
                    LocalAddr   = $Matches[2]
                    ForeignAddr = $Matches[3]
                    State       = $Matches[4]
                    PID         = $Matches[5]
                }
            }
        }
    } catch {}

    $listeningPorts = $connections | Where-Object { $_.State -eq "LISTENING" }

    [ordered]@{
        AllConnections  = $connections
        ListeningPorts  = $listeningPorts
        TotalListening  = ($listeningPorts | Measure-Object).Count
    }
}

# ── 8. FIREWALL ───────────────────────────────────────────────
Write-Host "  [+] Firewall" -ForegroundColor Gray
$VA.Firewall = Invoke-Safe "Firewall" {
    $profiles = try { Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogFileName } catch { $null }
    $rules    = try { Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.Enabled -eq "True" } | Select-Object DisplayName, Direction, Action, Profile, Protocol -First 200 } catch { $null }

    [ordered]@{
        Profiles      = $profiles
        EnabledRules  = $rules
        RawStatus     = (netsh advfirewall show allprofiles 2>$null) -join "`n"
    }
}

# ── 9. NETWORK SHARES ─────────────────────────────────────────
Write-Host "  [+] Shares & SMB" -ForegroundColor Gray
$VA.Shares = Invoke-Safe "Shares" {
    $shares = Get-CimInstance Win32_Share -ErrorAction Stop
    $smbv1  = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1"
    $smbv1svc = try { (Get-Service mrxsmb10 -ErrorAction Stop).Status } catch { "Not Found" }

    [ordered]@{
        Shares = @($shares | ForEach-Object { [ordered]@{
            Name        = $_.Name
            Path        = $_.Path
            Type        = $_.Type
            Description = $_.Description
        }})
        SMBv1_RegistryValue  = $smbv1
        SMBv1_ServiceStatus  = $smbv1svc
        SMBv1_Risk           = if ($smbv1 -ne 0 -and $smbv1svc -ne "Stopped" -and $smbv1svc -ne "Not Found") { "HIGH - EternalBlue risk" } else { "Low" }
        MappedDrives = (net use 2>$null) -join "`n"
    }
}

# ── 10. PATCH STATUS ──────────────────────────────────────────
Write-Host "  [+] Patch Status" -ForegroundColor Gray
$VA.PatchStatus = Invoke-Safe "PatchStatus" {
    $hotfixes = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending
    $wuPolicy = Get-RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $auPolicy = Get-RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $wuSvc    = try { (Get-Service wuauserv -ErrorAction Stop).Status } catch { "Unknown" }

    [ordered]@{
        TotalHotfixes       = $hotfixes.Count
        MostRecentPatch     = ($hotfixes | Select-Object -First 1).InstalledOn
        MostRecentPatchKB   = ($hotfixes | Select-Object -First 1).HotFixID
        AllHotfixes         = @($hotfixes | Select-Object HotFixID, Description, InstalledOn, InstalledBy)
        WUServiceStatus     = $wuSvc
        WUPolicy            = $wuPolicy
        AUPolicy            = $auPolicy
        DaysSinceLastPatch  = if ($hotfixes.Count -gt 0 -and ($hotfixes | Select-Object -First 1).InstalledOn) {
                                [math]::Round(((Get-Date) - ($hotfixes | Select-Object -First 1).InstalledOn).TotalDays, 0)
                              } else { $null }
    }
}

# ── 11. INSTALLED SOFTWARE ────────────────────────────────────
Write-Host "  [+] Installed Software" -ForegroundColor Gray
$VA.InstalledSoftware = Invoke-Safe "InstalledSoftware" {
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $software = foreach ($path in $regPaths) {
        try {
            Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -ne $null } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate,
                          @{N="InstallLocation"; E={$_.InstallLocation}},
                          @{N="Source"; E={ if ($path -like "*WOW6432*") {"32-bit"} elseif ($path -like "*HKCU*") {"User"} else {"64-bit"} }}
        } catch {}
    }
    @($software | Sort-Object DisplayName)
}

# ── 12. SERVICES ──────────────────────────────────────────────
Write-Host "  [+] Services" -ForegroundColor Gray
$VA.Services = Invoke-Safe "Services" {
    $services = Get-CimInstance Win32_Service -ErrorAction Stop

    # Flag unquoted service paths (privilege escalation vector)
    $unquoted = $services | Where-Object {
        $_.PathName -and
        $_.PathName -notmatch '^"' -and
        $_.PathName -match ' ' -and
        $_.PathName -notmatch '^[A-Z]:\\Windows\\'
    }

    [ordered]@{
        All = @($services | ForEach-Object { [ordered]@{
            Name        = $_.Name
            DisplayName = $_.DisplayName
            State       = $_.State
            StartMode   = $_.StartMode
            PathName    = $_.PathName
            StartName   = $_.StartName
        }})
        UnquotedServicePaths = @($unquoted | Select-Object Name, PathName, StartMode, State)
        UnquotedCount        = ($unquoted | Measure-Object).Count
    }
}

# ── 13. STARTUP & PERSISTENCE ─────────────────────────────────
Write-Host "  [+] Startup & Persistence" -ForegroundColor Gray
$VA.Startup = Invoke-Safe "Startup" {
    $regRunKeys = @(
        @{Hive="HKLM"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"},
        @{Hive="HKLM"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"},
        @{Hive="HKCU"; Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"},
        @{Hive="HKCU"; Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"},
        @{Hive="HKLM"; Path="HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"}
    )

    $runEntries = foreach ($key in $regRunKeys) {
        $props = Get-RegKey $key.Path
        if ($props) {
            $props.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                [ordered]@{ Hive = $key.Hive; Key = $key.Path; Name = $_.Name; Value = $_.Value }
            }
        }
    }

    $tasks = try {
        schtasks /query /fo CSV /v 2>$null | ConvertFrom-Csv |
        Where-Object { $_."Status" -ne "Disabled" } |
        Select-Object "TaskName", "Status", "Run As User", "Task To Run", "Next Run Time", "Last Run Time", "Last Result"
    } catch { $null }

    $wmiStartup = try {
        Get-CimInstance Win32_StartupCommand -ErrorAction Stop |
        Select-Object Name, Command, Location, User
    } catch { $null }

    [ordered]@{
        RegistryRunKeys = @($runEntries)
        ScheduledTasks  = @($tasks)
        WMIStartup      = @($wmiStartup)
    }
}

# ── 14. SECURITY CONFIGURATION ────────────────────────────────
Write-Host "  [+] Security Config" -ForegroundColor Gray
$VA.SecurityConfig = Invoke-Safe "SecurityConfig" {

    # UAC
    $uacKey   = Get-RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $uacEnabled = if ($uacKey) { $uacKey.EnableLUA } else { $null }
    $uacLevel   = if ($uacKey) { $uacKey.ConsentPromptBehaviorAdmin } else { $null }

    # RDP
    $rdpDeny  = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
    $rdpPort  = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "PortNumber"
    $rdpNLA   = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"

    # WinRM
    $winrm = try { (Get-Service WinRM -ErrorAction Stop).Status } catch { "Unknown" }

    # Windows Defender
    $defenderStatus = try {
        Get-MpComputerStatus -ErrorAction Stop |
        Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled,
                      RealTimeProtectionEnabled, BehaviorMonitorEnabled,
                      AntivirusSignatureLastUpdated, AntispywareSignatureLastUpdated,
                      NISEnabled, IoavProtectionEnabled
    } catch { $null }

    # Third-party AV via SecurityCenter2
    $avProducts = try {
        Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop |
        Select-Object displayName, productState, pathToSignedProductExe
    } catch { $null }

    # BitLocker
    $bitlocker = try {
        manage-bde -status 2>$null | Select-String "Protection Status" | ForEach-Object { $_.Line.Trim() }
    } catch { $null }

    # AlwaysInstallElevated (PE escalation)
    $aieHKCU = Get-RegValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    $aieHKLM = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"

    # WDigest (plaintext creds in memory)
    $wdigest = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"

    # Cached credentials
    $cachedCreds = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount"

    # Credential Guard
    $credGuard = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity"

    # PS Execution Policy
    $psPolicy = try { Get-ExecutionPolicy -List | Select-Object Scope, ExecutionPolicy } catch { $null }

    # Audit Policy
    $auditPolicy = try { (auditpol /get /category:* 2>$null) -join "`n" } catch { $null }

    # AutoRun
    $autorun = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun"

    [ordered]@{
        UAC = [ordered]@{
            Enabled         = $uacEnabled
            ConsentLevel    = $uacLevel
            # Level meanings: 0=Never notify, 1=Notify app changes only no dim, 2=Notify app changes, 5=Always notify
        }
        RDP = [ordered]@{
            Enabled             = if ($rdpDeny -eq 0) { $true } elseif ($rdpDeny -eq 1) { $false } else { "Unknown" }
            Port                = $rdpPort
            NLARequired         = if ($rdpNLA -eq 1) { $true } else { $false }
        }
        WinRM                   = $winrm
        WindowsDefender         = $defenderStatus
        ThirdPartyAV            = @($avProducts)
        BitLockerStatus         = $bitlocker
        SMBv1_Checked           = $true  # detailed in Shares section
        PSExecutionPolicy       = @($psPolicy)
        AuditPolicy             = $auditPolicy
        PrivilegeEscalation = [ordered]@{
            AlwaysInstallElevated_HKCU   = $aieHKCU
            AlwaysInstallElevated_HKLM   = $aieHKLM
            AIE_Risk                     = if ($aieHKCU -eq 1 -and $aieHKLM -eq 1) { "HIGH - MSI privilege escalation possible" } else { "Low" }
            WDigest_CleartextCreds       = $wdigest
            WDigest_Risk                 = if ($wdigest -eq 1) { "HIGH - Plaintext creds in LSASS memory" } else { "Low" }
            CachedLogonCount             = $cachedCreds
        }
        CredentialGuard             = $credGuard
        AutoRunNoDriveTypeValue     = $autorun
    }
}

# ── 15. RUNNING PROCESSES ─────────────────────────────────────
Write-Host "  [+] Running Processes" -ForegroundColor Gray
$VA.Processes = Invoke-Safe "Processes" {
    $procs = Get-CimInstance Win32_Process -ErrorAction Stop
    @($procs | ForEach-Object { [ordered]@{
        PID         = $_.ProcessId
        ParentPID   = $_.ParentProcessId
        Name        = $_.Name
        Path        = $_.ExecutablePath
        CommandLine = $_.CommandLine
        CreationDate= $_.CreationDate
    }})
}

# ── 16. INSTALLED DRIVERS ─────────────────────────────────────
Write-Host "  [+] Drivers" -ForegroundColor Gray
$VA.Drivers = Invoke-Safe "Drivers" {
    $drivers = try { driverquery /fo csv 2>$null | ConvertFrom-Csv } catch { $null }
    @($drivers)
}

# ── 17. ENVIRONMENT VARIABLES ─────────────────────────────────
Write-Host "  [+] Environment Variables" -ForegroundColor Gray
$VA.EnvironmentVars = Invoke-Safe "EnvVars" {
    [ordered]@{
        System = [System.Environment]::GetEnvironmentVariables([System.EnvironmentVariableTarget]::Machine)
        User   = [System.Environment]::GetEnvironmentVariables([System.EnvironmentVariableTarget]::User)
    }
}

# ── 18. .NET & POWERSHELL INFO ────────────────────────────────
Write-Host "  [+] .NET / PowerShell" -ForegroundColor Gray
$VA.RuntimeInfo = Invoke-Safe "RuntimeInfo" {
    $dotnetVersions = try {
        Get-ChildItem "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" -Recurse -ErrorAction SilentlyContinue |
        Get-ItemProperty -Name Version, Release -ErrorAction SilentlyContinue |
        Select-Object PSChildName, Version, Release
    } catch { $null }

    [ordered]@{
        DotNetVersions      = @($dotnetVersions)
        PSVersion           = $PSVersionTable.PSVersion.ToString()
        PSEdition           = $PSVersionTable.PSEdition
        CLRV                = $PSVersionTable.CLRVersion.ToString()
        PSCompatibleVersions= $PSVersionTable.PSCompatibleVersions.ToString()
    }
}

# ── 19. RECENT SECURITY EVENTS ────────────────────────────────
Write-Host "  [+] Security Events (recent)" -ForegroundColor Gray
$VA.SecurityEvents = Invoke-Safe "SecurityEvents" {
    $failedLogons = try {
        Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625} -MaxEvents 50 -ErrorAction Stop |
        Select-Object TimeCreated, Id, Message
    } catch { $null }

    $successLogons = try {
        Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4624} -MaxEvents 20 -ErrorAction Stop |
        Select-Object TimeCreated, Id, Message
    } catch { $null }

    $sysErrors = try {
        Get-WinEvent -FilterHashtable @{LogName="System"; Level=2} -MaxEvents 20 -ErrorAction Stop |
        Select-Object TimeCreated, Id, ProviderName, Message
    } catch { $null }

    $appErrors = try {
        Get-WinEvent -FilterHashtable @{LogName="Application"; Level=2} -MaxEvents 20 -ErrorAction Stop |
        Select-Object TimeCreated, Id, ProviderName, Message
    } catch { $null }

    [ordered]@{
        FailedLogons_4625_Count = if ($failedLogons) { ($failedLogons | Measure-Object).Count } else { 0 }
        FailedLogons_Last50     = @($failedLogons)
        SuccessLogons_Last20    = @($successLogons)
        SystemErrors_Last20     = @($sysErrors)
        AppErrors_Last20        = @($appErrors)
    }
}

# ── 20. RISK SUMMARY ──────────────────────────────────────────
Write-Host "  [+] Building Risk Summary" -ForegroundColor Gray
$VA.RiskSummary = [ordered]@{
    Findings = [System.Collections.Generic.List[object]]::new()
}

function Add-Finding {
    param([string]$Severity, [string]$Category, [string]$Title, [string]$Detail)
    $VA.RiskSummary.Findings.Add([ordered]@{
        Severity = $Severity; Category = $Category; Title = $Title; Detail = $Detail
    })
}

# Auto-flag risks based on collected data
if ($VA.SecurityConfig -and $VA.SecurityConfig.UAC.Enabled -eq 0) {
    Add-Finding "HIGH" "UAC" "UAC Disabled" "User Account Control is disabled. Privilege escalation risk."
}
if ($VA.SecurityConfig -and $VA.SecurityConfig.RDP.Enabled -eq $true -and $VA.SecurityConfig.RDP.NLARequired -eq $false) {
    Add-Finding "MEDIUM" "RDP" "RDP enabled without NLA" "RDP is active but Network Level Authentication is not enforced."
}
if ($VA.Shares -and $VA.Shares.SMBv1_Risk -like "HIGH*") {
    Add-Finding "CRITICAL" "SMB" "SMBv1 Enabled (EternalBlue)" "SMBv1 is active. System is potentially vulnerable to EternalBlue/WannaCry."
}
if ($VA.SecurityConfig -and $VA.SecurityConfig.PrivilegeEscalation.AIE_Risk -like "HIGH*") {
    Add-Finding "HIGH" "PrivEsc" "AlwaysInstallElevated Enabled" "MSI files can be installed with SYSTEM privileges by any user."
}
if ($VA.SecurityConfig -and $VA.SecurityConfig.PrivilegeEscalation.WDigest_Risk -like "HIGH*") {
    Add-Finding "HIGH" "Credentials" "WDigest Plaintext Creds Active" "Credentials stored in plaintext in LSASS memory. Mimikatz risk."
}
if ($VA.Services -and $VA.Services.UnquotedCount -gt 0) {
    Add-Finding "MEDIUM" "PrivEsc" "Unquoted Service Path(s) Found" "$($VA.Services.UnquotedCount) service(s) have unquoted paths with spaces - potential privilege escalation."
}
if ($VA.PatchStatus -and $VA.PatchStatus.DaysSinceLastPatch -gt 90) {
    Add-Finding "HIGH" "Patching" "System Not Patched in 90+ Days" "Last patch applied $($VA.PatchStatus.DaysSinceLastPatch) days ago ($($VA.PatchStatus.MostRecentPatchKB))."
}
if ($VA.SecurityConfig -and $null -eq $VA.SecurityConfig.WindowsDefender) {
    Add-Finding "HIGH" "AV" "Defender Status Unknown/Inactive" "Could not retrieve Windows Defender status. Verify AV coverage."
}
if ($VA.Metadata.IsAdmin -eq $false) {
    Add-Finding "INFO" "Collection" "Script ran without Admin rights" "Some data may be incomplete. Run as Administrator for full assessment."
}

$VA.RiskSummary.TotalFindings  = $VA.RiskSummary.Findings.Count
$VA.RiskSummary.CriticalCount  = ($VA.RiskSummary.Findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$VA.RiskSummary.HighCount      = ($VA.RiskSummary.Findings | Where-Object { $_.Severity -eq "HIGH" }).Count
$VA.RiskSummary.MediumCount    = ($VA.RiskSummary.Findings | Where-Object { $_.Severity -eq "MEDIUM" }).Count

# ============================================================
#  OUTPUT — JSON (machine-readable) + TXT (human-readable)
# ============================================================
Write-Host "  [+] Writing outputs..." -ForegroundColor Gray

# JSON output
$VA | ConvertTo-Json -Depth 15 | Out-File $JsonFile -Encoding UTF8

# Human-readable TXT summary
$TxtOutput = [System.Text.StringBuilder]::new()
$sep = "=" * 70

$null = $TxtOutput.AppendLine($sep)
$null = $TxtOutput.AppendLine("  VULNERABILITY ASSESSMENT REPORT — $Hostname")
$null = $TxtOutput.AppendLine($sep)
$null = $TxtOutput.AppendLine("Collected At : $TimeStamp")
$null = $TxtOutput.AppendLine("Collected By : $env:USERNAME")
$null = $TxtOutput.AppendLine("Admin Rights : $($VA.Metadata.IsAdmin)")
$null = $TxtOutput.AppendLine("")

$null = $TxtOutput.AppendLine("── RISK SUMMARY ──────────────────────────────────────────────────────")
$null = $TxtOutput.AppendLine("Total Findings : $($VA.RiskSummary.TotalFindings)")
$null = $TxtOutput.AppendLine("  CRITICAL     : $($VA.RiskSummary.CriticalCount)")
$null = $TxtOutput.AppendLine("  HIGH         : $($VA.RiskSummary.HighCount)")
$null = $TxtOutput.AppendLine("  MEDIUM       : $($VA.RiskSummary.MediumCount)")
$null = $TxtOutput.AppendLine("")
foreach ($f in $VA.RiskSummary.Findings) {
    $null = $TxtOutput.AppendLine("  [$($f.Severity)] [$($f.Category)] $($f.Title)")
    $null = $TxtOutput.AppendLine("    => $($f.Detail)")
}

$null = $TxtOutput.AppendLine("")
$null = $TxtOutput.AppendLine("── SYSTEM ────────────────────────────────────────────────────────────")
$si = $VA.SystemInfo
if ($si) {
    $null = $TxtOutput.AppendLine("OS           : $($si.OSCaption) (Build $($si.OSBuildNumber))")
    $null = $TxtOutput.AppendLine("Version      : $($si.OSVersion)")
    $null = $TxtOutput.AppendLine("Architecture : $($si.OSArchitecture)")
    $null = $TxtOutput.AppendLine("Domain       : $($si.Domain) (Role: $($si.DomainRole))")
    $null = $TxtOutput.AppendLine("Model        : $($si.Manufacturer) $($si.Model)")
    $null = $TxtOutput.AppendLine("BIOS         : $($si.BIOSManufacturer) $($si.BIOSVersion)")
    $null = $TxtOutput.AppendLine("CPU          : $($si.CPUName) ($($si.CPUCores) cores)")
    $null = $TxtOutput.AppendLine("RAM          : $($si.TotalRAM_GB) GB")
    $null = $TxtOutput.AppendLine("Last Boot    : $($si.LastBootTime) (Up: $($si.UptimeDays) days)")
    $null = $TxtOutput.AppendLine("Install Date : $($si.InstallDate)")
}

$null = $TxtOutput.AppendLine("")
$null = $TxtOutput.AppendLine("── PATCH STATUS ──────────────────────────────────────────────────────")
if ($VA.PatchStatus) {
    $null = $TxtOutput.AppendLine("Total KBs Installed  : $($VA.PatchStatus.TotalHotfixes)")
    $null = $TxtOutput.AppendLine("Last Patch           : $($VA.PatchStatus.MostRecentPatchKB) on $($VA.PatchStatus.MostRecentPatch)")
    $null = $TxtOutput.AppendLine("Days Since Patch     : $($VA.PatchStatus.DaysSinceLastPatch)")
}

$null = $TxtOutput.AppendLine("")
$null = $TxtOutput.AppendLine("── NETWORK INTERFACES ────────────────────────────────────────────────")
if ($VA.NetworkConfig -and $VA.NetworkConfig.Adapters) {
    foreach ($a in $VA.NetworkConfig.Adapters) {
        $null = $TxtOutput.AppendLine("  $($a.Description)")
        $null = $TxtOutput.AppendLine("    MAC: $($a.MACAddress)  IP: $($a.IPAddresses -join ', ')")
        $null = $TxtOutput.AppendLine("    GW:  $($a.DefaultGateway -join ', ')  DNS: $($a.DNSServers -join ', ')")
    }
}

$null = $TxtOutput.AppendLine("")
$null = $TxtOutput.AppendLine("── LISTENING PORTS ───────────────────────────────────────────────────")
if ($VA.NetworkConnections -and $VA.NetworkConnections.ListeningPorts) {
    foreach ($p in $VA.NetworkConnections.ListeningPorts | Sort-Object { [int](($_.LocalAddr -split ":")[-1]) }) {
        $null = $TxtOutput.AppendLine("  $($p.Protocol)  $($p.LocalAddr)  PID:$($p.PID)")
    }
}

$null = $TxtOutput.AppendLine("")
$null = $TxtOutput.AppendLine("── LOCAL ADMINS ──────────────────────────────────────────────────────")
if ($VA.UserAccounts -and $VA.UserAccounts.LocalAdministrators) {
    foreach ($a in $VA.UserAccounts.LocalAdministrators) {
        $null = $TxtOutput.AppendLine("  $a")
    }
}

$null = $TxtOutput.AppendLine("")
$null = $TxtOutput.AppendLine("── UNQUOTED SERVICE PATHS ────────────────────────────────────────────")
if ($VA.Services -and $VA.Services.UnquotedServicePaths) {
    foreach ($s in $VA.Services.UnquotedServicePaths) {
        $null = $TxtOutput.AppendLine("  [$($s.State)] $($s.Name) => $($s.PathName)")
    }
}
if ($VA.Services.UnquotedCount -eq 0) {
    $null = $TxtOutput.AppendLine("  None found.")
}

$null = $TxtOutput.AppendLine("")
$null = $TxtOutput.AppendLine("── SECURITY CONFIG ───────────────────────────────────────────────────")
if ($VA.SecurityConfig) {
    $null = $TxtOutput.AppendLine("UAC Enabled      : $($VA.SecurityConfig.UAC.Enabled)")
    $null = $TxtOutput.AppendLine("RDP Enabled      : $($VA.SecurityConfig.RDP.Enabled) | NLA: $($VA.SecurityConfig.RDP.NLARequired) | Port: $($VA.SecurityConfig.RDP.Port)")
    $null = $TxtOutput.AppendLine("WinRM Status     : $($VA.SecurityConfig.WinRM)")
    $null = $TxtOutput.AppendLine("Defender Active  : $($VA.SecurityConfig.WindowsDefender.AntivirusEnabled)")
    $null = $TxtOutput.AppendLine("Realtime Protect : $($VA.SecurityConfig.WindowsDefender.RealTimeProtectionEnabled)")
    $null = $TxtOutput.AppendLine("WDigest          : $($VA.SecurityConfig.PrivilegeEscalation.WDigest_CleartextCreds) — $($VA.SecurityConfig.PrivilegeEscalation.WDigest_Risk)")
    $null = $TxtOutput.AppendLine("AIE Elevated     : HKLM=$($VA.SecurityConfig.PrivilegeEscalation.AlwaysInstallElevated_HKLM) HKCU=$($VA.SecurityConfig.PrivilegeEscalation.AlwaysInstallElevated_HKCU)")
    $null = $TxtOutput.AppendLine("Cached Logons    : $($VA.SecurityConfig.PrivilegeEscalation.CachedLogonCount)")
    $null = $TxtOutput.AppendLine("BitLocker        : $($VA.SecurityConfig.BitLockerStatus -join ' | ')")
}

$null = $TxtOutput.AppendLine("")
$null = $TxtOutput.AppendLine("── FAILED LOGONS (last 50) ───────────────────────────────────────────")
$null = $TxtOutput.AppendLine("Count: $($VA.SecurityEvents.FailedLogons_4625_Count)")

$null = $TxtOutput.AppendLine("")
$null = $TxtOutput.AppendLine($sep)
$null = $TxtOutput.AppendLine("  Full detail available in: $(Split-Path $JsonFile -Leaf)")
$null = $TxtOutput.AppendLine("  Collection errors (if any): $(Split-Path $ErrorLog -Leaf)")
$null = $TxtOutput.AppendLine($sep)

$TxtOutput.ToString() | Out-File $TxtFile -Encoding UTF8

# Write error log
if ($ErrorAccumulator.Count -gt 0) {
    $ErrorAccumulator | Out-File $ErrorLog -Encoding UTF8
}

# ============================================================
#  DONE
# ============================================================
Write-Host ""
Write-Host "[COMPLETE] $Hostname — $($VA.RiskSummary.TotalFindings) findings ($($VA.RiskSummary.CriticalCount) Critical, $($VA.RiskSummary.HighCount) High)" -ForegroundColor Cyan
Write-Host "  JSON   : $JsonFile" -ForegroundColor Green
Write-Host "  Report : $TxtFile"  -ForegroundColor Green
if ($ErrorAccumulator.Count -gt 0) {
    Write-Host "  Errors : $ErrorLog ($($ErrorAccumulator.Count) non-fatal errors logged)" -ForegroundColor Yellow
}
