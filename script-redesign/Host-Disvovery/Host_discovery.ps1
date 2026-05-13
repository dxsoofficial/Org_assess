param (
    [string]$Subnet = "192.168.0",
    [int]$StartIP = 1,
    [int]$EndIP = 254
)

$ORG_NAME = Read-Host "Enter Organization Name"
$ORG_NAME = $ORG_NAME -replace " ", "_"

$OutputDir = Join-Path (Get-Location) $ORG_NAME
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$CSVFile = Join-Path $OutputDir "Host-Discovery.csv"
$TXTFile = Join-Path $OutputDir "Host-Discovery.txt"
$LOGFile = Join-Path $OutputDir "Scan.log"

"IPAddress,HostName,DeviceType" | Out-File $CSVFile

$devices = @()

function Test-Port {
    param($ip, $port)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $async = $tcp.BeginConnect($ip, $port, $null, $null)
        $wait = $async.AsyncWaitHandle.WaitOne(500)
        if ($wait -and $tcp.Connected) {
            $tcp.Close()
            return $true
        }
    } catch {}
    return $false
}

function Get-DeviceType {
    param($ip)

    if (Test-Port $ip 3389) { return "Windows Endpoint" }
    elseif (Test-Port $ip 22) { return "Linux Endpoint" }
    elseif (Test-Port $ip 9100) { return "Printer" }
    elseif (Test-Port $ip 554) { return "Camera" }
    elseif (Test-Port $ip 80 -or Test-Port $ip 443) { return "Web Device" }

    return "Unknown"
}

for ($i = $StartIP; $i -le $EndIP; $i++) {
    $ip = "$Subnet.$i"

    if (Test-Connection $ip -Count 1 -Quiet -ErrorAction SilentlyContinue) {
        
        $hostname = ""
        try { $hostname = ([System.Net.Dns]::GetHostEntry($ip)).HostName } catch {}

        $type = Get-DeviceType $ip

        $obj = [PSCustomObject]@{
            IPAddress = $ip
            HostName = $hostname
            DeviceType = $type
        }

        $devices += $obj
        "$ip,$hostname,$type" | Out-File $CSVFile -Append
    }
}

$TOTAL = $devices.Count

# ===== TXT REPORT =====
$report = @()

$report += "========================================="
$report += "     NETWORK DISCOVERY REPORT"
$report += "========================================="
$report += "Organization : $ORG_NAME"
$report += "Date         : $(Get-Date)"
$report += "Subnet       : $Subnet.0/24"
$report += ""

$report += "Total Devices Discovered : $TOTAL"
$report += ""

$report += "========== DEVICE SUMMARY =========="
$summary = $devices | Group-Object DeviceType
foreach ($s in $summary) {
    $report += "{0,-20} : {1}" -f $s.Name, $s.Count
}

$report += ""
$report += "========== DEVICE DETAILS =========="
$report += "{0,-15} {1,-30} {2,-20}" -f "IP Address", "HostName", "Device Type"
$report += "---------------------------------------------------------------"

foreach ($d in $devices) {
    $report += "{0,-15} {1,-30} {2,-20}" -f $d.IPAddress, $d.HostName, $d.DeviceType
}

$report | Out-File $TXTFile

Write-Host "Scan complete."
Write-Host "Total Devices: $TOTAL"cd 