<# 
DXSO MSME Assessment - Windows 10/11 Setup Wizard
Note: Run this in an Administrator PowerShell session!
#>

Write-Host "[========= DXSO Framework Windows Setup =========]" -ForegroundColor Cyan
Write-Host "[!] WARNING: This framework is designed for Kali Linux." -ForegroundColor Yellow
Write-Host "[!] Some tools (Zeek, Kismet, OpenVAS, arp-scan) CANNOT run natively on Windows without WSL or Docker." -ForegroundColor Yellow
Write-Host ""
Write-Host "[*] Checking for Winget (Windows Package Manager)..." -ForegroundColor Green

if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Host "[+] Winget found! Installing Windows-compatible CLI tools..." -ForegroundColor Green
    
    # Phase 1 & 4 Core Network Tools (Nmap, Wireshark/tshark)
    Write-Host "`n[*] Installing Nmap..." -ForegroundColor Yellow
    winget install Insecure.Nmap -h --accept-source-agreements --accept-package-agreements
    
    Write-Host "`n[*] Installing Wireshark (includes tshark)..." -ForegroundColor Yellow
    winget install WiresharkFoundation.Wireshark -h --accept-source-agreements --accept-package-agreements

    # Phase 7 Core Vulnerability Tools (Nuclei, Metasploit)
    Write-Host "`n[*] Installing Nuclei (ProjectDiscovery)..." -ForegroundColor Yellow
    winget install ProjectDiscovery.Nuclei -h --accept-source-agreements --accept-package-agreements

    Write-Host "`n[*] Installing Metasploit Framework..." -ForegroundColor Yellow
    winget install Rapid7.Metasploit -h --accept-source-agreements --accept-package-agreements

} else {
    Write-Host "[!] Winget is missing! Please update your App Installer from the Microsoft Store." -ForegroundColor Red
}

# Python-Based Tools (Impacket, URLCrazy, DNSRecon)
Write-Host "`n[*] Installing Python-based Hacking Tools via Pip..." -ForegroundColor Green
if (Get-Command pip -ErrorAction SilentlyContinue) {
    pip install impacket urlcrazy dnsrecon theharvester openpyxl
    Write-Host "[+] Pip installations complete." -ForegroundColor Green
} else {
    Write-Host "[!] Python/Pip is not installed or not in your system PATH!" -ForegroundColor Red
}

Write-Host "`n[========= Unsuppported Windows Tools =========]" -ForegroundColor DarkGray
Write-Host "The following tools must be run from a Linux Subsystem (WSL) or Kali VM:"
Write-Host "  - Kismet & Aircrack-ng (Windows Wi-Fi cards rarely support Monitor Mode)"
Write-Host "  - Zeek (Unix-socket dependent)"
Write-Host "  - OpenVAS / gvm-cli (Requires Linux daemon)"
Write-Host "  - arp-scan & netdiscover (Native raw socket issues on Win32)"
Write-Host ""
Write-Host "[+] Setup Sequence Complete. You can run 'python wrapper.py' for the supported phases!" -ForegroundColor Cyan
