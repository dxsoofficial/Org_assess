@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  VULNERABILITY ASSESSMENT - FULL SYSTEM COLLECTOR
::  Run as Administrator for complete output
:: ============================================================

set HOSTNAME=%COMPUTERNAME%
set BASEDIR=%~dp0
set OUTPUTDIR=%BASEDIR%output
if not exist "%OUTPUTDIR%" mkdir "%OUTPUTDIR%"
set OUTPUT=%OUTPUTDIR%\%HOSTNAME%_VA.txt
if exist "%OUTPUT%" del "%OUTPUT%"

:: Check admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Not running as Administrator. Some data may be incomplete.
)

call :HEADER "VULNERABILITY ASSESSMENT REPORT"
echo Hostname     : %COMPUTERNAME%                               >> "%OUTPUT%"
echo Date/Time    : %DATE% %TIME%                               >> "%OUTPUT%"
echo Collected by : %USERNAME%                                  >> "%OUTPUT%"

:: ============================================================
::  1. SYSTEM INFORMATION
:: ============================================================
call :HEADER "1. FULL SYSTEM INFO"
systeminfo >> "%OUTPUT%"

call :HEADER "1.1 OS DETAILS"
wmic os get Caption,Version,BuildNumber,OSArchitecture,ServicePackMajorVersion,InstallDate,LastBootUpTime /format:list >> "%OUTPUT%"

call :HEADER "1.2 BIOS INFO"
wmic bios get Manufacturer,Name,Version,ReleaseDate,SerialNumber /format:list >> "%OUTPUT%"

call :HEADER "1.3 MOTHERBOARD / SYSTEM MODEL"
wmic computersystem get Manufacturer,Model,SystemType,PCSystemType /format:list >> "%OUTPUT%"

:: ============================================================
::  2. USER & ACCOUNT SECURITY
:: ============================================================
call :HEADER "2. LOCAL USER ACCOUNTS"
net user >> "%OUTPUT%"

call :HEADER "2.1 DETAILED USER INFO (all local users)"
for /f "skip=4 tokens=1" %%u in ('net user') do (
    echo --- User: %%u --- >> "%OUTPUT%"
    net user %%u >> "%OUTPUT%"
)

call :HEADER "2.2 LOCAL ADMINISTRATORS GROUP"
net localgroup administrators >> "%OUTPUT%"

call :HEADER "2.3 ALL LOCAL GROUPS"
net localgroup >> "%OUTPUT%"

call :HEADER "2.4 PASSWORD POLICY"
net accounts >> "%OUTPUT%"

call :HEADER "2.5 CURRENT USER PRIVILEGES"
whoami /all >> "%OUTPUT%"

call :HEADER "2.6 LOGGED-ON USERS"
query user >> "%OUTPUT%" 2>&1

:: ============================================================
::  3. DOMAIN & ACTIVE DIRECTORY
:: ============================================================
call :HEADER "3. DOMAIN INFO"
wmic computersystem get Domain,DomainRole,PartOfDomain /format:list >> "%OUTPUT%"
nltest /dsgetdc:%USERDOMAIN% >> "%OUTPUT%" 2>&1

:: ============================================================
::  4. NETWORK CONFIGURATION
:: ============================================================
call :HEADER "4. FULL NETWORK CONFIG (ipconfig /all)"
ipconfig /all >> "%OUTPUT%"

call :HEADER "4.1 OPEN PORTS & LISTENING SERVICES"
netstat -ano >> "%OUTPUT%"

call :HEADER "4.2 ACTIVE CONNECTIONS WITH PROCESS NAMES"
netstat -b -n 2>&1 >> "%OUTPUT%"

call :HEADER "4.3 ROUTING TABLE"
route print >> "%OUTPUT%"

call :HEADER "4.4 ARP TABLE"
arp -a >> "%OUTPUT%"

call :HEADER "4.5 DNS CACHE"
ipconfig /displaydns >> "%OUTPUT%"

call :HEADER "4.6 NETWORK SHARES (SMB)"
net share >> "%OUTPUT%"

call :HEADER "4.7 MAPPED DRIVES"
net use >> "%OUTPUT%"

call :HEADER "4.8 HOSTS FILE"
type C:\Windows\System32\drivers\etc\hosts >> "%OUTPUT%"

call :HEADER "4.9 WIFI PROFILES"
netsh wlan show profiles >> "%OUTPUT%" 2>&1

call :HEADER "4.10 FIREWALL STATUS (all profiles)"
netsh advfirewall show allprofiles >> "%OUTPUT%"

call :HEADER "4.11 FIREWALL RULES (inbound)"
netsh advfirewall firewall show rule name=all dir=in >> "%OUTPUT%"

call :HEADER "4.12 FIREWALL RULES (outbound)"
netsh advfirewall firewall show rule name=all dir=out >> "%OUTPUT%"

call :HEADER "4.13 PROXY SETTINGS"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable >> "%OUTPUT%" 2>&1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer >> "%OUTPUT%" 2>&1

:: ============================================================
::  5. PATCH & UPDATE STATUS
:: ============================================================
call :HEADER "5. INSTALLED HOTFIXES / PATCHES (KBs)"
wmic qfe get HotFixID,Description,InstalledOn,InstalledBy /format:list >> "%OUTPUT%"

call :HEADER "5.1 WINDOWS UPDATE SETTINGS"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" >> "%OUTPUT%" 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" >> "%OUTPUT%" 2>&1

call :HEADER "5.2 WINDOWS UPDATE SERVICE STATUS"
sc query wuauserv >> "%OUTPUT%"

:: ============================================================
::  6. INSTALLED SOFTWARE
:: ============================================================
call :HEADER "6. INSTALLED SOFTWARE (32-bit)"
wmic product get Name,Version,Vendor,InstallDate /format:list >> "%OUTPUT%"

call :HEADER "6.1 INSTALLED SOFTWARE VIA REGISTRY (64-bit)"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s >> "%OUTPUT%" 2>&1

call :HEADER "6.2 INSTALLED SOFTWARE VIA REGISTRY (32-bit on 64-bit OS)"
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s >> "%OUTPUT%" 2>&1

:: ============================================================
::  7. SERVICES
:: ============================================================
call :HEADER "7. ALL SERVICES (running + stopped)"
sc query type= all state= all >> "%OUTPUT%"

call :HEADER "7.1 SERVICES WITH PATHS (check for unquoted service paths)"
wmic service get Name,DisplayName,PathName,StartMode,State /format:list >> "%OUTPUT%"

call :HEADER "7.2 AUTO-START SERVICES"
wmic service where StartMode='Auto' get Name,State,PathName /format:list >> "%OUTPUT%"

:: ============================================================
::  8. STARTUP & PERSISTENCE
:: ============================================================
call :HEADER "8. STARTUP PROGRAMS (WMIC)"
wmic startup get Caption,Command,Location,User /format:list >> "%OUTPUT%"

call :HEADER "8.1 STARTUP REGISTRY - HKLM RUN"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >> "%OUTPUT%" 2>&1

call :HEADER "8.2 STARTUP REGISTRY - HKCU RUN"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >> "%OUTPUT%" 2>&1

call :HEADER "8.3 STARTUP REGISTRY - HKLM RUNONCE"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" >> "%OUTPUT%" 2>&1

call :HEADER "8.4 SCHEDULED TASKS"
schtasks /query /fo LIST /v >> "%OUTPUT%"

:: ============================================================
::  9. SECURITY CONFIGURATION
:: ============================================================
call :HEADER "9. UAC SETTINGS"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA >> "%OUTPUT%" 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin >> "%OUTPUT%" 2>&1

call :HEADER "9.1 WINDOWS DEFENDER / ANTIVIRUS STATUS"
sc query WinDefend >> "%OUTPUT%" 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" >> "%OUTPUT%" 2>&1
powershell -command "Get-MpComputerStatus 2>$null | Select-Object AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntispywareSignatureLastUpdated,AntivirusSignatureLastUpdated | Format-List" >> "%OUTPUT%" 2>&1

call :HEADER "9.2 INSTALLED SECURITY PRODUCTS (AV/Firewall via WMI)"
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,productState,pathToSignedProductExe /format:list >> "%OUTPUT%" 2>&1
wmic /namespace:\\root\SecurityCenter2 path FirewallProduct get displayName,productState /format:list >> "%OUTPUT%" 2>&1

call :HEADER "9.3 RDP STATUS"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections >> "%OUTPUT%" 2>&1
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber >> "%OUTPUT%" 2>&1

call :HEADER "9.4 WINRM STATUS"
sc query WinRM >> "%OUTPUT%"

call :HEADER "9.5 SMB v1 STATUS (EternalBlue risk)"
sc query mrxsmb10 >> "%OUTPUT%" 2>&1
reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 >> "%OUTPUT%" 2>&1

call :HEADER "9.6 BITLOCKER STATUS"
manage-bde -status >> "%OUTPUT%" 2>&1

call :HEADER "9.7 AUDIT POLICY"
auditpol /get /category:* >> "%OUTPUT%" 2>&1

call :HEADER "9.8 LOCAL SECURITY POLICY (secedit)"
secedit /export /cfg "%OUTPUTDIR%\secedit_policy.cfg" /quiet
type "%OUTPUTDIR%\secedit_policy.cfg" >> "%OUTPUT%" 2>&1

call :HEADER "9.9 APPLOCKER / SOFTWARE RESTRICTION POLICY"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2" /s >> "%OUTPUT%" 2>&1

call :HEADER "9.10 CREDENTIAL GUARD / DEVICE GUARD"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /s >> "%OUTPUT%" 2>&1

:: ============================================================
::  10. RUNNING PROCESSES & TASKS
:: ============================================================
call :HEADER "10. RUNNING PROCESSES (tasklist)"
tasklist /v >> "%OUTPUT%"

call :HEADER "10.1 PROCESSES WITH FULL PATH"
wmic process get Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine /format:list >> "%OUTPUT%"

:: ============================================================
::  11. HARDWARE
:: ============================================================
call :HEADER "11. CPU"
wmic cpu get Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed /format:list >> "%OUTPUT%"

call :HEADER "11.1 MEMORY"
wmic computersystem get TotalPhysicalMemory /format:list >> "%OUTPUT%"
wmic memorychip get BankLabel,Capacity,Speed /format:list >> "%OUTPUT%"

call :HEADER "11.2 DISK"
wmic logicaldisk get Caption,DriveType,FileSystem,FreeSpace,Size,VolumeName /format:list >> "%OUTPUT%"
wmic diskdrive get Model,Size,InterfaceType,SerialNumber /format:list >> "%OUTPUT%"

call :HEADER "11.3 DRIVERS"
driverquery /fo list /v >> "%OUTPUT%"

:: ============================================================
::  12. EVENT LOG SNAPSHOT
:: ============================================================
call :HEADER "12. RECENT FAILED LOGON EVENTS (last 50)"
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:50 /rd:true /f:text >> "%OUTPUT%" 2>&1

call :HEADER "12.1 RECENT SUCCESSFUL LOGON EVENTS (last 20)"
wevtutil qe Security /q:"*[System[(EventID=4624)]]" /c:20 /rd:true /f:text >> "%OUTPUT%" 2>&1

call :HEADER "12.2 RECENT SYSTEM ERRORS (last 20)"
wevtutil qe System /q:"*[System[(Level=2)]]" /c:20 /rd:true /f:text >> "%OUTPUT%" 2>&1

call :HEADER "12.3 RECENT APPLICATION ERRORS (last 20)"
wevtutil qe Application /q:"*[System[(Level=2)]]" /c:20 /rd:true /f:text >> "%OUTPUT%" 2>&1

:: ============================================================
::  13. ENVIRONMENT & MISC
:: ============================================================
call :HEADER "13. ENVIRONMENT VARIABLES"
set >> "%OUTPUT%"

call :HEADER "13.1 POWERSHELL EXECUTION POLICY"
powershell -command "Get-ExecutionPolicy -List" >> "%OUTPUT%" 2>&1

call :HEADER "13.2 .NET FRAMEWORK VERSIONS"
reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP" /s >> "%OUTPUT%" 2>&1

call :HEADER "13.3 REMOTE DESKTOP USERS GROUP"
net localgroup "Remote Desktop Users" >> "%OUTPUT%" 2>&1

call :HEADER "13.4 OPEN ADMINISTRATIVE SHARES"
net share | findstr /i "C$ D$ E$ ADMIN$ IPC$" >> "%OUTPUT%" 2>&1

call :HEADER "13.5 CACHED CREDENTIALS COUNT"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount >> "%OUTPUT%" 2>&1

call :HEADER "13.6 ALWAYS INSTALL ELEVATED (PE escalation risk)"
reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated >> "%OUTPUT%" 2>&1
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated >> "%OUTPUT%" 2>&1

call :HEADER "13.7 AUTORUN / AUTOPLAY SETTINGS"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun >> "%OUTPUT%" 2>&1

call :HEADER "13.8 WDIGEST PLAINTEXT CREDS (credential theft risk)"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential >> "%OUTPUT%" 2>&1

echo. >> "%OUTPUT%"
echo ==== AUDIT COMPLETE ==== >> "%OUTPUT%"
echo. >> "%OUTPUT%"
echo Output saved to: %OUTPUT%
echo Done. Review %OUTPUT%
goto :EOF

:: ============================================================
::  HEADER FUNCTION
:: ============================================================
:HEADER
echo. >> "%OUTPUT%"
echo ================================================================ >> "%OUTPUT%"
echo   %~1 >> "%OUTPUT%"
echo ================================================================ >> "%OUTPUT%"
goto :EOF
