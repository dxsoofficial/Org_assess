@echo off
setlocal

set HOSTNAME=%COMPUTERNAME%
set BASEDIR=%~dp0
set OUTPUTDIR=%BASEDIR%output

if not exist "%OUTPUTDIR%" mkdir "%OUTPUTDIR%"
set OUTPUT=%OUTPUTDIR%%HOSTNAME%_VA.txt

if exist "%OUTPUT%" exit /b

echo ==== VULNERABILITY AUDIT START ==== > "%OUTPUT%"
echo Hostname: %HOSTNAME% >> "%OUTPUT%"
echo Date: %DATE% %TIME% >> "%OUTPUT%"

:: ================= SYSTEM =================
echo ==== SYSTEM INFO ==== >> "%OUTPUT%"
systeminfo >> "%OUTPUT%"

echo ==== HOTFIX / PATCHES ==== >> "%OUTPUT%"
wmic qfe list full >> "%OUTPUT%"

:: ================= USERS =================
echo ==== USERS ==== >> "%OUTPUT%"
net user >> "%OUTPUT%"

echo ==== ADMIN GROUP ==== >> "%OUTPUT%"
net localgroup administrators >> "%OUTPUT%"

echo ==== LOGGED IN USER ==== >> "%OUTPUT%"
query user >> "%OUTPUT%"

:: ================= SECURITY =================
echo ==== FIREWALL STATUS ==== >> "%OUTPUT%"
netsh advfirewall show allprofiles >> "%OUTPUT%"

echo ==== WINDOWS DEFENDER ==== >> "%OUTPUT%"
sc query WinDefend >> "%OUTPUT%"

echo ==== BITLOCKER STATUS ==== >> "%OUTPUT%"
manage-bde -status >> "%OUTPUT%"

:: ================= SOFTWARE =================
echo ==== INSTALLED SOFTWARE ==== >> "%OUTPUT%"
wmic product get name,version >> "%OUTPUT%"

:: ================= NETWORK =================
echo ==== NETWORK CONFIG ==== >> "%OUTPUT%"
ipconfig /all >> "%OUTPUT%"

echo ==== ACTIVE CONNECTIONS ==== >> "%OUTPUT%"
netstat -ano >> "%OUTPUT%"

echo ==== ROUTING TABLE ==== >> "%OUTPUT%"
route print >> "%OUTPUT%"

echo ==== ARP TABLE ==== >> "%OUTPUT%"
arp -a >> "%OUTPUT%"

:: ================= SERVICES =================
echo ==== RUNNING SERVICES ==== >> "%OUTPUT%"
sc query >> "%OUTPUT%"

echo ==== STARTUP PROGRAMS ==== >> "%OUTPUT%"
wmic startup get caption,command >> "%OUTPUT%"

:: ================= TASKS =================
echo ==== SCHEDULED TASKS ==== >> "%OUTPUT%"
schtasks /query /fo LIST /v >> "%OUTPUT%"

:: ================= SHARES =================
echo ==== SHARED FOLDERS ==== >> "%OUTPUT%"
net share >> "%OUTPUT%"

:: ================= RDP =================
echo ==== RDP STATUS ==== >> "%OUTPUT%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections >> "%OUTPUT%"

:: ================= SMB =================
echo ==== SMB VERSION ==== >> "%OUTPUT%"
sc qc lanmanworkstation >> "%OUTPUT%"

:: ================= EVENT LOGS =================
echo ==== RECENT SECURITY EVENTS ==== >> "%OUTPUT%"
wevtutil qe Security /c:20 /f:text >> "%OUTPUT%"

echo ==== VULNERABILITY AUDIT END ==== >> "%OUTPUT%"

endlocal
exit
