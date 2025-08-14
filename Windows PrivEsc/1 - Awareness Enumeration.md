# Getting the Lay of the Land

In this section will cover:
- Situational Awareness
- Initial Enumeration
- Communication with Processes

## Situational Awareness

When placed in any situation, whether in our day-to-day lives or during a project such as a network penetration test, it is always important to orient ourselves in space and time. We cannot function and react effectively without an understanding of our current surroundings. We require this information to make informed decisions about our next steps to operate proactively instead of reactively.

**Network Information**

We may find that the host is dual-homed and that compromising the host may allow us to move laterally into another part of the network that we could not access previously.

````
# Interface(s), IP Address(es), DNS Information
> ipconfig /all

# ARP Table
> arp -a

# Routing Table
> route print
````

**Enumerating Protections**

Most modern environments have some sort of anti-virus or Endpoint Detection and Response (EDR) service running to monitor, alert on, and block threats proactively. These tools may interfere with the enumeration process.

Many organizations utilize some sort of application whitelisting solution to control what types of applications and files certain users can run. This may be used to attempt to block non-admin users from running cmd.exe or powershell.exe or other binaries and file types not needed for their day-to-day work. A popular solution offered by Microsoft is AppLocker. We can use the GetAppLockerPolicy cmdlet to enumerate the local, effective (enforced), and domain AppLocker policies.

There are ways to deal with these, and enumerating the protections in use can help us modify our tools in a lab environment and test them before using them against a client system. Some EDR tools detect on or even block usage of common binaries such as net.exe, tasklist, etc. Organizations may restrict what binaries a user can run or immediately flag suspicious activities, such as an accountant's machine showing specific binaries being run via cmd.exe.
````
# Check Windows Defender Status
> Get-MpComputerStatus

# List AppLocker Rules
> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Test AppLocker Policy
> Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
````

## Initial Enumeration

During an assessment, we may gain a low-privileged shell on a Windows host (domain-joined or not) and need to perform privilege escalation to further our access. Fully compromising the host may gain us access to sensitive files/file shares, grant us the ability to capture traffic to obtain more credentials, or obtain credentials that can help further our access or even escalate directly to Domain Admin in an Active Directory environment.

> The highly privileged NT AUTHORITY\SYSTEM account, or LocalSystem account which is a highly privileged account with more privileges than a local administrator account and is used to run most Windows services.

> The built-in local administrator account. Some organizations disable this account, but many do not. It is not uncommon to see this account reused across multiple systems in a client environment.

> Another local account that is a member of the local Administrators group. Any account in this group will have the same privileges as the built-in administrator account.

> A standard (non-privileged) domain user who is part of the local Administrators group.

> A domain admin (highly privileged in the Active Directory environment) that is part of the local Administrators group.

**Key Data Points**

- **OS name**: Knowing the type of Windows OS (workstation or server) and level (Windows 7 or 10, Server 2008, 2012, 2016, 2019, etc.) will give us an idea of the types of tools that may be available (such as the PowerShell version), or lack thereof on legacy systems. This would also identify the operating system version for which there may be public exploits available.

- **Version**: As with the OS version, there may be public exploits that target a vulnerability in a specific version of Windows. Windows system exploits can cause system instability or even a complete crash. Be careful running these against any production system, and make sure you fully understand the exploit and possible ramifications before running one.

- **Running Services**: Knowing what services are running on the host is important, especially those running as NT AUTHORITY\SYSTEM or an administrator-level account. A misconfigured or vulnerable service running in the context of a privileged account can be an easy win for privilege escalation.

**System Information**
````
# Tasklist
> tasklist /svc

# Display All Environment Variables
> set

# Detailed Configuration Information
> systeminfo

# Patches and Updates
> wmic qfe
> Get-HotFix | ft -AutoSize

# Installed Programs
> wmic product get name
> Get-WmiObject -Class Win32_Product |  select Name, Version

# Display Running Processes
> netstat -ano
````
**User & Group Information**

Users are often the weakest link in an organization, especially when systems are configured and patched well. It is essential to gain an understanding of the users and groups on the system, members of specific groups that can provide us with admin level access, the privileges our current user has, password policy information, and any logged on users that we may be able to target.
````
# Logged-In Users
> query user

# Current User
> echo %USERNAME%
> whoami

# Current User Privileges
> whoami /priv

# Current User Group Information
> whoami /groups

# Get All Users
> net user

# Get All Groups
> net localgroup

# Details About a Group
> net localgroup administrators

# Get Password Policy & Other Account Information
> net accounts
````

## Communication with Processes

One of the best places to look for privilege escalation is the processes that are running on the system. Even if a process is not running as an administrator, it may lead to additional privileges. The most common example is discovering a web server like IIS or XAMPP running on the box, placing an aspx/php shell on the box, and gaining a shell as the user running the web server. Generally, this is not an administrator but will often have the SeImpersonate token, allowing for Rogue/Juicy/Lonely Potato to provide SYSTEM permissions.

**Access Tokens**

In Windows, access tokens are used to describe the security context (security attributes or rules) of a process or thread. The token includes information about the user account's identity and privileges related to a specific process or thread. When a user authenticates to a system, their password is verified against a security database, and if properly authenticated, they will be assigned an access token. Every time a user interacts with a process, a copy of this token will be presented to determine their privilege level.

**Enumerating Network Services**

The netstat command will display active TCP and UDP connections which will give us a better idea of what services are listening on which port(s) both locally and accessible to the outside.
````
# Display Active Network Connections
> netstat -ano
````
The main thing to look for with Active Network Connections are entries listening on loopback addresses (127.0.0.1 and ::1) that are not listening on the IP Address (10.129.43.8) or broadcast (0.0.0.0, ::/0). The reason for this is network sockets on localhost are often insecure due to the thought that "they aren't accessible to the network." 

One of the best examples of this type of privilege escalation is the Splunk Universal Forwarder, installed on endpoints to send logs into Splunk. The default configuration of Splunk did not have any authentication on the software and allowed anyone to deploy applications, which could lead to code execution. Again, the default configuration of Splunk was to run it as SYSTEM$ and not a low privilege user. 

**Named Pipes**

The other way processes communicate with each other is through Named Pipes. Pipes are essentially files stored in memory that get cleared out after being read. Cobalt Strike uses Named Pipes for every command (excluding BOF). Essentially the workflow looks like this:
- Beacon starts a named pipe of \.\pipe\msagent_12
- Beacon starts a new process and injects command into that process directing output to \.\pipe\msagent_12
- Server displays what was written into \.\pipe\msagent_12

Cobalt Strike did this because if the command being ran got flagged by antivirus or crashed, it would not affect the beacon (process running the command). Often, Cobalt Strike users will change their named pipes to masquerade as another program. One of the most common examples is mojo instead of msagent.

Pipes are used for communication between two applications or processes using shared memory. There are two types of pipes, named pipes and anonymous pipes. An example of a named pipe is \\.\PipeName\\ExampleNamedPipeServer. Windows systems use a client-server implementation for pipe communication. In this type of implementation, the process that creates a named pipe is the server, and the process communicating with the named pipe is the client. Named pipes can communicate using half-duplex, or a one-way channel with the client only being able to write data to the server, or duplex, which is a two-way communication channel that allows the client to write data over the pipe, and the server to respond back with data over that pipe. Every active connection to a named pipe server results in the creation of a new named pipe. These all share the same pipe name but communicate using a different data buffer.

````
# Listing Named Pipes with Pipelist
> pipelist.exe /accepteula

# Listing Named Pipes with PowerShell
>  gci \\.\pipe\
````
After obtaining a listing of named pipes, we can use Accesschk to enumerate the permissions assigned to a specific named pipe by reviewing the Discretionary Access List (DACL), which shows us who has the permissions to modify, write, read, or execute a resource.
````
# Reviewing LSASS Named Pipe Permissions
> accesschk.exe /accepteula \\.\Pipe\lsass -v
\\.\Pipe\lsass
  Untrusted Mandatory Level [No-Write-Up]
  RW Everyone
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        SYNCHRONIZE
        READ_CONTROL
  RW NT AUTHORITY\ANONYMOUS LOGON
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        SYNCHRONIZE
        READ_CONTROL
  RW APPLICATION PACKAGE AUTHORITY\Your Windows credentials
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        SYNCHRONIZE
        READ_CONTROL
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS
````
From the output above, we can see that only administrators have full access to the LSASS process, as expected. This WindscribeService Named Pipe Privilege Escalation is a great example. Using accesschk we can search for all named pipes that allow write access with a command such as accesschk.exe -w \pipe\* -v and notice that the WindscribeService named pipe allows READ and WRITE access to the Everyone group, meaning all authenticated users.
````
# Checking WindscribeService Named Pipe Permissions
> accesschk.exe -accepteula -w \pipe\WindscribeService -v

\\.\Pipe\WindscribeService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
````
