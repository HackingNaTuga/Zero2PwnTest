## Host and Service Enumeration Cheat Sheet

### Host Discovery
````
$ nmap 192.168.1.1/24 -sn
$ nmap 192.168.1.1/24 -Pn
$ [msf](Jobs:0 Agents:1) post(multi/manage/autoroute) >> use post/multi/gather/ping_sweep
$ for i in $(seq 254); do ping 172.16.8.$i -c1 -W1 & done | grep from
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
$ nxc smb <FQDN/IP> -u '' -p '' --shares (Netexec shares enumerate with null session)
$ nxc smb <FQDN/IP> -u '<user>' -p '<password>' --shares (Netexec shares enumerate with user account)
$ enum4linux-ng <FQDN/IP> -A (SMB enumeration using enum4linux.)
$ rpcclient -U "" <FQDN/IP> (Interaction with the target using RPC with null session)
$ for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done (Brute Force RID)
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

### SMTP
````
$ sudo nmap 10.129.14.128 -sC -sV -p25
$ sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v (Verify if open-relay is open)
$ telnet <FQDN/IP> 25 (Connect to smtp service)
$ VRFY root (Verify if user exist)
````

### IMAP & POP3
````
$ sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
$ curl -k 'imaps://<FQDN/IP>' --user <user>:<password> (Log in to the IMAPS service using cURL.)
$ openssl s_client -connect <FQDN/IP>:imaps (Connect to the IMAPS service.)
$ openssl s_client -connect <FQDN/IP>:pop3s ( Connect to the POP3s service.)
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

### MSSQL
````
$ sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
$ python3 mssqlclient.py <USER>@<IP> -windows-auth
$ impacket-mssqlclient <USER>@<IP> -windows-auth
$ impacket-mssqlclient DOMAIN/<USER>@<IP>
$ impacket-mssqlclient '<user>:<pass>@<ip>' -windows-auth
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
````









