# Services Enumeration

Let's list several dangerous services and configurations.

## FTP
The File Transfer Protocol (FTP) is one of the oldest protocols on the Internet. The FTP runs within the application layer of the TCP/IP protocol stack. Thus, it is on the same layer as HTTP or POP. These protocols also work with the support of browsers or email clients to perform their services. There are also special FTP programs for the File Transfer Protocol.
In an FTP connection, two channels are opened. First, the client and server establish a control channel through TCP port 21. The client sends commands to the server, and the server returns status codes. Then both communication participants can establish the data channel via TCP port 20. This channel is used exclusively for data transmission, and the protocol watches for errors during this process. If a connection is broken off during transmission, the transport can be resumed after re-established contact.
We also need to know that FTP is a clear-text protocol that can sometimes be sniffed if conditions on the network are right.

**TFTP**
Trivial File Transfer Protocol (TFTP) is simpler than FTP and performs file transfers between client and server processes. However, it does not provide user authentication and other valuable features supported by FTP. In addition, while FTP uses TCP, TFTP uses UDP, making it an unreliable protocol and causing it to use UDP-assisted application layer recovery.

Let us take a look at a few commands of TFTP and FTP:
| COMMAND | DESCRIPTION |
|:-------:|:------------:|
| connect | Sets the remote host, and optionally the port, for file transfers. |
| get     | Transfers a file or set of files from the remote host to the local host. |
| put     | Transfers a file or set of files from the local host onto the remote host. |
| quit    | Exits tftp. |
| status  | Shows the current status of tftp, including the current transfer mode (ascii or binary), connection status, time-out value, and so on. |
| verbose | Turns verbose mode, which displays additional information during file transfer, on or off. |

Unlike the FTP client, TFTP does not have directory listing functionality.
**vsFTPd Config File**
````
$ cat /etc/vsftpd.conf | grep -v "#"
````
**FTPUSERS**
````
$ cat /etc/ftpusers
````
**Dangerous Settings**
There are many different security-related settings we can make on each FTP server. These can have various purposes, such as testing connections through the firewalls, testing routes, and authentication mechanisms. One of these authentication mechanisms is the anonymous user. This is often used to allow everyone on the internal network to share files and data without accessing each other's computers.

|     SETTING      |                             DESCRIPTION                             |
|:----------------:|:-------------------------------------------------------------------:|
| anonymous_enable=YES        | Allowing anonymous login?                                 |
| anon_upload_enable=YES      | Allowing anonymous to upload files?                       |
| anon_mkdir_write_enable=YES | Allowing anonymous to create new directories?             |
| no_anon_password=YES        | Do not ask anonymous for password?                        |
| anon_root=/home/username/ftp| Directory for anonymous.                                  |
| write_enable=YES            | Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE? |

**Anonymous Login**
````
$ ftp 10.129.14.136

Connected to 10.129.14.136.
220 "Welcome to the HTB Academy vsFTP service."
Name (10.129.14.136:cry0l1t3): anonymous

230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
````

**Recursive Listing**
````
ftp> ls -R
````

**Download a File**
````
ftp> get Important\ Notes.txt
````
**Download All Available Files**
````
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
````
**Upload a File**
````
ftp> put testupload.txt 
````

### Footprinting the Service

**NMAP**
````
sudo nmap -sV -p21 -sC -A 10.129.14.136
````
````
nc -nv 10.129.14.136 21
telnet 10.129.14.136 21
````

## SMB

Server Message Block (SMB) is a client-server protocol that regulates access to files and entire directories and other network resources such as printers, routers, or interfaces released for the network. Information exchange between different system processes can also be handled based on the SMB protocol.
Access rights are defined by Access Control Lists (ACL). They can be controlled in a fine-grained manner based on attributes such as execute, read, and full access for individual users or user groups. The ACLs are defined based on the shares and therefore do not correspond to the rights assigned locally on the server.

**Default Configuration**
````
$ cat /etc/samba/smb.conf | grep -v "#\|\;"
````

|         SETTING          |                                 DESCRIPTION                                 |
|:------------------------:|:---------------------------------------------------------------------------:|
| [sharename]              | The name of the network share.                                              |
| workgroup = WORKGROUP/DOMAIN | Workgroup that will appear when clients query.                           |
| path = /path/here/       | The directory to which user is to be given access.                          |
| server string = STRING   | The string that will show up when a connection is initiated.                |
| unix password sync = yes | Synchronize the UNIX password with the SMB password?                        |
| usershare allow guests = yes | Allow non-authenticated users to access defined share?                  |
| map to guest = bad user  | What to do when a user login request doesn't match a valid UNIX user?       |
| browseable = yes         | Should this share be shown in the list of available shares?                 |
| guest ok = yes           | Allow connecting to the service without using a password?                   |
| read only = yes          | Allow users to read files only?                                             |
| create mask = 0700       | What permissions need to be set for newly created files?                    |


**Dangerous Settings**

In that case, we will see what advantages and disadvantages the settings bring with them.

|         SETTING          |                                  DESCRIPTION                                   |
|:------------------------:|:------------------------------------------------------------------------------:|
| browseable = yes         | Allow listing available shares in the current share?                          |
| read only = no           | Forbid the creation and modification of files?                                |
| writable = yes           | Allow users to create and modify files?                                       |
| guest ok = yes           | Allow connecting to the service without using a password?                     |
| enable privileges = yes  | Honor privileges assigned to specific SID?                                    |
| create mask = 0777       | What permissions must be assigned to the newly created files?                 |
| directory mask = 0777    | What permissions must be assigned to the newly created directories?           |
| logon script = script.sh | What script needs to be executed on the user's login?                         |
| magic script = script.sh | Which script should be executed when the script gets closed?                  |
| magic output = script.out| Where the output of the magic script needs to be stored?                      |

**SMBclient - Connecting to the Share**

Now we can display a list (-L) of the server's shares with the smbclient command from our host. We use the so-called null session (-N), which is anonymous access without the input of existing users or valid passwords.
````
$ smbclient -N -L //10.129.14.128
````
**List files on a specific share folder**
````
$ smbclient //10.129.14.128/notes
````
**Download Files from SMB**
````
smb: \> get prep-prod.txt
smb: \> !cat prep-prod.txt
````
**Upload Files to SMB Share**
````
smb: \> put local_file [remote_file]
````

### Footprinting the Service

**Nmap**
````
$ sudo nmap 10.129.14.128 -sV -sC -p139,445
````
One of the handy tools for this is rpcclient. This is a tool to perform MS-RPC functions.
The Remote Procedure Call (RPC) is a concept and, therefore, also a central tool to realize operational and work-sharing structures in networks and client-server architectures. The communication process via RPC includes passing parameters and the return of a function value.

**RPCclient**
````
$ rpcclient -U "" 10.129.14.128
````

|        QUERY         |                                 DESCRIPTION                                  |
|:--------------------:|:----------------------------------------------------------------------------:|
| srvinfo              | Server information.                                                         |
| enumdomains          | Enumerate all domains that are deployed in the network.                     |
| querydominfo         | Provides domain, server, and user information of deployed domains.          |
| netshareenumall      | Enumerates all available shares.                                            |
| netsharegetinfo <share> | Provides information about a specific share.                            |
| enumdomusers         | Enumerates all domain users.                                                |
| queryuser <RID>      | Provides information about a specific user.                                 |
| querygroup <RID>     | Provide informations about a specific group.

**Brute Forcing User RIDs**
````
$ for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
````
**Enum4Linux-ng**
````
$ ./enum4linux-ng.py 10.129.14.128 -A`
````

## NFS

Network File System (NFS) is a network file system developed by Sun Microsystems and has the same purpose as SMB. Its purpose is to access file systems over a network as if they were local.
A significant advantage of NFSv4 over its predecessors is that only one UDP or TCP port 2049 is used to run the service, which simplifies the use of the protocol across firewalls.

**Default Configuration**
````
$ cat /etc/exports
````
The default exports file also contains some examples of configuring NFS shares.

|      OPTION        |                                                       DESCRIPTION                                                       |
|:------------------:|:------------------------------------------------------------------------------------------------------------------------:|
| rw                 | Read and write permissions.                                                                                             |
| ro                 | Read only permissions.                                                                                                  |
| sync               | Synchronous data transfer. (A bit slower)                                                                               |
| async              | Asynchronous data transfer. (A bit faster)                                                                              |
| secure             | Ports above 1024 will not be used.                                                                                      |
| insecure           | Ports above 1024 will be used.                                                                                          |
| no_subtree_check   | This option disables the checking of subdirectory trees.                                                                |
| root_squash        | Assigns all permissions to files of root UID/GID 0 to the UID/GID of anonymous, which prevents root from accessing files on an NFS mount. |

**Dangerous Settings**
|     OPTION      |                                                                                      DESCRIPTION                                                                                      |
|:---------------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| rw              | Read and write permissions.                                                                                                                                       |
| insecure        | Ports above 1024 will be used.                                                                                                                                    |
| nohide          | If another file system was mounted below an exported directory, this directory is exported by its own exports entry.                                             |
| no_root_squash  | All files created by root are kept with the UID/GID 0.                                                                                          

### Footprinting the Service

**NMAP**
````
$ sudo nmap 10.129.14.128 -p111,2049 -sV -sC
$ sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049
````
**Show Available NFS Shares**
````
$ showmount -e 10.129.14.128
````
**Mounting NFS Share**
````
$ mkdir target-NFS
$ sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
$ sudo mount -t nfs 10.129.14.128:/[target_share] ./target-NFS/ -o nolock
````
**List Contents with Usernames & Group Names**
````
$ ls -l mnt/nfs/
````
**List Contents with UIDs & GUIDs**
````
$ ls -n mnt/nfs/
````
**Unmounting**
````
$ sudo umount ./target-NFS
````

## DNS

Domain Name System (DNS) is an integral part of the Internet.
There are several types of DNS servers that are used worldwide:

- DNS root server
- Authoritative name server
- Non-authoritative name server
- Caching server
- Forwarding server
- Resolver

|     SERVER TYPE           |                                                                                                    DESCRIPTION                                                                                                     |
|:-------------------------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| DNS Root Server           | The root servers of the DNS are responsible for the top-level domains (TLD). As the last instance, they are only requested if the name server does not respond. Thus, a root server is a central interface between users and content on the Internet, as it links domain and IP address. The Internet Corporation for Assigned Names and Numbers (ICANN) coordinates the work of the root name servers. There are 13 such root servers around the globe. |
| Authoritative Nameserver  | Authoritative name servers hold authority for a particular zone. They only answer queries from their area of responsibility, and their information is binding. If an authoritative name server cannot answer a client's query, the root name server takes over at that point. Based on the country, company, etc., authoritative nameservers provide answers to recursive DNS nameservers, assisting in finding the specific web server(s). |
| Non-authoritative Nameserver | Non-authoritative name servers are not responsible for a particular DNS zone. Instead, they collect information on specific DNS zones themselves, which is done using recursive or iterative DNS querying. |
| Caching DNS Server        | Caching DNS servers cache information from other name servers for a specified period. The authoritative name server determines the duration of this storage.                                                       |
| Forwarding Server         | Forwarding servers perform only one function: they forward DNS queries to another DNS server.                                                                                                                      |
| Resolver                  | Resolvers are not authoritative DNS servers but perform name resolution locally in the computer or router.                                                                                                         |

Different DNS records are used for the DNS queries, which all have various tasks. Moreover, separate entries exist for different functions since we can set up mail servers and other servers for a domain.


| DNS RECORD |                                                                                                      DESCRIPTION                                                                                                       |
|:----------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| A          | Returns an IPv4 address of the requested domain as a result.                                                                                                                     |
| AAAA       | Returns an IPv6 address of the requested domain.                                                                                                                                 |
| MX         | Returns the responsible mail servers as a result.                                                                                                                                |
| NS         | Returns the DNS servers (nameservers) of the domain.                                                                                                                             |
| TXT        | This record can contain various information. The all-rounder can be used, e.g., to validate the Google Search Console or validate SSL certificates. In addition, SPF and DMARC entries are set to validate mail traffic and protect it from spam. |
| CNAME      | This record serves as an alias for another domain name. If you want the domain www.hackthebox.eu to point to the same IP as hackthebox.eu, you would create an A record for hackthebox.eu and a CNAME record for www.hackthebox.eu. |
| PTR        | The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names.                                                                    |
| SOA        | Provides information about the corresponding DNS zone and email address of the administrative contact.                                                                           |

**Default Configuration**
All DNS servers work with three different types of configuration files:

- local DNS configuration files
- zone files
- reverse name resolution files

**Local DNS Configuration**
````
# cat /etc/bind/named.conf.local
````
**Zone Files**
````
# cat /etc/bind/db.domain.com
````
The PTR records are responsible for the reverse translation of IP addresses into names, as we have already seen in the above table.

**Reverse Name Resolution Zone Files**
````
# cat /etc/bind/db.10.129.14
````

**Dangerous Settings**
|   OPTION         |                                           DESCRIPTION                                           |
|:----------------:|:-----------------------------------------------------------------------------------------------:|
| allow-query      | Defines which hosts are allowed to send requests to the DNS server.                            |
| allow-recursion  | Defines which hosts are allowed to send recursive requests to the DNS server.                  |
| allow-transfer   | Defines which hosts are allowed to receive zone transfers from the DNS server.                 |
| zone-statistics  | Collects statistical data of zones.                                                            |

### Footprinting the Service

**DIG - NS Query**
````
$ dig ns google.com @server_ip
````
**DIG - Version Query**
````
$ dig CH TXT version.bind IP
````
**DIG - ANY Query**
````
$ dig any google.com @nameserver
````
**DIG - AXFR Zone Transfer**
````
$ dig axfr google.com @nameserver
````
**Subdomain Brute Forcing**
````
$ for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.google.com @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done

dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt google.com
subfinder -d domain
python3 sublist3r.py -d <domain-name> -n
ffuf -u "http://FUZZ.domain" -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt
````

## SMTP

The Simple Mail Transfer Protocol (SMTP) is a protocol for sending emails in an IP network. It can be used between an email client and an outgoing mail server or between two SMTP servers. SMTP is often combined with the IMAP or POP3 protocols, which can fetch emails and send emails. 
By default, SMTP servers accept connection requests on port 25. However, newer SMTP servers also use other ports such as TCP port 587. This port is used to receive mail from authenticated users/servers, usually using the STARTTLS command to switch the existing plaintext connection to an encrypted connection.

**Default Configuration**
````
$ cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"
````
The sending and communication are also done by special commands that cause the SMTP server to do what the user requires.

|   COMMAND   |                                                                 DESCRIPTION                                                                 |
|:-----------:|:-------------------------------------------------------------------------------------------------------------------------------------------:|
| AUTH PLAIN  | AUTH is a service extension used to authenticate the client.                                                                               |
| HELO        | The client logs in with its computer name and thus starts the session.                                                                    |
| MAIL FROM   | The client names the email sender.                                                                                                         |
| RCPT TO     | The client names the email recipient.                                                                                                      |
| DATA        | The client initiates the transmission of the email.                                                                                        |
| RSET        | The client aborts the initiated transmission but keeps the connection between client and server.                                          |
| VRFY        | The client checks if a mailbox is available for message transfer.                                                                          |
| EXPN        | The client also checks if a mailbox is available for messaging with this command.                                                         |
| NOOP        | The client requests a response from the server to prevent disconnection due to time-out.                                                  |
| QUIT        | The client terminates the session.                                                                                                         |

**Telnet - HELO/EHLO**
````
$ telnet 10.129.14.128 25
Escape character is '^]'.
220 ESMTP Server 

HELO mail1.inlanefreight.htb
````
**Telnet - VRFY**
````
$ telnet 10.129.14.128 25
Escape character is '^]'.
220 ESMTP Server 

VRFY root
252 2.0.0 root
````
**Dangerous Settings**

Open Relay Configuration`
````
mynetworks = 0.0.0.0/0
````

### Footprinting the Service

**nmap**
````
$ sudo nmap 10.129.14.128 -sC -sV -p25
$ sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v
````

## IMAP / POP3

With the help of the Internet Message Access Protocol (IMAP), access to emails from a mail server is possible. Unlike the Post Office Protocol (POP3), IMAP allows online management of emails directly on the server and supports folder structures. Thus, it is a network protocol for the online management of emails on a remote server.

**IMAP Commands**

|         COMMAND          |                                                                                   DESCRIPTION                                                                                   |
|:------------------------:|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| 1 LOGIN username password | User's login.                                                                                                                                                                     |
| 1 LIST "" *              | Lists all directories.                                                                                                                                                            |
| 1 CREATE "INBOX"         | Creates a mailbox with a specified name.                                                                                                                                          |
| 1 DELETE "INBOX"         | Deletes a mailbox.                                                                                                                                                                |
| 1 RENAME "ToRead" "Important" | Renames a mailbox.                                                                                                                                                          |
| 1 LSUB "" *              | Returns a subset of names from the set of names that the User has declared as being active or subscribed.                                                                        |
| 1 SELECT INBOX           | Selects a mailbox so that messages in the mailbox can be accessed.                                                                                                                |
| 1 UNSELECT INBOX         | Exits the selected mailbox.                                                                                                                                                       |
| 1 FETCH <ID> all         | Retrieves data associated with a message in the mailbox.                                                                                                                          |
| 1 CLOSE                  | Removes all messages with the Deleted flag set.                                                                                                                                   |
| 1 LOGOUT                 | Closes the connection with the IMAP server.                                                                                                                                       |

**POP3 Commands**

|     COMMAND     |                                                      DESCRIPTION                                                      |
|:---------------:|:----------------------------------------------------------------------------------------------------------------------:|
| USER username   | Identifies the user.                                                                                                  |
| PASS password   | Authentication of the user using its password.                                                                        |
| STAT            | Requests the number of saved emails from the server.                                                                  |
| LIST            | Requests from the server the number and size of all emails.                                                            |
| RETR id         | Requests the server to deliver the requested email by ID.                                                              |
| DELE id         | Requests the server to delete the requested email by ID.                                                               |
| CAPA            | Requests the server to display the server capabilities.                                                                |
| RSET            | Requests the server to reset the transmitted information.                                                              |
| QUIT            | Closes the connection with the POP3 server.                                                                            |

**Dangerous Settings**

Nevertheless, configuration options that were improperly configured could allow us to obtain more information, such as debugging the executed commands on the service or logging in as anonymous, similar to the FTP service.
|         SETTING         |                                                                              DESCRIPTION                                                                               |
|:-----------------------:|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| auth_debug              | Enables all authentication debug logging.                                                                                                                             |
| auth_debug_passwords    | This setting adjusts log verbosity, the submitted passwords, and the scheme gets logged.                                                                               |
| auth_verbose            | Logs unsuccessful authentication attempts and their reasons.                                                                                                           |
| auth_verbose_passwords  | Passwords used for authentication are logged and can also be truncated.                                                                                                |
| auth_anonymous_username | This specifies the username to be used when logging in with the ANONYMOUS SASL mechanism.                                                                              |

### Footprinting the Service
By default, ports 110 and 995 are used for POP3, and ports 143 and 993 are used for IMAP. The higher ports (993 and 995) use TLS/SSL to encrypt the communication between the client and server.
````
$ sudo nmap 10.129.14.128 -sV -p110,143,993,995 -sC
````
**cURL**
````
$ curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd

* LIST (\HasNoChildren) "." Important
* LIST (\HasNoChildren) "." INBOX
````
**OpenSSL - TLS Encrypted Interaction POP3**
````
$ openssl s_client -connect 10.129.14.128:pop3s
````
**OpenSSL - TLS Encrypted Interaction IMAP**
````
$ openssl s_client -connect 10.129.14.128:imaps
````

## SNMP

Simple Network Management Protocol (SNMP) was created to monitor network devices. In addition, this protocol can also be used to handle configuration tasks and change settings remotely. SNMP-enabled hardware includes routers, switches, servers, IoT devices, and many other devices that can also be queried and controlled using this standard protocol. SNMP also transmits control commands using agents over UDP port 161.

**MIB**

A MIB is a text file in which all queryable SNMP objects of a device are listed in a standardized tree hierarchy. It contains at least one Object Identifier (OID), which, in addition to the necessary unique address and a name, also provides information about the type, access rights, and a description of the respective object.

**OID**

An OID represents a node in a hierarchical namespace. A sequence of numbers uniquely identifies each node, allowing the node's position in the tree to be determined. 

**Community Strings**

Community strings can be seen as passwords that are used to determine whether the requested information can be viewed or not. 

**Default Configuration**
````
$ cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'
````

**Dangerous Settings**
|         SETTINGS         |                                                                                   DESCRIPTION                                                                                   |
|:------------------------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| rwuser noauth            | Provides access to the full OID tree without authentication.                                                                                                                   |
| rwcommunity <community string> <IPv4 address>  | Provides access to the full OID tree regardless of where the requests were sent from.                                                                         |
| rwcommunity6 <community string> <IPv6 address> | Same access as with rwcommunity with the difference of using IPv6.                                                                                               |

### Footprinting the Service

**SNMPwalk**
````
$ snmpwalk -v2c -c public 10.129.14.128
````
**OneSixtyOne**
````
$ sudo apt install onesixtyone
$ onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.14.128
````
**Braa**
````
$ sudo apt install braa
$ braa <community string>@<IP>:.1.3.6.*   # Syntax
$ braa public@10.129.14.128:.1.3.6.*
````

## MySQL

MySQL is an open-source SQL relational database management system developed and supported by Oracle. A database is simply a structured collection of data organized for easy use and retrieval. 

**Default Configuration**
````
$ cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'
````
**Dangerous Settings**
|     SETTINGS     |                                                                                   DESCRIPTION                                                                                   |
|:----------------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| user             | Sets which user the MySQL service will run as.                                                                                                                                |
| password         | Sets the password for the MySQL user.                                                                                                                                         |
| admin_address    | The IP address on which to listen for TCP/IP connections on the administrative network interface.                                                                             |
| debug            | This variable indicates the current debugging settings                                                                                                                        |
| sql_warnings     | This variable controls whether single-row INSERT statements produce an information string if warnings occur.                                                                  |
| secure_file_priv | This variable is used to limit the effect of data import and export operations.                                                                                                |

### Footprinting the Service

**Scanning MySQL Server**
````
$ sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
````
**Connect to MySql Server**
````
$ mysql -u User -p -h IP
````

| Command | Descripton |
|:--------:|:----------:|
| mysql -u user -p password -h IP_address | Connect to the MySQL server. There should not be a space between the '-p' flag, and the password.|
| show databases; | Show all databases. |
| use database; | Select one of the existing databases.|
| show tables; | Show all available tables in the selected database.|
| show columns from table; | Show all columns in the selected table.|
| select * from table; | Show everything in the desired table.|
| select * from table where column = "string"; | Search for needed string in the desired table. |

## MSSQL

Microsoft SQL (MSSQL) is Microsoft's SQL-based relational database management system.

**MSSQL Clients**
| mssql-cli | SQL Server PowerShell | HeidiSQL | SQLPro | Impacket's mssqlclient.py | SQL Server Management Studio |
|-----------|------------------------|----------|--------|----------------------------|----------------------------|

**MSSQL Databases**
| Default System Database | Description |
|-----------------------------|-----------------|
| master                     | Tracks all system information for an SQL server instance |
| model                      | Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database created after changes to the model database |
| msdb                       | The SQL Server Agent uses this database to schedule jobs & alerts |
| tempdb                     | Stores temporary objects |
| resource                   | Read-only database containing system objects included with SQL server |

### Footprinting the Service

**NMAP**
````
$ sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
````
**Metasploit**
````
msf6 auxiliary(scanner/mssql/mssql_ping)
````
**Connecting with Mssqlclient.py**
````
$ python3 mssqlclient.py <USER>@<IP> -windows-auth
$ impacket-mssqlclient <USER>@<IP> -windows-auth
$ impacket-mssqlclient DOMAIN/<USER>@<IP> 
````

## Oracle TNS

The Oracle Transparent Network Substrate (TNS) server is a communication protocol that facilitates communication between Oracle databases and applications over networks. 
Each database or service has a unique entry in the tnsnames.ora file, containing the necessary information for clients to connect to the service. The entry consists of a name for the service, the network location of the service, and the database or service name that clients should use when connecting to the service. 
On the other hand, the listener.ora file is a server-side configuration file that defines the listener process's properties and parameters, which is responsible for receiving incoming client requests and forwarding them to the appropriate Oracle database instance.

### Footprint the service
**NMAP**
````
$ sudo nmap -p1521 -sV 10.129.204.235 --open
````
**SID Bruteforcing**
````
$ sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute
````
We can use the odat.py tool to perform a variety of scans to enumerate and gather information about the Oracle database services and its components. 
````
$ ./odat.py all -s 10.129.204.235
````
**SQLplus - Log In**
````
$ sqlplus scott/tiger@10.129.204.235/<SID>
````
**Oracle RDBMS - Interaction**
````
SQL> select table_name from all_tables;
SQL> select * from user_role_privs;
````
**Oracle RDBMS - Database Enumeration**
````
$ sqlplus <USER>/<PASS>@<IP>/<SID> as sysdba
SQL> select * from user_role_privs;
````
**Oracle RDBMS - Extract Password Hashes**
````
SQL> select name, password from sys.user$;
````
**Oracle RDBMS - File Upload**
````
$ echo "Oracle File Upload Test" > testing.txt
$ ./odat.py utlfile -s 10.129.204.235 -d <SID> -U <USER> -P <PASS> --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
````
ODAT Setup
````
https://github.com/quentinhardy/odat/releases
sudo apt-get install alien
get basic and sqlplus .rpm https://www.oracle.com/database/technologies/instant-client/linux-x86-64-downloads.html
sudo alien -i oracle-instantclient-basic-23.8.0.25.04-1.el9.x86_64.rpm
sudo alien -i oracle-instantclient-sqlplus-23.8.0.25.04-1.el9.x86_64.rpm
sudo sh -c "echo /usr/lib/oracle/23/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig
./odat-libc2.17-x86_64 all -s <IP> 
````

## IPMI

Intelligent Platform Management Interface (IPMI) is a set of standardized specifications for hardware-based host management systems used for system management and monitoring. It acts as an autonomous subsystem and works independently of the host's BIOS, CPU, firmware, and underlying operating system.

### Footprinting the Service

**NMAP**
````
$ sudo nmap -sU --script ipmi-version -p 623 <IP>
````
During internal penetration tests, we often find BMCs where the administrators have not changed the default password. Some unique default passwords to keep in our cheatsheets include:
| Product          | Username   | Password                                               |
|:------------------------:|:----------------:|:-------------------------------------------------------------:|
| Dell iDRAC             | root           | calvin                                                      |
| HP iLO                 | Administrator  | randomized 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI        | ADMIN          | ADMIN                                                       |

**Metasploit Dumping Hashes**
````
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes 
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts <IP>
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run
````
**Crack Hash**
````
echo "a0a113d8820000005cd66e:6f9686237cad0f01033f11247abafb272d888fe6" > hash2
hashcat hash2 /usr/share/wordlists/rockyou.txt
````


