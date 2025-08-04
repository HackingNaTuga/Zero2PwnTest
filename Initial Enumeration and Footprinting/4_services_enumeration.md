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
