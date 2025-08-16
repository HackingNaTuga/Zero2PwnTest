# Network Poisoning Attacks (Sniffing out a Foothold)

In this section will cover:
- LLMNR/NBT-NS Poisoning - from Linux
- LLMNR/NBT-NS Poisoning - from Windows

## LLMNR/NBT-NS Poisoning - from Linux

**LLMNR & NBT-NS Primer**

Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails. If a machine attempts to resolve a host but DNS resolution fails, typically, the machine will try to ask all other machines on the local network for the correct host address via LLMNR. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. It uses port 5355 over UDP natively. If LLMNR fails, the NBT-NS will be used. NBT-NS identifies systems on a local network by their NetBIOS name. NBT-NS utilizes port 137 over UDP.

The kicker here is that when LLMNR/NBT-NS are used for name resolution, ANY host on the network can reply. This is where we come in with Responder to poison these requests. With network access, we can spoof an authoritative name resolution source ( in this case, a host that's supposed to belong in the network segment ) in the broadcast domain by responding to LLMNR and NBT-NS traffic as if they have an answer for the requesting host. This poisoning effort is done to get the victims to communicate with our system by pretending that our rogue system knows the location of the requested host. If the requested host requires name resolution or authentication actions, we can capture the NetNTLM hash and subject it to an offline brute force attack in an attempt to retrieve the cleartext password. The captured authentication request can also be relayed to access another host or used against a different protocol (such as LDAP) on the same host. LLMNR/NBNS spoofing combined with a lack of SMB signing can often lead to administrative access on hosts within a domain.

**Quick Example - LLMNR/NBT-NS Poisoning**
- A host attempts to connect to the print server at \\print01.domain, but accidentally types in \\printer01.domain.
- The DNS server responds, stating that this host is unknown.
- The host then broadcasts out to the entire local network asking if anyone knows the location of \\printer01.domain.
- The attacker (us with Responder running) responds to the host stating that it is the \\printer01.domain that the host is looking for.
- The host believes this reply and sends an authentication request to the attacker with a username and NTLMv2 password hash.
- This hash can then be cracked offline or used in an SMB Relay attack if the right conditions exist.

### Methodology

We are performing these actions to collect authentication information sent over the network in the form of NTLMv1 and NTLMv2 password hashes. NTLMv1 and NTLMv2 are authentication protocols that utilize the LM or NT hash. We will then take the hash and attempt to crack them offline using tools such as Hashcat or John with the goal of obtaining the account's cleartext password to be used to gain an initial foothold or expand our access within the domain if we capture a password hash for an account with more privileges than an account that we currently possess.

Several tools can be used to attempt LLMNR & NBT-NS poisoning:

| Tool       | Description                                                                 |
| ---------- | --------------------------------------------------------------------------- |
| Responder  | Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions. |
| Inveigh    | Inveigh is a cross-platform MITM platform that can be used for spoofing and poisoning attacks. |
| Metasploit | Metasploit has several built-in scanners and spoofing modules made to deal with poisoning attacks. |

Responder is written in Python and typically used on a Linux attack host, though there is a .exe version that works on Windows. Inveigh is written in both C# and PowerShell (considered legacy). Both tools can be used to attack the following protocols:
- LLMNR
- DNS
- MDNS
- NBNS
- DHCP
- ICMP
- HTTP
- HTTPS
- SMB
- LDAP
- WebDAV
- Proxy Auth

Responder also has support for:
- MSSQL
- DCE-RPC
- FTP, POP3, IMAP, and SMTP auth

### Responder

The -A flag puts us into analyze mode, allowing us to see NBT-NS, BROWSER, and LLMNR requests in the environment without poisoning any responses. We must always supply either an interface or an IP. Some common options we'll typically want to use are -wf; this will start the WPAD rogue proxy server, while -f will attempt to fingerprint the remote host operating system and version. We can use the -v flag for increased verbosity if we are running into issues, but this will lead to a lot of additional data printed to the console. Other options such as -F and -P can be used to force NTLM or Basic authentication and force proxy authentication, but may cause a login prompt, so they should be used sparingly. The use of the -w flag utilizes the built-in WPAD proxy server. This can be highly effective, especially in large organizations, because it will capture all HTTP requests by any users that launch Internet Explorer if the browser has Auto-detect settings enabled.

If you are successful and manage to capture a hash, Responder will print it out on screen and write it to a log file per host located in the **/usr/share/responder/logs** directory. Hashes are saved in the format **(MODULE_NAME)-(HASH_TYPE)-(CLIENT_IP).txt**, and one hash is printed to the console and stored in its associated log file unless -v mode is enabled. For example, a log file may look like SMB-NTLMv2-SSP-172.16.5.25.
````bash
$ sudo responder -I <Interface>
````

**Cracking an NTLMv2 Hash With Hashcat**
````bash
$ hashcat -m 5600 <hash> /usr/share/wordlists/rockyou.txt
````

## LLMNR/NBT-NS Poisoning - from Windows

LLMNR & NBT-NS poisoning is possible from a Windows host as well. In the last section, we utilized Responder to capture hashes. This section will explore the tool Inveigh and attempt to capture another set of credentials.

**Inveigh - Overview**

The tool Inveigh works similar to Responder, but is written in PowerShell and C#. Inveigh can listen to IPv4 and IPv6 and several other protocols, including LLMNR, DNS, mDNS, NBNS, DHCPv6, ICMPv6, HTTP, HTTPS, SMB, LDAP, WebDAV, and Proxy Auth. 

**Inveigh.ps1**

````powershell
# Import Module Inveigh.ps1
> Import-Module .\Inveigh.ps1

# List all parameters
> (Get-Command Invoke-Inveigh).Parameters

# Start Poisoning
> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
````

**Inveigh.exe**

The PowerShell version of Inveigh is the original version and is no longer updated. The tool author maintains the C# version, which combines the original PoC C# code and a C# port of most of the code from the PowerShell version. 
````powershell
# Start Poisoning
> .\Inveigh.exe
````
The options with a [+] are default and enabled by default and the ones with a [ ] before them are disabled. The running console output also shows us which options are disabled and, therefore, responses are not being sent (mDNS in the above example). We can also see the message Press ESC to enter/exit interactive console, which is very useful while running the tool. The console gives us access to captured credentials/hashes, allows us to stop Inveigh, and more.

We can hit the esc key to enter the console while Inveigh is running.
````powershell
# List all fuctions
> HELP

# View unique captured hashes
> GET NTLMV2UNIQUE

# View usernames
> GET NTLMV2USERNAMES
````


