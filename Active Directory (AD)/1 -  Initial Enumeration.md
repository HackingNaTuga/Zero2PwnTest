# Initial Enumeration

In this section will cover:
- External Recon and Enumeration Principles
- Initial Enumeration of the domain

**Active Directory Explained**

Active Directory (AD) is a directory service for Windows enterprise environments that was officially implemented in 2000 with the release of Windows Server 2000 and has been incrementally improved upon with the release of each subsequent server OS since. AD is based on the protocols x.500 and LDAP that came before it and still utilizes these protocols in some form today. It is a distributed, hierarchical structure that allows for centralized management of an organization’s resources, including users, computers, groups, network devices and file shares, group policies, devices, and trusts. AD provides authentication, accounting, and authorization functions within a Windows enterprise environment. 

## External Recon and Enumeration Principles

It can be beneficial to perform external reconnaissance of your target. This can serve many different functions, such as:
- Validating information provided to you in the scoping document from the client
- Ensuring you are taking actions against the appropriate scope when working remotely
- Looking for any information that is publicly accessible that can affect the outcome of your test, such as leaked credentials

**What Are We Looking For?**

When conducting our external reconnaissance, there are several key items that we should be looking for. This information may not always be publicly accessible, but it would be prudent to see what is out there. If we get stuck during a penetration test, looking back at what could be obtained through passive recon can give us that nudge needed to move forward, such as password breach data that could be used to access a VPN or other externally facing service. The table below highlights the "What" in what we would be searching for during this phase of our engagement.

| Data Point        | Description |
| ----------------- | ----------- |
| IP Space          | Valid ASN for our target, netblocks in use for the organization's public-facing infrastructure, cloud presence and the hosting providers, DNS record entries, etc. |
| Domain Information | Based on IP data, DNS, and site registrations. Who administers the domain? Are there any subdomains tied to our target? Are there any publicly accessible domain services present? (Mailservers, DNS, Websites, VPN portals, etc.) Can we determine what kind of defenses are in place? (SIEM, AV, IPS/IDS in use, etc.) |
| Schema Format     | Can we discover the organization's email accounts, AD usernames, and even password policies? Anything that will give us information we can use to build a valid username list to test external-facing services for password spraying, credential stuffing, brute forcing, etc. |
| Data Disclosures  | For data disclosures we will be looking for publicly accessible files ( .pdf, .ppt, .docx, .xlsx, etc. ) for any information that helps shed light on the target. For example, any published files that contain intranet site listings, user metadata, shares, or other critical software or hardware in the environment (credentials pushed to a public GitHub repo, the internal AD username format in the metadata of a PDF, for example.) |
| Breach Data       | Any publicly released usernames, passwords, or other critical information that can help an attacker gain a foothold. |


**Where Are We Looking?**

Our list of data points above can be gathered in many different ways. There are many different websites and tools that can provide us with some or all of the information above that we could use to obtain information vital to our assessment. The table below lists a few potential resources and examples that can be used.

| Resource                   | Examples |
| -------------------------- | -------- |
| ASN / IP registrars        | IANA, arin for searching the Americas, RIPE for searching in Europe, BGP Toolkit |
| Domain Registrars & DNS    | Domaintools, PTRArchive, ICANN, manual DNS record requests against the domain in question or against well known DNS servers, such as 8.8.8.8. |
| Social Media               | Searching Linkedin, Twitter, Facebook, your region's major social media sites, news articles, and any relevant info you can find about the organization. |
| Public-Facing Company Websites | Often, the public website for a corporation will have relevant info embedded. News articles, embedded documents, and the "About Us" and "Contact Us" pages can also be gold mines. |
| Cloud & Dev Storage Spaces | GitHub, AWS S3 buckets & Azure Blog storage containers, Google searches using "Dorks" |
| Breach Data Sources        | HaveIBeenPwned to determine if any corporate email accounts appear in public breach data, Dehashed to search for corporate emails with cleartext passwords or hashes we can try to crack offline. We can then try these passwords against any exposed login portals (Citrix, RDS, OWA, 0365, VPN, VMware Horizon, custom applications, etc.) that may use AD authentication. |

ASN
- https://bgp.he.net/

DNS
- https://whois.domaintools.com/
- https://viewdns.info/

Public Data
- LinkedIn, Indeed.com, and Glassdoor
- https://github.com/trufflesecurity/truffleHog
- https://buckets.grayhatwarfare.com/
- filetype:pdf inurl:"domain"
- intext:"@<domain>" inurl:"domain"
- https://github.com/initstring/linkedin2username
- http://dehashed.com/

## Initial Enumeration of the domain

**Setting Up**

For this first portion of the test, we are starting on an attack host placed inside the network for us. This is one common way that a client might select for us to perform an internal penetration test. A list of the types of setups a client may choose for testing includes:
- A penetration testing distro (typically Linux) as a virtual machine in their internal infrastructure that calls back to a jump host we control over VPN, and we can SSH into.
- A physical device plugged into an ethernet port that calls back to us over VPN, and we can SSH into.
- A physical presence at their office with our laptop plugged into an ethernet port.
- A Linux VM in either Azure or AWS with access to the internal network that we can SSH into using public key authentication and our public IP address whitelisted.
- VPN access into their internal network (a bit limiting because we will not be able to perform certain attacks such as LLMNR/NBT-NS Poisoning).
- From a corporate laptop connected to the client's VPN.
- On a managed workstation (typically Windows), physically sitting in their office with limited or no internet access or ability to pull in tools. They may also elect this option but give you full internet access, local admin, and put endpoint protection into monitor mode so you can pull in tools at will.
- On a VDI (virtual desktop) accessed using Citrix or the like, with one of the configurations described for the managed workstation typically accessible over VPN either remotely or from a corporate laptop.

The client may also choose from a "grey box" approach where they give us just a list of in-scope IP addresses/CIDR network ranges, or "black box" where we have to plug in and do all discovery blindly using various techniques. Finally, they can choose either evasive, non-evasive, or hybrid evasive (starting "quiet" and slowly getting louder to see what threshold we are detected at and then switching to non-evasive testing. They may also elect to have us start with no credentials or from the perspective of a standard domain user.

**Tasks**

Our tasks to accomplish for this section are:
- Enumerate the internal network, identifying hosts, critical services, and potential avenues for a foothold.
- This can include active and passive measures to identify users, hosts, and vulnerabilities we may be able to take advantage of to further our access.
- Document any findings we come across for later use. Extremely important!

Below are some of the key data points that we should be looking for at this time and noting down into our notetaking tool of choice and saving scan/tool output to files whenever possible.

**Key Data Points**
| Data Point                  | Description |
| --------------------------- | ----------- |
| AD Users                    | We are trying to enumerate valid user accounts we can target for password spraying. |
| AD Joined Computers         | Key Computers include Domain Controllers, file servers, SQL servers, web servers, Exchange mail servers, database servers, etc. |
| Key Services                | Kerberos, NetBIOS, LDAP, DNS |
| Vulnerable Hosts and Services | Anything that can be a quick win. (a.k.a an easy host to exploit and gain a foothold) |

### Methodology

We will start with passive identification of any hosts in the network, followed by active validation of the results to find out more about each host (what services are running, names, potential vulnerabilities, etc.). Once we know what hosts exist, we can proceed with probing those hosts, looking for any interesting data we can glean from them. After we have accomplished these tasks, we should stop and regroup and look at what info we have. At this time, we'll hopefully have a set of credentials or a user account to target for a foothold onto a domain-joined host or have the ability to begin credentialed enumeration from our Linux attack host.

#### Identifying Hosts

First, let's take some time to listen to the network and see what's going on. We can use Wireshark and TCPDump to "put our ear to the wire" and see what hosts and types of network traffic we can capture. This is particularly helpful if the assessment approach is "black box." We notice some ARP requests and replies, MDNS, and other basic layer two packets (since we are on a switched network, we are limited to the current broadcast domain) some of which we can see below. This is a great start that gives us a few bits of information about the customer's network setup.

If we are on a host without a GUI (which is typical), we can use tcpdump, net-creds, and NetMiner, etc., to perform the same functions. We can also use tcpdump to save a capture to a .pcap file, transfer it to another host, and open it in Wireshark.

````bash
$ sudo tcpdump -i <interface>
````
As a note for testing, it's always a good idea to save the PCAP traffic you capture. You can review it again later to look for more hints, and it makes for great additional information to include while writing your reports.

Our first look at network traffic pointed us to a couple of hosts via MDNS and ARP. Now let's utilize a tool called **Responder** to analyze network traffic and determine if anything else in the domain pops up.

**Responder** is a tool built to listen, analyze, and poison LLMNR, NBT-NS, and MDNS requests and responses. It has many more functions, but for now, all we are utilizing is the tool in its Analyze mode. This will passively listen to the network and not send any poisoned packets. We'll cover this tool more in-depth in later sections.

````bash
sudo responder -I <interface> -A
````
Our passive checks have given us a few hosts to note down for a more in-depth enumeration. Now let's perform some active checks starting with a quick ICMP sweep of the subnet using **fping**.

**Fping** provides us with a similar capability as the standard ping application in that it utilizes ICMP requests and replies to reach out and interact with a host. Where fping shines is in its ability to issue ICMP packets against a list of multiple hosts at once and its scriptability.
Here we'll start fping with a few flags: a to show targets that are alive, s to print stats at the end of the scan, g to generate a target list from the CIDR network, and q to not show per-target results.
````bash
$ fping -asgq <IP>/<mask>
````
Now that we have a list of active hosts within our network, we can enumerate those hosts further. We are looking to determine what services each host is running, identify critical hosts such as Domain Controllers and web servers, and identify potentially vulnerable hosts to probe later. With our focus on AD, after doing a broad sweep, it would be wise of us to focus on standard protocols typically seen accompanying AD services, such as DNS, SMB, LDAP, and Kerberos name a few. Below is a quick example of a simple **Nmap** scan.
````bash
sudo nmap -v -A -iL hosts.txt -oN host_enum
````

#### Identifying Users

We will need to find a way to establish a foothold in the domain by either obtaining clear text credentials or an NTLM password hash for a user, a SYSTEM shell on a domain-joined host, or a shell in the context of a domain user account. Obtaining a valid user with credentials is critical in the early stages of an internal penetration test. This access (even at the lowest level) opens up many opportunities to perform enumeration and even attacks.

**Kerbrute - Internal AD Username Enumeration**

**Kerbrute** can be a stealthier option for domain account enumeration. It takes advantage of the fact that Kerberos pre-authentication failures often will not trigger logs or alerts. We will use Kerbrute in conjunction with the jsmith.txt or jsmith2.txt user lists from Insidetrust. This repository contains many different user lists that can be extremely useful when attempting to enumerate users when starting from an unauthenticated perspective. We can point Kerbrute at the DC we found earlier and feed it a wordlist.
````bash
$ kerbrute userenum -d <domain> --dc <IP_DC> jsmith.txt -o valid_ad_users
````

#### Identifying Potential Vulnerabilities

The local system account NT AUTHORITY\SYSTEM is a built-in account in Windows operating systems. It has the highest level of access in the OS and is used to run most Windows services. It is also very common for third-party services to run in the context of this account by default. A SYSTEM account on a domain-joined host will be able to enumerate Active Directory by impersonating the computer account, which is essentially just another kind of user account. Having SYSTEM-level access within a domain environment is nearly equivalent to having a domain user account.

There are several ways to gain SYSTEM-level access on a host, including but not limited to:
- Remote Windows exploits such as MS08-067, EternalBlue, or BlueKeep.
- Abusing a service running in the context of the SYSTEM account, or abusing the service account SeImpersonate privileges using Juicy Potato. This type of attack is possible on older Windows OS' but not always possible with Windows Server 2019.
- Local privilege escalation flaws in Windows operating systems such as the Windows 10 Task Scheduler 0-day.
- Gaining admin access on a domain-joined host with a local account and using Psexec to launch a SYSTEM cmd window

By gaining SYSTEM-level access on a domain-joined host, you will be able to perform actions such as, but not limited to:
- Enumerate the domain using built-in tools or offensive tools such as BloodHound and PowerView.
- Perform Kerberoasting / ASREPRoasting attacks within the same domain.
- Run tools such as Inveigh to gather Net-NTLMv2 hashes or perform SMB relay attacks.
- Perform token impersonation to hijack a privileged domain user account.
- Carry out ACL attacks.
