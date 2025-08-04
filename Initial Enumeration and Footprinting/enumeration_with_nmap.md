# Enumeration with NMAP

------------------------------------------------------

## Host Discovery

When we need to conduct an internal penetration test for the entire network of a company, for example, then we should, first of all, get an overview of which systems are online that we can work with. To actively discover such systems on the network, we can use various Nmap host discovery options. There are many options Nmap provides to determine whether our target is alive or not. The most effective host discovery method is to use ICMP echo requests, which we will look into.

**Scan Network Range**
``` 
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```
|Scanning Options|	Description|
|:--------------:|:------------:|
|10.129.2.0/24	|Target network range.|
|-sn|	Disables port scanning.|
|-oA tnet|	Stores the results in all formats starting with the name 'tnet'.| 

**Scan IP List**
```
sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
```
-iL:	Performs defined scans against targets in provided 'hosts.lst' list.

**Scan Multiple IPs**
```
sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20| grep for | cut -d" " -f5
sudo nmap -sn -oA tnet 10.129.2.18-20| grep for | cut -d" " -f5
```

**Scan Single IP**
```
sudo nmap 10.129.2.18 -sn -oA host
```

If we disable port scan (-sn), Nmap automatically ping scan with ICMP Echo Requests (-PE). Once such a request is sent, we usually expect an ICMP reply if the pinging host is alive. The more interesting fact is that our previous scans did not do that because before Nmap could send an ICMP echo request, it would send an ARP ping resulting in an ARP reply.
We see here that Nmap does indeed detect whether the host is alive or not through the ARP request and ARP reply alone. To disable ARP requests and scan our target with the desired ICMP echo requests, we can disable ARP pings by setting the "--disable-arp-ping" option. Then we can scan our target again and look at the packets sent and received.
```
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping
```

## Port Scanning

After we have found out that our target is alive, we want to get a more accurate picture of the system. The information we need includes:

- Open ports and its services
- Service versions
- Information that the services provided
- Operating system

There are a total of 6 different states for a scanned port we can obtain:

|State	|Description|
|:------:|:---------|
|open|	This indicates that the connection to the scanned port has been established. These connections can be TCP connections, UDP datagrams as well as SCTP associations.|
|closed|	When the port is shown as closed, the TCP protocol indicates that the packet we received back contains an RST flag. This scanning method can also be used to determine if our target is alive or not.|
|filtered|	Nmap cannot correctly identify whether the scanned port is open or closed because either no response is returned from the target for the port or we get an error code from the target.|
|unfiltered|	This state of a port only occurs during the TCP-ACK scan and means that the port is accessible, but it cannot be determined whether it is open or closed.|
|open/filtered|	If we do not get a response for a specific port, Nmap will set it to that state. This indicates that a firewall or packet filter may protect the port.|
|closed/filtered	|This state only occurs in the IP ID idle scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall.|

**Stealth Scan**
````
sudo nmap 10.129.2.28 -sS
````
-sS: This means that nmap will only send a syn packet and will not wait for a response before evaluating another port.

**Full TCP Scan**
````
sudo nmap 10.129.2.28 -sT
````
-sT: Full Three-Way Handshake 

**Scanning Top 10 TCP Ports**
````
sudo nmap 10.129.2.28 --top-ports=10
````
**Specific Port**
````
sudo nmap 10.129.2.28 -p 21
````
**Multiple Ports**
````
sudo nmap 10.129.2.28 -p 21,22,80,445
````
**All Ports**
````
sudo nmap 10.129.2.28 -p-
sudo nmap 10.129.2.28 -p 1-65535
````
**Open UDP Ports**
````
sudo nmap 10.129.2.28 -F -sU
````

## Saving the Results

While we run various scans, we should always save the results. We can use these later to examine the differences between the different scanning methods we have used. Nmap can save the results in 3 different formats.

- Normal output (-oN) with the .nmap file extension
- Grepable output (-oG) with the .gnmap file extension
- XML output (-oX) with the .xml file extension

We can also specify the option (-oA) to save the results in all formats. **The command could look like this**:
````
sudo nmap 10.129.2.28 -p- -oA target
````

## Service Enumeration

For us, it is essential to determine the application and its version as accurately as possible. We can use this information to scan for known vulnerabilities and analyze the source code for that version if we find it. An exact version number allows us to search for a more precise exploit that fits the service and the operating system of our target.

It is recommended to perform a quick port scan first, which gives us a small overview of the available ports. This causes significantly less traffic, which is advantageous for us because otherwise we can be discovered and blocked by the security mechanisms. We can deal with these first and run a port scan in the background, which shows all open ports (-p-). We can use the version scan to scan the specific ports for services and their versions (-sV).

````
sudo nmap 10.129.2.28 -p- -sV
````
|Scanning Options|Description|
|:--------------:|:----------|
|10.129.2.28	|Scans the specified target.|
|-p-	|Scans all ports.|
|-sV	|Performs service version detection on specified ports.|

We can also increase the verbosity level (-v / -vv), which will show us the open ports directly when Nmap detects them.
````
sudo nmap 10.129.2.28 -p- -sV -v
````

## Scripting Engine

| **Category**  | **Description** |
|:-------------:|:---------------:|
| auth      | Determination of authentication credentials. |
| broadcast | Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans. |
| brute     | Executes scripts that try to log in to the respective service by brute-forcing with credentials. |
| default   | Default scripts executed by using the -sC option. |
| discovery | Evaluation of accessible services. |
| dos       | These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services. |
| exploit   | This category of scripts tries to exploit known vulnerabilities for the scanned port. |
| external  | Scripts that use external services for further processing. |
| fuzzer    | This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time. |
| intrusive | Intrusive scripts that could negatively affect the target system. |
| malware   | Checks if some malware infects the target system. |
| safe      | Defensive scripts that do not perform intrusive and destructive access. |
| version   | Extension for service detection. |
| vuln     | Identification of specific vulnerabilities. |

**Default Scripts**
````
sudo nmap <target> -sC
````
**Specific Scripts Category**
````
sudo nmap <target> --script <category>
````
**Defined Scripts**
````
sudo nmap <target> --script <script-name>,<script-name>,...
sudo nmap 10.129.2.28 -p 25 --script banner,smtp-commands
````
**Aggressive Scan**
````
sudo nmap 10.129.2.28 -p 80 -A
````
**Vuln Category**
````
sudo nmap 10.129.2.28 -p 80 -sV --script vuln 
````

## Flag Compilation

**Scanning Options**
| Nmap Option            | Description |
|:--------------------------:|:----------------------------:|
| 10.10.10.0/24              | Target network range. |
| -sn                        | Disables port scanning. |
| -Pn                        | Disables ICMP Echo Requests. |
| -n                         | Disables DNS Resolution. |
| -PE                        | Performs the ping scan by using ICMP Echo Requests against the target. |
| --packet-trace             | Shows all packets sent and received. |
| --reason                   | Displays the reason for a specific result. |
| --disable-arp-ping         | Disables ARP Ping Requests. |
| --top-ports=&lt;num&gt;     | Scans the specified top ports that have been defined as most frequent. |
| -p-                        | Scan all ports. |
| -p22-110                   | Scan all ports between 22 and 110. |
| -p22,25                    | Scans only the specified ports 22 and 25. |
| -F                         | Scans top 100 ports. |
| -sS                        | Performs a TCP SYN-Scan. |
| -sA                        | Performs a TCP ACK-Scan. |
| -sU                        | Performs a UDP Scan. |
| -sV                        | Scans the discovered services for their versions. |
| -sC                        | Perform a Script Scan with scripts that are categorized as "default". |
| --script &lt;script&gt;     | Performs a Script Scan by using the specified scripts. |
| -O                         | Performs an OS Detection Scan to determine the OS of the target. |
| -A                         | Performs OS Detection, Service Detection, and traceroute scans. |
| -D RND:5                   | Sets the number of random Decoys that will be used to scan the target. |
| -e                         | Specifies the network interface that is used for the scan. |
| -S 10.10.10.200            | Specifies the source IP address for the scan. |
| -g                         | Specifies the source port for the scan. |
| --dns-server &lt;ns&gt;     | DNS resolution is performed by using a specified name server. |

**Output Options**
| Nmap Option   | Description |
|:-----------------:|:----------------------------:|
| -oA filename      | Stores the results in all available formats starting with the name of "filename". |
| -oN filename      | Stores the results in normal format with the name "filename". |
| -oG filename      | Stores the results in "grepable" format with the name of "filename". |
| -oX filename      | Stores the results in XML format with the name of "filename". |

**Performance Options**
| Nmap Option                    | Description |
|:---------------------------------:|:----------------------------:|
| --max-retries &lt;num&gt;          | Sets the number of retries for scans of specific ports. |
| --stats-every=5s                  | Displays scan's status every 5 seconds. |
| -v / -vv                          | Displays verbose output during the scan. |
| --initial-rtt-timeout 50ms        | Sets the specified time value as initial RTT timeout. |
| --max-rtt-timeout 100ms           | Sets the specified time value as maximum RTT timeout. |
| --min-rate 300                    | Sets the number of packets that will be sent simultaneously. |
| -T &lt;0-5&gt;                       | Specifies the specific timing template. |

