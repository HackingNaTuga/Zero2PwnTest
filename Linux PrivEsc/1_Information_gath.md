# Information Gathering

Here we will see ways to enumerate our host to obtain important information for our priv esc:
- Environment Enumeration
- Linux Services & Internals Enumeration
- Credential Hunting

## Environment Enumeration

When you gain initial shell access to the host, it is important to check several key details.

OS Version: Knowing the distribution (Ubuntu, Debian, FreeBSD, Fedora, SUSE, Red Hat, CentOS, etc.) will give you an idea of the types of tools that may be available. This would also identify the operating system version, for which there may be public exploits available.

Kernel Version: As with the OS version, there may be public exploits that target a vulnerability in a specific kernel version. Kernel exploits can cause system instability or even a complete crash. Be careful running these against any production system, and make sure you fully understand the exploit and possible ramifications before running one.

Running Services: Knowing what services are running on the host is important, especially those running as root. A misconfigured or vulnerable service running as root can be an easy win for privilege escalation. Flaws have been discovered in many common services such as Nagios, Exim, Samba, ProFTPd, etc. Public exploit PoCs exist for many of them, such as CVE-2016-9566, a local privilege escalation flaw in Nagios Core < 4.2.4.

Several helper scripts (such as LinPEAS and LinEnum) exist to assist with enumeration.
- https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS
- http://github.com/rebootuser/LinEnum

Typically we'll want to run a few basic commands to orient ourselves:
- whoami - what user are we running as
- id - what groups does our user belong to?
- hostname - what is the server named, can we gather anything from the naming convention?
- ifconfig or ip a - what subnet did we land in, does the host have additional NICs in other subnets?
- sudo -l - can our user run anything with sudo (as another user as root) without needing a password? This can sometimes be the easiest win and we can do something like sudo su and drop right into a root shell.

**Operative System & Kernel**
````
$ cat /etc/os-release
$ uname -a
$ cat /proc/version
````
**List Path & Environment Variables**
````
$ echo $PATH
$ env
````
**List shells**
````
$ cat /etc/shells
````
**Drives and any shares on the system & Mounted File Systems & Unmounted File Systems**
````
$ lsblk
$ lpstat
$ cat /etc/fstab
-------
$ df -h
$ cat /etc/fstab | grep -v "#" | column -t
````
**Network**
````
$ route
$ netstat -rn
$ netstat -ano
$ arp -a
$ ifconfig
````
**Existing Users and Which has Shell**

All users on the system are stored in the /etc/passwd file. The format gives us some information, such as:
- Username
- Password
- User ID (UID)
- Group ID (GID)
- User ID info
- Home directory
- Shell

````
$ cat /etc/passwd
$ cat /etc/passwd | cut -f1 -d:
$ grep "sh$" /etc/passwd
$ grep "sh$" /etc/passwd
$ ls /home
````
**Existing Groups & List members of a group**
````
$ cat /etc/group
$ getent group sudo
````
**All Hidden Files**
````
$ find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep <user>
````
**All Hidden Directories**
````
$ find / -type d -name ".*" -ls 2>/dev/null
````
**Temporary Files**
````
$ ls -l /tmp /var/tmp /dev/shm
````

## Linux Services & Internals Enumeration

When we talk about the internals, we mean the internal configuration and way of working, including integrated processes designed to accomplish specific tasks. So we start with the interfaces through which our target system can communicate.

**Network Interfaces**
````
$ ip a
$ ifconfig
````
**Hosts**
````
$ cat /etc/hosts
````
**User's Last Login & Logged In Users**
````
$ lastlog
$ w
````
**Command History**
````
$ history
$ find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
````
**Cron**
````
$ ls -la /etc/cron.daily/
````
**Proc**
````
$ find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"
````
**Installed Packages**
````
$ apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
````
**Sudo Version**
````
$ sudo -V
````
**Binaries**
````
$ ls -l /bin /usr/bin/ /usr/sbin/
````
````
$ for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done
````
**Configuration Files & Scripts**
````
$ find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null
$ find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"
````
**Running Services by User**
````
$ ps aux | grep root
````

## Credential Hunting

These may be found in configuration files (.conf, .config, .xml, etc.), shell scripts, a user's bash history file, backup (.bak) files, within database files or even in text files. Credentials may be useful for escalating to other users or even root, accessing databases and other systems within the environment.

**Wp-config Credentials**
````
$ grep 'DB_USER\|DB_PASSWORD' wp-config.php
````
**Config**
````
$  find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
````
**SSH Keys**
````
$  ls ~/.ssh
````

