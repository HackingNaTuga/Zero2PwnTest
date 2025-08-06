# Extracting Passwords from Linux Systems

Linux-based distributions support various authentication mechanisms. One of the most commonly used is Pluggable Authentication Modules (PAM). 
The pam_unix.so module uses standardized API calls from system libraries to update account information. The primary files it reads from and writes to are /etc/passwd and /etc/shadow. 

## Passwd file
The /etc/passwd file contains information about every user on the system and is readable by all users and services. Each entry in the file corresponds to a single user and consists of seven fields, which store user-related data in a structured format. These fields are separated by colons (:). As such, a typical entry may look something like this:
````
student:x:1000:1000:,,,:/home/student:/bin/bash
````

| Field           | Value             |
|-----------------|-------------------|
| Username        | student           |
| Password        | x                 |
| User ID         | 1000              |
| Group ID        | 1000              |
| GECOS           | ,,,               |
| Home directory  | /home/student |
| Default shell   | /bin/bash         |

The most relevant field for our purposes is the Password field, as it can contain different types of entries. In rare cases (generally on very old systems) this field may hold the actual password hash. On modern systems, however, password hashes are stored in the /etc/shadow file

## Shadow file

Since reading password hash values can put the entire system at risk, the /etc/shadow file was introduced. It has a similar format to /etc/passwd but is solely responsible for password storage and management.
The /etc/shadow file is also only readable by users with administrative privileges. The format of this file is divided into the following nine fields:
````
student:$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::
````
| Field             | Value                               |
|-------------------|-------------------------------------|
| Username          | student                             |
| Password          | $y$j9T$3QSBB6CbHEu...SNIP...f8Ms     |
| Last change       | 18955                               |
| Min age           | 0                                   |
| Max age           | 99999                               |
| Warning period    | 7                                   |
| Inactivity period | -                                   |
| Expiration date   | -                                   |
| Reserved field    | -                                   |

## Opasswd

The PAM library (pam_unix.so) can prevent users from reusing old passwords. These previous passwords are stored in the /etc/security/opasswd file. Administrator (root) privileges are required to read this file, assuming its permissions have not been modified manually.

````
$ sudo cat /etc/security/opasswd
````

## Cracking Linux Credentials

````
$ sudo cp /etc/passwd /tmp/passwd.bak 
$ sudo cp /etc/shadow /tmp/shadow.bak 
$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
$ hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
````
