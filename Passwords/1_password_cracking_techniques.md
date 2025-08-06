# Password Cracking Techniques

Passwords are commonly hashed when stored, in order to provide some protection in the event they fall into the hands of an attacker. Hashing is a mathematical function which transforms an arbitrary number of input bytes into a (typically) fixed-size output; common examples of hash functions are MD5, and SHA-256.
Hash functions are designed to work in one direction. This means it should not be possible to figure out what the original password was based on the hash alone. When attackers attempt to do this, it is called password cracking. Common techniques are to use rainbow tables, to perform dictionary attacks, and typically as a last resort, to perform brute-force attacks.

## John The Ripper

**Single crack mode**

Single crack mode is a rule-based cracking technique that is most useful when targeting Linux credentials. It generates password candidates based on the victim's username, home directory name, and GECOS values (full name, room number, phone number, etc.).
````
$ john --single passwd
````

**Wordlist mode**
````
$ john --wordlist=<wordlist_file> <hash_file>
````

**Incremental mode**

Incremental mode is a powerful, brute-force-style password cracking mode that generates candidate passwords based on a statistical model (Markov chains). It is designed to test all character combinations defined by a specific character set, prioritizing more likely passwords based on training data.
````
$ john --incremental <hash_file>
````

**Identifying hash formats**

Sometimes, password hashes may appear in an unknown format, and even John the Ripper (JtR) may not be able to identify them with complete certainty.
````
$ hashid -j <hash>
````

**Cracking Files**

It is also possible to crack password-protected or encrypted files with JtR. Multiple "2john" tools come with JtR that can be used to process files and produce hashes compatible with JtR. The generalized syntax for these tools is:
````
$ <tool> <file_to_crack> > file.hash
$ locate *2john*
````

| Tool                   | Description                                      |
|------------------------|--------------------------------------------------|
| pdf2john              | Converts PDF documents for John                  |
| ssh2john              | Converts SSH private keys for John               |
| mscash2john           | Converts MS Cash hashes for John                 |
| keychain2john         | Converts OS X keychain files for John            |
| rar2john              | Converts RAR archives for John                   |
| pfx2john              | Converts PKCS#12 files for John                  |
| truecrypt_volume2john | Converts TrueCrypt volumes for John              |
| keepass2john          | Converts KeePass databases for John              |
| vncpcap2john          | Converts VNC PCAP files for John                 |
| putty2john            | Converts PuTTY private keys for John             |
| zip2john              | Converts ZIP archives for John                   |
| hccap2john            | Converts WPA/WPA2 handshake captures for John    |
| office2john           | Converts MS Office documents for John            |
| wpa2john              | Converts WPA/WPA2 handshakes for John            |

## Hashcat

````
$ hashcat -a 0 -m 0 <hashes> [wordlist, rule, mask, ...]
````
- -a is used to specify the attack mode
- -m is used to specify the hash type
- <hashes> is a either a hash string, or a file containing one or more password hashes of the same type
- [wordlist, rule, mask, ...] is a placeholder for additional arguments that depend on the attack mode

**Hash Types**
````
$ hashcat --help
$ hashid -m '<hash>'
````

**Dictionary attack**
````
$ hashcat -a 0 -m 0 e3e3ec5831ad5e7288241960e5d4fdb8 /usr/share/wordlists/rockyou.txt
--------------------------------------------------------------------------------------
- With Rules -
/usr/share/hashcat/rules
$ hashcat -a 0 -m 0 1b0556a75770563578569ae21392630c /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
````

**Mask**

Mask attack (-a 3) is a type of brute-force attack in which the keyspace is explicitly defined by the user. For example, if we know that a password is eight characters long, rather than attempting every possible combination, we might define a mask that tests combinations of six letters followed by two numbers.

| Symbol | Charset                             |
|--------|--------------------------------------|
| ?l     | abcdefghijklmnopqrstuvwxyz           |
| ?u     | ABCDEFGHIJKLMNOPQRSTUVWXYZ           |
| ?d     | 0123456789                           |
| ?h     | 0123456789abcdef                     |
| ?H     | 0123456789ABCDEF                     |
| ?s     | «space»!"#$%&'()*+,-./:;<=>?@[]^_`{  |
| ?a     | ?l?u?d?s                             |
| ?b     | 0x00 - 0xff                          |

````
$ hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'
````

## Create custom Rules and Wordlists

### Custom Rule
Let's look at a simple example using a password list with only one entry.
````
$ cat password.list
password
````
We can use Hashcat to combine lists of potential names and labels with specific mutation rules to create custom wordlists.

| Function | Description                                |
|----------|--------------------------------------------|
| :        | Do nothing                                 |
| l        | Lowercase all letters                      |
| u        | Uppercase all letters                      |
| c        | Capitalize the first letter and lowercase others |
| sXY      | Replace all instances of X with Y          |
| $!       | Add the exclamation character at the end   |

Each rule is written on a new line and determines how a given word should be transformed. 
````
$ cat custom.rule

:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
````
We can use the following command to apply the rules in custom.rule to each word in password.list and store the mutated results in mut_password.list.
````
$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
````

### Generate Wordlist

**CeWL**
````
$ cewl https://domain -d 4 -m 6 --lowercase -w word.wordlist
````
We specify some parameters, like the depth to spider (-d), the minimum length of the word (-m), the storage of the found words in lowercase (--lowercase), as well as the file where we want to store the results (-w).

**Tool: cupp**

## Protected Files

One way to tell whether an SSH key is encrypted or not, is to try reading the key with ssh-keygen.
````
$ ssh-keygen -yf ~/.ssh/id_ed25519 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIpNefJd834VkD5iq+22Zh59Gzmmtzo6rAffCx2UtaS6
--------------------------------------------------------------------------------
$ ssh-keygen -yf ~/.ssh/id_rsa
Enter passphrase for "/home/jsmith/.ssh/id_rsa":
````

**SSH keys**
````
$ ssh2john.py SSH.private > ssh.hash
$ john --wordlist=rockyou.txt ssh.hash
````

**Password-protected documents**
````
$ office2john.py Protected.docx > protected-docx.hash
$ john --wordlist=rockyou.txt protected-docx.hash
$ john protected-docx.hash --show

The same to xlxs
````
````
$ pdf2john.py PDF.pdf > pdf.hash
$ john --wordlist=rockyou.txt pdf.hash
$ john pdf.hash --show
````

## Protected Archives

There are many types of archive files. Some of the more commonly encountered file extensions include tar, gz, rar, zip, vmdb/vmx, cpt, truecrypt, bitlocker, kdbx, deb, 7z, and gzip.

**ZIP files**
````
$ zip2john ZIP.zip > zip.hash
$ john --wordlist=rockyou.txt zip.hash
````
**KeePass and PWsafe**
````
$ pwsafe2john pwsafe.psafe3 > pwsafedump
$ john --wordlist=rockyou.txt pwsafedump

$ keepass2john <file>.kdbx > keepass.hash
$ john --wordlist=rockyou.txt keepass.hash
````

**OpenSSL encrypted GZIP files**
````
$ file GZIP.gzip 
GZIP.gzip: openssl enc'd data with salted password
--------------------------------------------------
$ for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
````

**BitLocker-encrypted drives**
````
$ bitlocker2john -i Backup.vhd > backup.hashes
$ grep "bitlocker\$0" backup.hashes > backup.hash
$ hashcat -a 0 -m 22100 backup.hash /usr/share/wordlists/rockyou.txt
````
````
- Mounting BitLocker-encrypted drives in Linux (or macOS) -
$ sudo apt-get install dislocker
$ sudo mkdir -p /media/bitlocker
$ sudo mkdir -p /media/bitlockermount
$ sudo losetup -f -P Backup.vhd
$ sudo dislocker /dev/loop0p2 -u1234qwer -- /media/bitlocker
$ sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount
$ cd /media/bitlockermount/
$ ls -la
$ sudo umount /media/bitlockermount
$ sudo umount /media/bitlocker
````
