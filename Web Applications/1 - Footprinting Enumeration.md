# Footprinting & Enumeration

In this module, we aim to look at techniques that allow us to enumerate web applications, from the domain, parameters, directories, vhosts, and JavaScript deobfuscation.

# Domain Enumerations

## Whois

````
$ sudo apt update
$ sudo apt install whois -y
$ whois facebook.com
````

## DNS

**Dig - Any Query**
````
$ dig any google.com @nameserver
````

**Zone Transfer**
````
$ dig axfr google.com @nameserver
````

**Subdomain Brute Forcing**
````
$ for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.google.com @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done

dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt google.com
subfinder -d domain
python3 sublist3r.py -d <domain-name> -n
ffuf -u "http://FUZZ.domain" -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt
````

## Crawling

Crawling, often called spidering, is the automated process of systematically browsing the World Wide Web.
**Crawlers** can extract a diverse array of data, each serving a specific purpose in the reconnaissance process:
- Links (Internal and External): These are the fundamental building blocks of the web, connecting pages within a website (internal links) and to other websites (external links). Crawlers meticulously collect these links, allowing you to map out a website's structure, discover hidden pages, and identify relationships with external resources.
- Comments: Comments sections on blogs, forums, or other interactive pages can be a goldmine of information. Users often inadvertently reveal sensitive details, internal processes, or hints of vulnerabilities in their comments.
- Metadata: Metadata refers to data about data. In the context of web pages, it includes information like page titles, descriptions, keywords, author names, and dates. This metadata can provide valuable context about a page's content, purpose, and relevance to your reconnaissance goals.
- Sensitive Files: Web crawlers can be configured to actively search for sensitive files that might be inadvertently exposed on a website. This includes backup files (e.g., .bak, .old), configuration files (e.g., web.config, settings.php), log files (e.g., error_log, access_log), and other files containing passwords, API keys, or other confidential information. Carefully examining the extracted files, especially backup and configuration files, can reveal a trove of sensitive information, such as database credentials, encryption keys, or even source code snippets.

**Robots.txt** is a simple text file placed in the root directory of a website (e.g., www.example.com/robots.txt)
While robots.txt is not strictly enforceable (a rogue bot could still ignore it), most legitimate web crawlers and search engine bots will respect its directives. This is important for several reasons:
- Avoiding Overburdening Servers: By limiting crawler access to certain areas, website owners can prevent excessive traffic that could slow down or even crash their servers.
- Protecting Sensitive Information: Robots.txt can shield private or confidential information from being indexed by search engines.
- Legal and Ethical Compliance: In some cases, ignoring robots.txt directives could be considered a violation of a website's terms of service or even a legal issue, especially if it involves accessing copyrighted or private data.

The **.well-known** standard, defined in RFC 8615, serves as a standardized directory within a website's root domain.
The Internet Assigned Numbers Authority (IANA) maintains a registry of .well-known URIs, each serving a specific purpose defined by various specifications and standards. Below is a table highlighting a few notable examples:
| URI Suffix                           | Description                                                                                                                    | Status       | Reference                                                                                                                       |
|--------------------------------------|--------------------------------------------------------------------------------------------------------------------------------|--------------|---------------------------------------------------------------------------------------------------------------------------------|
| security.txt                         | Contains contact information for security researchers to report vulnerabilities.                                              | Permanent    | [RFC 9116](https://datatracker.ietf.org/doc/html/rfc9116)                                                                      |
| /.well-known/change-password         | Provides a standard URL for directing users to a password change page.                                                         | Provisional  | [W3C Specification](https://w3c.github.io/webappsec-change-password-url/#the-change-password-well-known-uri)                   |
| openid-configuration                 | Defines configuration details for OpenID Connect, an identity layer on top of the OAuth 2.0 protocol.                         | Permanent    | [OpenID Connect Discovery](http://openid.net/specs/openid-connect-discovery-1_0.html)                                          |
| assetlinks.json                      | Used for verifying ownership of digital assets (e.g., apps) associated with a domain.                                          | Permanent    | [Google Digital Asset Links](https://github.com/google/digitalassetlinks/blob/master/well-known/specification.md)              |
| mta-sts.txt                          | Specifies the policy for SMTP MTA Strict Transport Security (MTA-STS) to enhance email security.                              | Permanent    | [RFC 8461](https://datatracker.ietf.org/doc/html/rfc8461)                                                                      |


**Popular Web Crawlers**
- Burp Suite Spider: Burp Suite, a widely used web application testing platform, includes a powerful active crawler called Spider. Spider excels at mapping out web applications, identifying hidden content, and uncovering potential vulnerabilities.
- OWASP ZAP (Zed Attack Proxy): ZAP is a free, open-source web application security scanner. It can be used in automated and manual modes and includes a spider component to crawl web applications and identify potential vulnerabilities.
- Scrapy (Python Framework): Scrapy is a versatile and scalable Python framework for building custom web crawlers. It provides rich features for extracting structured data from websites, handling complex crawling scenarios, and automating data processing. Its flexibility makes it ideal for tailored reconnaissance tasks.
- Apache Nutch (Scalable Crawler): Nutch is a highly extensible and scalable open-source web crawler written in Java. It's designed to handle massive crawls across the entire web or focus on specific domains. While it requires more technical expertise to set up and configure, its power and flexibility make it a valuable asset for large-scale reconnaissance projects.

ReconSpider
````
$ wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
$ unzip ReconSpider.zip
$ python3 ReconSpider.py http://inlanefreight.com
````
LinkFinder
````
$ git clone https://github.com/GerbenJavado/LinkFinder.git
$ cd LinkFinder
$ pip3 install -r requirements.txt
$ python linkfinder.py -i https://example.com/1.js -o cli
$ python linkfinder.py -i https://example.com/1.js -o results.html
````

## Search Engine & Web Archives

**Search Operators**
| Operator             | Operator Description                                                      | Example                                                        | Example Description                                                                                           |
|----------------------|----------------------------------------------------------------------------|----------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| site:                | Limits results to a specific website or domain.                           | site:example.com                                               | Find all publicly accessible pages on example.com.                                                            |
| inurl:               | Finds pages with a specific term in the URL.                              | inurl:login                                                    | Search for login pages on any website.                                                                        |
| filetype:            | Searches for files of a particular type.                                  | filetype:pdf                                                   | Find downloadable PDF documents.                                                                              |
| intitle:             | Finds pages with a specific term in the title.                            | intitle:"confidential report"                                  | Look for documents titled "confidential report" or similar variations.                                        |
| intext: or inbody:   | Searches for a term within the body text of pages.                         | intext:"password reset"                                        | Identify webpages containing the term “password reset”.                                                       |
| cache:               | Displays the cached version of a webpage (if available).                  | cache:example.com                                              | View the cached version of example.com to see its previous content.                                            |
| link:                | Finds pages that link to a specific webpage.                              | link:example.com                                               | Identify websites linking to example.com.                                                                     |
| related:             | Finds websites related to a specific webpage.                             | related:example.com                                            | Discover websites similar to example.com.                                                                     |
| info:                | Provides a summary of information about a webpage.                        | info:example.com                                               | Get basic details about example.com, such as its title and description.                                        |
| define:              | Provides definitions of a word or phrase.                                 | define:phishing                                                | Get a definition of "phishing" from various sources.                                                           |
| numrange:            | Searches for numbers within a specific range.                             | site:example.com numrange:1000-2000                            | Find pages on example.com containing numbers between 1000 and 2000.                                            |
| allintext:           | Finds pages containing all specified words in the body text.               | allintext:admin password reset                                 | Search for pages containing both "admin" and "password reset" in the body text.                               |
| allinurl:            | Finds pages containing all specified words in the URL.                     | allinurl:admin panel                                           | Look for pages with "admin" and "panel" in the URL.                                                            |
| allintitle:          | Finds pages containing all specified words in the title.                   | allintitle:confidential report 2023                            | Search for pages with "confidential," "report," and "2023" in the title.                                       |
| AND                  | Narrows results by requiring all terms to be present.                      | site:example.com AND (inurl:admin OR inurl:login)              | Find admin or login pages specifically on example.com.                                                         |
| OR                   | Broadens results by including pages with any of the terms.                  | "linux" OR "ubuntu" OR "debian"                                | Search for webpages mentioning Linux, Ubuntu, or Debian.                                                       |
| NOT                  | Excludes results containing the specified term.                            | site:bank.com NOT inurl:login                                  | Find pages on bank.com excluding login pages.                                                                  |
| * (wildcard)         | Represents any character or word.                                          | site:socialnetwork.com filetype:pdf user* manual               | Search for user manuals (user guide, user handbook) in PDF format on socialnetwork.com.                        |
| .. (range search)    | Finds results within a specified numerical range.                          | site:ecommerce.com "price" 100..500                            | Look for products priced between 100 and 500 on an e-commerce website.                                         |
| " " (quotation marks)| Searches for exact phrases.                                                | "information security policy"                                  | Find documents mentioning the exact phrase "information security policy".                                      |
| - (minus sign)       | Excludes terms from the search results.                                    | site:news.com -inurl:sports                                    | Search for news articles on news.com excluding sports-related content.                                         |

Finding Login Pages:
 - site:example.com inurl:login
 - site:example.com (inurl:login OR inurl:admin)

Identifying Exposed Files:
 - site:example.com filetype:pdf
 - site:example.com (filetype:xls OR filetype:docx)

Uncovering Configuration Files:
 - site:example.com inurl:config.php
 - site:example.com (ext:conf OR ext:cnf) (searches for extensions commonly used for configuration files)

Locating Database Backups:
 - site:example.com inurl:backup
 - site:example.com filetype:sql

**Web Archives**

- https://web.archive.org/

# FFUF Fuzzing

**Directory Fuzzing**
````
$ ffuf -w <SNIP> -u http://SERVER_IP:PORT/FUZZ
$ ffuf -w <wordlist>:FUZZ
$ ffuf -w <wordlist>:FUZZ -u http://SERVER_IP:PORT/FUZZ
$ ffuf -w <wordlist>:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v
````
**Page Fuzzing**
````
$ ffuf -w <wordlist>:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ
$ ffuf -w <wordlist>:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php
$ ffuf -w <wordlist>:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v
````
**Sub-domain & Vhost**
````
$ ffuf -w <wordlist>:FUZZ -u https://FUZZ.<domain>/
$ ffuf -w <wordlist>:FUZZ -u http://<IP>/ -H 'Host: FUZZ.<domain>'
````
**Filtering Results**
````
MATCHER OPTIONS:
  -mc              Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403)
  -ml              Match amount of lines in response
  -mr              Match regexp
  -ms              Match HTTP response size
  -mw              Match amount of words in response

FILTER OPTIONS:
  -fc              Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fl              Filter by amount of lines in response. Comma separated list of line counts and ranges
  -fr              Filter regexp
  -fs              Filter HTTP response size. Comma separated list of sizes and ranges
  -fw              Filter by amount of words in response. Comma separated list of word counts and ranges

$ ffuf -w <wordlist>:FUZZ -u http://<IP/domain>/ -H 'Host: FUZZ.<domain>' -fs 900
````
**Parameters & Values**
````
$ ffuf -w <wordlist>:FUZZ -u http://<domain/IP>:PORT/admin/admin.php?FUZZ=key -fs xxx
$ ffuf -w <wordlist>:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
$ ffuf -w ids.txt:FUZZ -u http://<domain>:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xx
````
**Multi Fuzzing**
````
$ ffuf -w <wordlist>:FUZZ1 -w <wordlist2>:FUZZ2 -u http://<domain>:PORT/admin/admin.php -X POST -d 'FUZZ1=FUZZ2' -H 'Content-Type: application/x-www-form-urlencoded' -fs xx
````

# JavaScript deobfuscation

**Obfuscation**
- https://www.toptal.com/developers/javascript-minifier
- https://beautifytools.com/javascript-obfuscator.php
- https://obfuscator.io/
- https://jsconsole.com/

**Javascript Beautifier**
- https://prettier.io/playground/
- https://beautifier.io/
  
**Deobfudcator**
- https://matthewfl.com/unPacker.html
  
**Decoding**
- base64
- hex
- rot13
