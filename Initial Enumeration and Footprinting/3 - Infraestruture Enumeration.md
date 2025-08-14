
# Domain Information

Domain information is a core component of any penetration test, and it is not just about the subdomains but about the entire presence on the Internet. Therefore, we gather information and try to understand the company's functionality and which technologies and structures are necessary for services to be offered successfully and efficiently.
This type of information is gathered passively without direct and active scans. In other words, we remain hidden and navigate as "customers" or "visitors" to avoid direct connections to the company that could expose us. The OSINT relevant sections are only a tiny part of how in-depth OSINT goes and describe only a few of the many ways to obtain information in this way.
However, when passively gathering information, we can use third-party services to understand the company better. However, the first thing we should do is scrutinize the company's main website. Then, we should read through the texts, keeping in mind what technologies and structures are needed for these services.

**Online Presence**

The first point of presence on the Internet may be the SSL certificate from the company's main website that we can examine. Often, such a certificate includes more than just a subdomain, and this means that the certificate is used for several domains, and these are most likely still active.
Another source to find more subdomains is crt.sh. This source is Certificate Transparency logs. Certificate Transparency is a process that is intended to enable the verification of issued digital certificates for encrypted Internet connections. 
````
curl -s https://crt.sh/\?q\=google.com\&output\=json | jq .
curl -s https://crt.sh/\?q\=google.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u
````

**Internet Search Engines**

Shodan can be used to find devices and systems permanently connected to the Internet like Internet of Things (IoT).

````
$ for i in $(cat subdomainlist);do host $i | grep "has address" | grep google.com | cut -d" " -f4 >> ip-addresses.txt;done
$ for i in $(cat ip-addresses.txt);do shodan host $i;done
````
Other searches engines:

- Censys (https://search.censys.io/)
- Binary Edge (https://www.binaryedge.io/)
- ZoomEye (https://www.zoomeye.ai/)

**DNS Records**

````
dig any google.com
````
Let us look at what we have learned here and come back to our principles. We see an IP record, some mail servers, some DNS servers, TXT records, and an SOA record.

- A records: We recognize the IP addresses that point to a specific (sub)domain through the A record. Here we only see one that we already know.

- MX records: The mail server records show us which mail server is responsible for managing the emails for the company. Since this is handled by google in our case, we should note this and skip it for now.

- NS records: These kinds of records show which name servers are used to resolve the FQDN to IP addresses. Most hosting providers use their own name servers, making it easier to identify the hosting provider.

- TXT records: this type of record often contains verification keys for different third-party providers and other security aspects of DNS, such as SPF, DMARC, and DKIM, which are responsible for verifying and confirming the origin of the emails sent. Here we can already see some valuable information if we look closer at the results.

# Cloud Resources

The use of cloud, such as AWS, GCP, Azure, and others, is now one of the essential components for many companies nowadays. After all, all companies want to be able to do their work from anywhere, so they need a central point for all management. This is why services from Amazon (AWS), Google (GCP), and Microsoft (Azure) are ideal for this purpose.

Even though cloud providers secure their infrastructure centrally, this does not mean that companies are free from vulnerabilities. The configurations made by the administrators may nevertheless make the company's cloud resources vulnerable. This often starts with the S3 buckets (AWS), blobs (Azure), cloud storage (GCP), which can be accessed without authentication if configured incorrectly.

````
$ for i in $(cat subdomainlist);do host $i | grep "has address" | grep google.com | cut -d" " -f1,4;done

s3-website-us-west-2.amazonaws.com 10.129.95.250
````

One of the easiest and most used is Google search combined with Google Dorks. For example, we can use the Google Dorks inurl: and intext: to narrow our search to specific terms. In the following example, we see red censored areas containing the company name.

**Google Search for AWS**
````
intext:domain inurl:amazonaws.com
````
**Google Search for Azure**
````
intext:domain inurl:blob.core.windows.net
````

Useful Links:

- https://domain.glass/
- https://buckets.grayhatwarfare.com/
