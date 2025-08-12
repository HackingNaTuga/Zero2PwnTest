# Environment-Based Priv Esc

Here we will have techniques in which we can abuse Path and restrictive Shell Escape.

## Path Abuse

PATH is an environment variable that specifies the set of directories where an executable can be located. An account's PATH variable is a set of absolute paths, allowing a user to type a command without specifying the absolute path to the binary. 
````
$ echo $PATH
````
**Explore Path**
````
$ PATH=.:${PATH}
$ export PATH
$ echo $PATH
````

## Wildcard Abuse

A wildcard character can be used as a replacement for other characters and are interpreted by the shell before other actions. Examples of wild cards include:

| Character | Significance |
|-----------|--------------|
| `*`       | An asterisk that can match any number of characters in a file name. |
| `?`       | Matches a single character. |
| `[ ]`     | Brackets enclose characters and can match any single one at the defined position. |
| `~`       | A tilde at the beginning expands to the name of the user home directory or can have another username appended to refer to that user's home directory. |
| `-`       | A hyphen within brackets will denote a range of characters. |

An example of how wildcards can be abused for privilege escalation is the tar command, a common program for creating/extracting archives.
````
$ man tar

<SNIP>
Informative output
       --checkpoint[=N]
              Display progress messages every Nth record (default 10).

       --checkpoint-action=ACTION
              Run ACTION on each checkpoint.
````
The --checkpoint-action option permits an EXEC action to be executed when a checkpoint is reached (i.e., run an arbitrary operating system command once the tar command executes.) By creating files with these names, when the wildcard is specified, --checkpoint=1 and --checkpoint-action=exec=sh root.sh is passed to tar as command-line options. Let's see this in practice.

````
*/01 * * * * cd /home/<user> && tar -zcf /home/<user>/backup.tar.gz *
````
````
$ echo 'echo "<user> ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
$ echo "" > "--checkpoint-action=exec=sh root.sh"
$ echo "" > --checkpoint=1
````
When the cronjob is executed and runs the tar command, it will automatically execute our checkpoints and, consequently, our script.

## Escaping Restricted Shells

**RBASH**

Restricted Bourne shell (rbash) is a restricted version of the Bourne shell, a standard command-line interpreter in Linux which limits the user's ability to use certain features of the Bourne shell, such as changing directories, setting or modifying environment variables, and executing commands in other directories. It is often used to provide a safe and controlled environment for users who may accidentally or intentionally damage the system.

**RKSH**

Restricted Korn shell (rksh) is a restricted version of the Korn shell, another standard command-line interpreter. The rksh shell limits the user's ability to use certain features of the Korn shell, such as executing commands in other directories, creating or modifying shell functions, and modifying the shell environment.

**RZSH**

Restricted Z shell (rzsh) is a restricted version of the Z shell and is the most powerful and flexible command-line interpreter. The rzsh shell limits the user's ability to use certain features of the Z shell, such as running shell scripts, defining aliases, and modifying the shell environment.

**Escaping**

Command Substitution

Another method for escaping from a restricted shell is to use command substitution. This involves using the shell's command substitution syntax to execute a command. For example, imagine the shell allows users to execute commands by enclosing them in backticks (`). In that case, it may be possible to escape from the shell by executing a command in a backtick substitution that is not restricted by the shell.

Command Chaining

In some cases, it may be possible to escape from a restricted shell by using command chaining. We would need to use multiple commands in a single command line, separated by a shell metacharacter, such as a semicolon (;) or a vertical bar (|), to execute a command. For example, if the shell allows users to execute commands separated by semicolons, it may be possible to escape from the shell by using a semicolon to separate two commands, one of which is not restricted by the shell.

Environment Variables

For escaping from a restricted shell to use environment variables involves modifying or creating environment variables that the shell uses to execute commands that are not restricted by the shell. For example, if the shell uses an environment variable to specify the directory in which commands are executed, it may be possible to escape from the shell by modifying the value of the environment variable to specify a different directory.

Shell Functions

In some cases, it may be possible to escape from a restricted shell by using shell functions. For this we can define and call shell functions that execute commands not restricted by the shell. Let us say, the shell allows users to define and call shell functions, it may be possible to escape from the shell by defining a shell function that executes a command.



````
$ ls -l `pwd`
$ echo *
$ echo $(<flag.txt)
$ man -C flag.txt
````

