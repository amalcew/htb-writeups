![Editorial](https://github.com/user-attachments/assets/d91dd486-9c41-49fa-a3d8-95556e28591f)

## Reconnaissance & port scanning

Let's start with port enumeration
``` bash
# Nmap 7.94SVN scan initiated Sun Jun 16 15:08:25 2024 as: nmap -sV -sC -vvv -oA logs/initial 10.10.11.20
Nmap scan report for 10.10.11.20 (10.10.11.20)
Host is up, received syn-ack (0.025s latency).
Scanned at 2024-06-16 15:08:25 CEST for 9s
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMApl7gtas1JLYVJ1BwP3Kpc6oXk6sp2JyCHM37ULGN+DRZ4kw2BBqO/yozkui+j1Yma1wnYsxv0oVYhjGeJavM=
|   256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMXtxiT4ZZTGZX4222Zer7f/kAWwdCWM/rGzRrGVZhYx
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun 16 15:08:34 2024 -- 1 IP address (1 host up) scanned in 9.54 seconds
```

The target has open port 80, which suggests web application. 

![01-initial_page](https://github.com/user-attachments/assets/df2eb697-b9b6-4052-baf0-e2928cf7d3d0)

The webpage has two endpoints, the most promising is `/upload` endpoint which contains multiple input fields and the upload functionality:

![02-publish_page](https://github.com/user-attachments/assets/d8e6e830-6b2a-47b3-b081-b219050b5b3d)

## Initial foothold

### Server-side request forgery

The form contains cover upload, which expects images or URL to the image. As the attacks on upload form were fruitless, I've tested if this field could be vulnerable to SSRF attack.
To test it, Burp Intruder can be used:

![image](https://github.com/user-attachments/assets/04b0623f-0fcf-4d58-8e2e-44dd9ce2f1c8)

As we can see, some discrepancies were detected when testing for SSRF on port 5000. After typing the URL and hitting "Preview" button, the image changes:

![image](https://github.com/user-attachments/assets/3c14fa5c-7ddb-48a9-b2e5-b7afacec9257)

The image is in fact a text file, which can be downloaded. The file stores some kind of JSON data response, containing multiple endpoints on the application.
When testing those endpoints on the URL field, one of them proved to be worthy, as it returned an API response containing login and password to the machine:

![image](https://github.com/user-attachments/assets/689b8442-e92f-4541-b27b-ac1f714817fc)

### SSH connection

With those credentials, we can connect to the machine:

``` bash
> ssh dev@10.10.11.20
dev@10.10.11.20's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri Oct  4 01:56:05 PM UTC 2024

  System load:  0.01              Processes:             231
  Usage of /:   61.3% of 6.35GB   Users logged in:       1
  Memory usage: 20%               IPv4 address for eth0: 10.10.11.20
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Oct  4 12:59:07 2024 from xx.xx.xx.xx
dev@editorial:~$ id
uid=1001(dev) gid=1001(dev) groups=1001(dev)
dev@editorial:~$ 
```

and capture the user flag.
