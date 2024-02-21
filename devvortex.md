# Devvortex

## Reconnaissance & port scanning

Initial engagement with the machine was done by port scanning and web enumeration using provided IP address.

```
# Nmap 7.94SVN scan initiated Wed Feb 21 20:08:21 2024 as: nmap -sV --open -vvv -oA logs/initial_recon/initial 10.10.11.242
Nmap scan report for 10.10.11.242
Host is up, received conn-refused (0.063s latency).
Scanned at 2024-02-21 20:08:21 CET for 9s
Not shown: 978 closed tcp ports (conn-refused), 20 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Feb 21 20:08:30 2024 -- 1 IP address (1 host up) scanned in 9.56 seconds

```

First findings are ssh and http services running, machine's ip address redirects us to devvortex.htb. IP address was added to `/etc/hosts` for stability:

```bash
echo "10.10.14.242 devvortex.htb" | sudo tee -a /etc/hosts
```

Machine hosts a web page:

![01-initial_page](https://github.com/amalcew/htb-writeups/assets/73908014/0a668c52-9a0d-46d8-a37b-199b15ad9b7f)
