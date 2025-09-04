# CSRF

## 原理

CSRF全称Cross-Site-Request Forgery，即跨站请求伪造。

核心：在用户不知情的情况下，恶意网站诱使用户发出了带有副作用的请求。（XSS加载恶意脚本其实也是用户不知情的情况，然后恶意代码发出一些请求）

这里有两个关键点：

1. 不同于XSS，CSRF的请求是恶意网站发出的，它为什么可以知道cookie？

   其实恶意网站并不知道cookie，是浏览器在请求时带上了正常网站的cookie。

   cookie有一个samesite属性控制跨站是否发送cookie

2. 为什么可以发出请求？

​	同源策略并没有限制你进行请求，只是**浏览器**（同源策略的执行者）接受响应时会截取，恶意网站接受不到返回的数据。但是请求的副作用已经产生，攻击	者的目的已经达到了

下图内容在`web复习.md`中

![image-20250903163557624](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250903163557624.png)

## 防御

CORS其实是可以用于解决CSRF的  CSRF是跨域“写”和CORS防御的跨域“读”很类似。

CORS中的复杂请求需要进行预检，防止对服务器产生副作用，有防御CSRF的意思。

但是因为历史问题CORS保留了可以直接发出的简单请求。

二者是可以由服务端执行一个理想的统一控制跨域访问策略来解决。

下面为《白帽子将web安全》原文：（这本书值得多读几遍）

> ​	前文讲到CORS中有简单请求和复杂请求，其中复杂请求的预检操作是为了避免请求被直接发出而给服务端带来副作用，这看起来有点防御CSRF的意思。实际上CSRF和跨域资源共享很类似，只不过在多数场景中前者指的是跨域的“写”操作，而后者更多的是指跨域的“读”操作。但理论上这两者是可以用同一种方案来解决的，这个“理想的方案”应该是由服务端来统一控制跨域访问策略。CORS的复杂请求确实是这么设计的，经过服务端允许才能访问服务端，但是CORS还有一种简单请求，无须服务端许可，请求就可以发出去。
>
> 笔者认为这是有历史原因的，因为在还没有CORS标准时，Web标准的设计中本身就有很多方式支持跨域发起请求，如加载外部资源、跨域提交表单等。而CORS标准是很晚才被提出来的，即使在CORS标准中所有请求都用复杂请求的预检方式，但是HTML原本就能发出的跨域请求还是不受CORS标准的约束，而这些功能又不能完全废弃，也就是说CORS方案做得再完美也还是有个大窟窿无法堵住。由于这个“历史问题”，CORS标准干脆放开部分限制，提出了一种简单请求方式，无须服务端许可，请求就能发出去。

正确防御办法：

1. 验证码：CSRF在用户不知情发出，因此使用验证码让用户进行确认。
2. 校验Referer：和CORS的Origin一样，标识来源。无法依赖。可以作为监控手段。
3. Cookie的SameSite属性：可以缓解CSRF攻击，但是不能完全依赖它
4. Anti-CSRF Token：业界现在最常见的做法。url中带上随机的Token，恶意网站无法知道url自然不能发送有副作用的请求

# SSRF

## 原理

SSRF全称是 Server Side Request Forgery     也就是服务端请求伪造

位列2021    OWASP top10

> **[A10:2021-Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/)** is added from the Top 10 community survey (#1). The data shows a relatively low incidence rate with above average testing coverage, along with above-average ratings for Exploit and Impact potential. This category represents the scenario where the security community members are telling us this is important, even though it's not illustrated in the data at this time.

一句话概括：攻击者发出恶意请求使得web应用进行了预料之外的访问。

SSRF（常指访问内网应用）和远程文件包含漏洞（访问远程脚本）很像（实际远程文件包含也可以归为SSRF）

SSRF其实也利用了”认证及验证机制失效“（OWASP-2021-A07）和”失效的访问控制“（OWASP-2021-A01）。因为它访问的内网应用大多无**认证**和和**授权**（注意区分认证Authentication和授权Authorization）

## 如何攻击

1. 通过改变url探测内网IP是否存在，端口是否开放
2. 通过各种HTTP外的其他协议进行攻击

最基本是file://协议（文件包含也用）

还有FTP，LDAP，IMAP，POP3，SMTP，telnet等

最有利DICT协议（2628端口）和Gopher协议（70端口），可以实现协议走私（LDAP也可以）

Gopher协议比较原始，格式如下

`gopher://<host>:<port>/<gophertype><selector>`

`<selector>`的内容会被直接发送给服务器，可以在这部分放一个HTTP数据包

有SSRF漏洞的地方直接放http协议只能控制url，利用Gopher协议走私可以控制整个数据包

注意Gopher协议最理想夹带建立TCP链接后立马就能用，无需额外握手的协议，比如HTTP

类似的无需握手的服务比如Redis服务（默认不启用身份认证），也是很好的选择

## 绕过

1. 申请一个域名修改它的A记录解析到IP127.0.0.1
2. 使用可以指向任意ip的域名   127.0.0.1.xip.io，可解析为127.0.0.1
3. 使用。代替.
4. 使用[::]代替127.0.0.1
5. 使用@符号      `http://www.baidu.com@10.10.10.10` 与 `http://10.10.10.10` 请求是相同的

这里@的写法其实源于http的basic认证的已经废弃的一种写法

`http://<username>:<password>@www.baidu.com`

## 防御

SSRF防御要根据实际情况进行选择。总体思想是放弃黑名单，采用白名单的机制校验。

1. 校验协议类型，最好禁用多余的协议
2. 校验IP地址是否为公网（允许用户填写任意IP访问时）
3. 允许的情况下校验url是否在白名单中
4. 使用成熟的url解析库，避免自己写正则
5. 加强内网应用的认证和授权
6. 进行日志记录，不要返回错误信息（但是不返回错误信息可以根据时间测信道攻击）
