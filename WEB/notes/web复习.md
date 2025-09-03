# COOKIE

## 概述

服务器端Set-Cookie写入cookie

将数据放入cookie  不安全  两种解决方法

1. cookie仅作为sessionID，服务端存放数据session

   在客户端存放，使用JWT（json web token）    无法主动废弃

   注意，JWT由Header.Payload.Signature组成，只签名不加密，只能验证，防篡改

   要加密使用JWE

## 属性

1. Domain     不指定时为Host-Only cookie只在当前域名生效       只要指定就对子域名生效
2. Path          指定cookie生效的路径      但是不同路径下的页面是同源的，可以互相读取cookie
3. Expires    指定有效期，不显示指定就是临时cookie，浏览器关就删除
4. HttpOnly属性    只用于HTTP/HTTPS传输，客户端的javascript无法读取（缓解XSS）
5. Secure       只能在HTTPS请求发
6. Samesite：（一定程度缓解CSRF）
   None：任何场景都发送，但是带上Secure属性
   LAX：普通跨站请求不发送，但是导航发送
   Strict：任何情况都不发送（影响体验）

固定会话攻击：诱导使用一个固定的session_id



# HTTPS

如何从http升级到https？

服务端发送重定向响应，状态码为301或者302，在location头中放入新的https协议的url地址，浏览器发出请求

然后在443端口ssl握手协商密钥。。。D-H密钥

问题：**第一个请求是明文传输**

1. SSL/TLS密码套件降级攻击，中间人修改客户端请求只保留不安全的算法套件
2. 中间人全程劫持让用户一直以http访问，自己代替进行https访问，并返回https响应，用户以为一直在https

如何解决？

**HSTS**   HTTP Strict-Transport-Security

响应加入一个**Strict-Transport-Security**头，向浏览器指明接下来多久要用https访问



# websocket

WebSocket 连接始于一个普通的 HTTP 请求。客户端通过一个特殊的请求，请求服务器将协议**升级**为 WebSocket。

- **客户端请求头 (Client Handshake)**

  http

  ```
  GET /chat HTTP/1.1
  Host: server.example.com
  Upgrade: websocket          # 关键：请求升级协议
  Connection: Upgrade         # 关键：请求升级连接
  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ== # 随机生成的16字节Base64密钥，用于验证
  Sec-WebSocket-Version: 13   # 使用的WebSocket协议版本（13是最普遍的）
  Origin: http://example.com  # 用于安全验证，防止未经授权的跨源访问
  ```

- **服务器响应头 (Server Handshake)**
  如果服务器支持 WebSocket，它会返回一个 `101 Switching Protocols` 响应，表示同意升级。

  http

  ```
  HTTP/1.1 101 Switching Protocols
  Upgrade: websocket          # 同意升级
  Connection: Upgrade         # 同意升级连接
  Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo= # 对客户端Key计算后的响应值
  ```

  - `Sec-WebSocket-Accept` 的计算方法：将客户端的 `Sec-WebSocket-Key` 加上一个固定的GUID `"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"`，然后计算其SHA-1哈希值，最后进行Base64编码。
  - 浏览器会验证这个值，确保对方是真正的WebSocket服务器，而不是意外的HTTP响应。

**一旦握手成功，TCP连接就不会被释放，但之后的通信不再使用HTTP协议，而是使用WebSocket协议的数据帧格式。**



# 同源策略

## 什么是同源？

协议   主机    端口

## 同源策略干了什么？

阻止跨域**读取**数据，即阻止一个域的javascript代码读取另一个域的数据

但是注意，跨域**加载**资源是允许的

可以用 `<script>` 的`src`引入跨域的 JS 文件（这就是 JSONP 的原理）

可以通过 `XMLHttpRequest` 或 `fetch`向不同源的服务器发送ajax请求（请求会发出但是响应会被浏览器拦截），恶意网站通过这点以及自动发送跨站自动发送cookie（SameSite属性）实现CSRF（跨域写）

## 谁在执行同源策略？浏览器

## 跨域解决方案

### 前端之间

1. window.name跨域    窗口发生跳转的时候window.name的值会保留。设计初衷并不是跨域
2. window.postMessage  一个窗口间通信的api
3. 两个子域名将 `document.domain` 设置为相同的父域

### 跨域访问服务端

1. JSONP  JSON with Padding          利用script的src标签不受同源策略的限制(xss也是利用这点)   src请求?callback=myfunc

   然后服务端返回js代码，即用myfunc()包裹的json数据（作为参数）。注意响应的内容类型应该是application/javascript

   前端直接执行，前端设置myfunc函数，内容可以是打印参数这样

2. CORS    最标准的方案，完全由服务端控制。请求带上Origin头说明客户端的源，服务端返回acess-contrl-allow-orign的头，指示允许的源。一个问题：简单请求（GET，POST）会直接发出（浏览器拦截响应），复杂请求浏览器会通过OPTIONS预检。简单请求依旧可以进行CSRF攻击。

   **为什么还保留简单请求**？历史问题，提出的太晚了

3. websocket。一个全新的协议，允许全双工，不受同源策略限制



# XSS



# CSRF



# SSRF



# SQL注入



# 其他注入

xxe  os命令执行    消息头注入（CRLF注入）LDAP注入





# 浏览器



# DNS & CDN

## DNS

### 服务器类型

分为递归查询和迭代查询，区别是谁在查询

1. DNS解析器（本地DNS服务器）    由IPS提供，接受用户请求并执行
2. 根域名服务器
3. 顶级域名服务器
4. 权威域名服务器

### 记录类型

- **A记录**：将域名指向一个IPv4地址。
- **AAAA记录**：将域名指向一个IPv6地址。
- **CNAME记录**：别名记录，将一个域名指向另一个域名。     **和CDN相关**
- **MX记录**：邮件交换记录，指定负责接收邮件的服务器。
- **TXT记录**：文本记录，常用于域名所有权验证、SPF反垃圾邮件等。
- **NS记录**：指定该域名由哪个DNS服务器来进行解析。

### 缓存

一次DNS查询的缓存检查顺序，遵循一个高效的“由近及远”的链条：

1. **浏览器缓存** → 最快，但范围仅限该浏览器。找不到就交给主机
2. **操作系统缓存 & `hosts` 文件** → 系统级，为所有应用服务。
3. **路由器缓存** → 家庭或局域网级，所有连接到该路由器的设备共享。
4. **ISP递归解析器缓存** → 规模最大，为所有使用该ISP的用户服务。
5. 若以上均未命中，则启动完整的**递归/迭代DNS查询**过程。

## CDN

CDN：Content Delivery Network   内容分发网络

访问baidu.com时，DNS会有一条**CNAME记录**跳转到a.shifen.com

这里a开头的域名就是CDN域名。

CDN是由商家在各地搭建的服务器，**提前**拉取顾客的服务器的静态内容（源码）并对外分发

动态内容根据用户不同或者时间不同而改变，若是通过CDN服务器再访问百度的服务器就达不到加速的功能

也有能分发动态内容的CDN

CDN相当于代理服务器，是一面墙，可以缓解DDOS攻击

**CDN被DDOS攻击怎么办？**

通过**任播**技术进行**负载均衡**

任播：

- **多个**分布在不同地理位置的服务器**共享同一个IP地址**。
- 网络路由器会根据动态的路由协议（主要是**BGP**），将发送到该IP地址的数据包**路由到“最近”的一台服务器**。
- 这里的“最近”通常指的是**网络拓扑上的最近**（跳数最少、延迟最低），而不一定是物理距离上的最近

# Nmap

## 一、当你不加任何参数直接运行 `nmap <target>` 时，nmap 默认的行为是：

1. **扫描类型**：执行一个 **TCP SYN 扫描** (`-sS`)。这是一种“半开放”扫描，速度快且不易被目标系统记录到日志。
2. **扫描端口**：只扫描 **1000 个最常用的端口**。这个列表是nmap根据网络流量统计维护的，涵盖了绝大多数常见服务（如HTTP, HTTPS, SSH, FTP, SMB, RDP等）。
3. **其他操作**：默认会启用**主机发现**（`-sn`，即ping扫描），如果主机在线，再对其进行端口扫描。同时会进行**服务版本探测** (`-sV`) 和**操作系统探测** (`-O`)。

**总结：`nmap 192.168.1.1` ≈ `nmap -sS -sV -O --top-ports 1000 192.168.1.1`**

## 二、nmap 扫描出来的端口有几种状态？

nmap 扫描后，端口通常会处于以下六种状态之一：

open                       端口开放

closed                     端口可访问（主机存活） 但是无监听

filtered                    通常是被防火墙过滤，数据包被丢弃导致**无响应**

unfiletered	     通常是ACK扫描（发送ACK包，收到RST包说明未被防火墙过滤）

open | filtered       常见于隐蔽扫描，发送错误的包，端口关闭则返回RST包，开放不响应（不响应也可能被过滤）

closed |filtered      罕见情况

## 三、有哪些常见高危端口？

| **远程管理服务**     |          |                              |
| -------------------- | -------- | ---------------------------- |
| **20、21**           | TCP      | **FTP**（文件传输协议）      |
| **22**               | TCP      | **SSH**（安全外壳协议）      |
| **23**               | TCP      | **Telnet**（远程终端协议）   |
| 69                   | TCP      | TFTP（简单文件传送协议）     |
| **3389**             | TCP      | **RDP**（远程桌面协议）      |
| **5900-5902**        | TCP      | **VNC**（虚拟网络控制台）    |
| 512-514              | TCP      | Linux rexec（远程登录）      |
| 873                  | TCP      | Rsync（数据镜像备份工具）    |
| **局域网服务**       |          |                              |
| **53**               | TCP、UDP | **DNS**（域名系统）          |
| 111、2049            | TCP      | **NFS**（网络文件系统）      |
| **135**              | TCP、UDP | **RPC**（远程过程调用）      |
| 137                  | TCP、UDP | NBNS（NetBIOS名字服务）      |
| 138                  | TCP、UDP | NBDS（NetBIOS数据报文服务）  |
| 139                  | TCP、UDP | NBSS（NetBIOS会话服务）      |
| **445**              | TCP、UDP | **SMB**（网络文件共享协议）  |
| 161                  | TCP、UDP | SNMP（简单网络管理协议)      |
| **389**              | TCP、UDP | **LDAP**（轻量目录访问协议） |
| **互联网服务**       |          | **（都是明文）**             |
| **25**               | TCP      | **SMTP**（简单邮件传输协议） |
| 110                  | TCP      | **POP3**（邮局协议版本3）    |
| 143                  | TCP      | **IMAP**（邮件访问协议）     |
| 80、8000、8080、8888 | TCP      | **HTTP**（超文本传输协议）   |
| **数据库**           |          |                              |
| 1433                 | TCP      | SQL Server（数据库管理系统） |
| 1521                 | TCP      | Oracle（甲骨文数据库）       |
| **3306**             | TCP      | **MySQL**（数据库）          |
| 5000                 | TCP      | Sybase/DB2（数据库）         |
| 5432                 | TCP      | PostgreSQL（数据库）         |
| 6379                 | TCP      | Redis（数据库）              |
| 27017-27018          | TCP      | MongoDB（数据库）            |

# IDS、IPS、防火墙

防火墙是第一道防线，相当于门，工作在网络层和传输层。根据IP地址，端口，协议进行过滤

1. 包过滤防火墙
2. 状态检测防火墙

IDS设置在**旁路**，只负责警报并记录日志     HIDS      NIDS        snort

IPS串联在主线路（**在线部署**）可以丢弃恶意数据包    snort-inline

