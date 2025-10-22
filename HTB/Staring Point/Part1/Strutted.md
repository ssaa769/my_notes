# 一：拿shell

这是一台LINUX靶机，很久没做linux的了，这一台主要是**CVE-2024-53677: Apache Struts 文件上传漏洞**

nmap扫一下，只有80端口和22端口。

目前感受下来HTB上linux靶机端口开放少，重点web漏洞拿shell，windows重点域渗透，横向移动更重要，很多时候有初始账户，不需要web拿shell

登到web页面看看，经典重定向到strutted.htb，写入/etc/hosts

页面简单明了，就是一个上传文件，限定类型为`Supported file types: JPG, JPEG, PNG, GIF`

左上角有一列链接 ，全点上一遍，在最后的downloads时候下载了一个zip安装包，解压看一看

```
└─# ls
context.xml  README.md  tomcat-users.xml
Dockerfile   strutted
```

```
└─# ls strutted 
mvnw  mvnw.cmd  pom.xml  src  target
```

这里有一个pom.xml。pom.xml是maven的主要配置文件。

maven就是一个 项目管理与构建自动化工具，主要用于 Java 项目。它的目的和Make相同，即自动化构建。Make是通过Makefile指定工作步骤，Maven通过pom.xml指定需要什么配置，然后由maven进行构建。这个思想很类似docker compose的yml配置文件，它们都是声明式配置。

POM 是 Maven 工程的基本工作单元，是一个 XML 文件，包含了项目的基本信息，用于描述项目如何构建，声明项目依赖，等等。

执行任务或目标时，Maven 会在当前目录中查找 POM，获取所需的配置信息，然后执行目标。我们在这个pom.xml配置文件中找到了：

```
<name>Strutted™</name>
    <description>Instantly upload an image and receive a unique, shareable link. Keep your images secure, accessible, and easy to share—anywhere, anytime.</description>

    <properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <struts2.version>6.3.0.1</struts2.version>
```

这里就出现本机主要目标了：Apache Struts文件上传漏洞：CVE-2024-53677

https://www.freebuf.com/vuls/418881.html

> Struts 2.0.0 - 2.3.37（EOL）
>
> Struts 2.5.0 - 2.5.33（EOL）
>
> Struts 6.0.0 - 6.3.0.2

这里的版本是6.3.0.1,刚好受影响。

Apache Struts是美国阿帕奇（Apache）基金会的一个开源项目，是一套用于创建企业级Java Web应用的开源MVC框架。

> **根本原因**: 在解析上传文件的文件名时，Struts 2 内置的 `MultiPartRequest` 实现未能正确处理包含 Unicode 字符的文件名，导致攻击者可以通过构造特殊的文件名来绕过已有的文件扩展名和路径遍历检查，从而将恶意文件上传到服务器上的任意可访问目录。

在 Struts 2 中，有一个重要特性——值栈，它帮助我们能够轻松访问 Action 类中的属性。Action类是structs2的核心类，它存放了很多信息，而我们可以通过值栈访问其中的信息。

比如这样一个类：

```
package com.struts2;
import com.opensymphony.xwork2.ActionSupport;
public class MyAction extends ActionSupport {
    private String message;
    @Override
    public String execute() throws Exception {
        message = "Hello";
        return SUCCESS;
    }
    public String getMessage() {
        return message;
    }
}
```

我们使用top关键字即可访问栈顶对象。[0].top.message就可以访问到Hello

回到靶机，我们原来上传文件的请求如下：

```
POST /upload.action HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
----WebKitFormBoundary
Content-Disposition: form-data; name="Upload"; filename="1.txt"
Content-Type: text/plain
example text
----WebKitFormBoundary--
```

我们想要上传的文件最后是一个jsp可执行文件，就可以使用[0].top.uploadFilename = “1.jsp”修改，请求包如下：

> 当使用 multipart/form-data 格式提交表单数据时，每个子部分（例如每个表单字段和任何与字段数据相关的文件）都需要提供一个 Content-Disposition 标头，以提供相关信息。标头的第一个指令始终为 *form-data*，并且还必须包含一个 *name* 参数来标识相关字段。

```
POST /upload.action HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
----WebKitFormBoundary
Content-Disposition: form-data; name="Upload"; filename="1.txt"
Content-Type: text/plain
example text
----WebKitFormBoundary
content-Disposition: form-data; name="top.UploadFileName"
shell.jsp
----WebKitFormBoundary--
```

这里其实有两个问题，为什么数据包中请求就等于执行了？还有为什么这里没有[0]。

这其实就涉及到这个上传漏洞的本质原因：**Struts2 的 OGNL 表达式注入**。

Struts2 框架的核心机制之一就是 **“将 HTTP 请求参数自动绑定到 Action 对象的属性”**。这个机制是由 OGNL 驱动的。struts2会自动提取top.UploadFileName=shell.jsp为OGNL表达式执行，从而绑定参数到Action对象的uploadFile属性，最后保存的文件名就被我们修改了。还有就是为什么没有[0]，因为struct2会先使用ParametersInterceptor类处理HTTP请求中的文件上传请求，提取参数和值，最后通过OGNL表达式绑定到Action类中。而ParametersInterceptor类的isvalid方法有一个过滤：
```
\w+((\.\w+)|(\[\d+])|(\(\d+\))|(\['(\w-?|[\u4e00-\u9fa5]-?)+'])|(\('(\w-?|
[\u4e00-\u9fa5]-?)+'\)))*
```

这个过滤会过滤[0].top，但是[0].top指的本来就是栈顶，和直接top是一样的，所以直接top.UploadFileName绕过过滤。



回到靶机，我们下载的zip压缩包中有源码，分析源码，发现对文件上传本身有两个检测：MIME检测和文件头检测，这简单，直接伪造就可。这里还要注意一点，上传后是生成随即格式如 http://strutted.htb/s/d2dee165的路径。我们无法预测随机数，所以改uploadFilename的时候直接改成`../../shell.jsp`即可

writeup中是上传一个命令执行的jsp，然后下载攻击机反弹shell的sh脚本，添加执行权限并执行，也可以直接使用反弹shell的jsp webshell。

# 二：提权

`sudo -l`查看，发现tcpdump有sudo权限，直接上GTFObins照着方法提权就可。本质是利用tcpdump的两个参数，一个`-z`指定脚本，一个`-Z`指定以哪个用户运行