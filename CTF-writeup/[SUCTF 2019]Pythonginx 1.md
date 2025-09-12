![image-20250912134651809](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250912134651809.png)

整理一下python代码

```python
from urllib import parse
from urllib.parse import urlsplit, urlunsplit
from flask import Flask, request
import urllib.request

app = Flask(__name__)

@app.route('/getUrl', methods=['GET', 'POST'])
def getUrl():
    url = request.args.get("url")
    host = parse.urlparse(url).hostname
    if host == 'suctf.cc':
        return "我扌 your problem? 111"
    
    parts = list(urlsplit(url))
    host = parts[1]
    if host == 'suctf.cc':
        return "我扌 your problem? 222 " + host
    
    newhost = []
    for h in host.split('.'):
        newhost.append(h.encode('idna').decode('utf-8'))
    parts[1] = '.'.join(newhost)
    
    # 去掉 url 中的空格
    finalUrl = urlunsplit(parts).split(' ')[0]
    host = parse.urlparse(finalUrl).hostname
    
    if host == 'suctf.cc':
        return urllib.request.urlopen(finalUrl).read()
    else:
        return "我扌 your problem? 333"

if __name__ == '__main__':
    app.run(debug=True)
```

关键是`urllib.request.urlopen(finalUrl).read()`这是一个明显的SSRF漏洞。中间代码都是在层层过滤，目标就是绕过过滤了。

html注释如下：

```html
    <!-- Dont worry about the suctf.cc. Go on! -->
    <!-- Do you know the nginx? -->
```

那么ssrf的目标显然就是nginx,一些文件如下

- 配置文件存放目录：/etc/nginx

- 主配置文件：/etc/nginx/conf/nginx.conf
- 管理脚本：/usr/lib64/systemd/system/nginx.service
- 模块：/usr/lisb64/nginx/modules
- 应用程序：/usr/sbin/nginx
- 程序默认存放位置：/usr/share/nginx/html
- 日志默认存放位置：/var/log/nginx
- 配置文件目录为：/usr/local/nginx/conf/nginx.conf

用file://读取这些文件。为了绕过对主机名的绕制，我们主要利用idna（国际化域名应用）这里有`h.encode('idna').decode('utf-8')`我们举例℆这个字符,如果使用python3进行idna编码的话是`b’c/u’`如果再使用utf-8进行解码的话结果是`c/u`变成了三个ascii字符。

因此可以构造如下payload:

`file://suctf.c℆sr/local/nginx/conf/nginx.conf`
