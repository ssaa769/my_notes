主页面要求提交一个正确的字符串，给出了源码如下:

```php
<?php
include 'config.php'; // FLAG is defined in config.php
#防止你直接访问config.php/*
if (preg_match('/config\.php\/*$/i', $_SERVER['PHP_SELF'])) {
  exit("I don't know what you are thinking, but I won't let you read it :)");
}
#展示源码
if (isset($_GET['source'])) {
  highlight_file(basename($_SERVER['PHP_SELF']));
  exit();
}
#如果你猜到了$secret就直接返回flag
$secret = bin2hex(random_bytes(64));
if (isset($_POST['guess'])) {
  $guess = (string) $_POST['guess'];
  if (hash_equals($secret, $guess)) {
    $message = 'Congratulations! The flag is: ' . FLAG;
  } else {
    $message = 'Wrong.';
  }
}
?>
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Can you guess it?</title>
  </head>
  <body>
    <h1>Can you guess it?</h1>
    <p>If your guess is correct, I'll give you the flag.</p>
    <p><a href="?source">Source</a></p>
    <hr>
<?php if (isset($message)) { ?>
    <p><?= $message ?></p>
<?php } ?>
    <form action="index.php" method="POST">
      <input type="text" name="guess">
      <input type="submit">
    </form>
  </body>
</html>
```

跟着题目的意思来就是猜测$secret的值。暴力破解这里不可行，因为有64个字节，计算量过大。我们转变思路，源码开头特意告诉你flag定义在config.php中，并且用了一个正则防止你访问。这很明显，我们要想办法读config.php，不然题目不用给出这些信息。

```php
if (isset($_GET['source'])) {
  highlight_file(basename($_SERVER['PHP_SELF']));
  exit();
}
```

这一部分显然就是帮你读取config.php的。可以看到，这里使用了`basename($_SERVER['PHP_SELF'])`的组合。

这题的关键:

basename()函数就是截取最后一段的文件名，但是最后一段为不可见字符时会退取上一层的目录。即..../index.php/%80会取index.php

我们构造url如下

```
http://......../index.php/config.php/%ff?source
```

首先$_SERVER['PHP_SELF']获取的字符串是index.php/config.php/%ff，最后的%ff匹配不上能过正则。然后basename截取到的是config.php/%ff，最后是一个不可显字符，回退成config.php，于是可以读取。