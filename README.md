 ### acme client demo
 ```
 # 用http方式验证，占用80端口
 ./lego --email="mail@qq.com" --domains="domain.com" --http run

 # 用tls方式验证，占用443端口
 ./lego --email="mail@qq.com" --domains="domain.com" --tls run


 # 用dns方式验证，不占端口，解析需要对,dns provider 很多需要根据云厂商切换
 ./lego --email="mail@qq.com" --domains="domain.com" --dns="route53|namecheap" run
 ```

```
HTTP-01：通过HTTP访问服务器80端口的.well-known/acme-challenge验证。
DNS-01：在DNS中添加_acme-challenge开头的TXT记录，这种方式因为能签发通配符证书（Wildcard）而被大范围使用。
TLS-SNI-01、TLS-ALPN-01：通过TLS的方式对443端口访问进行验证。(TLS-ALPN-01支持的客户端非常少,TLS-SNI因为漏洞被遗弃)
```

 ## 问题
 1. http验证
 ```
 http：总是遇到qcloud拦截，貌似是没有备案导致，但是dns没有问题
[app.lt53.cn] acme: error: 403 :: urn:ietf:params:acme:error:unauthorized :: During secondary validation: Invalid response from https://dnspod.qcloud.com/static/webblock.html?d=app.lt53.cn [203.205.224.59]: "<!DOCTYPE html>\n<html>\n\t<head>\n\t\t<meta charset=\"utf-8\" />\n\t\t<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge,chrome=1\" />\n\t\t<", url: 



 ```
 2. tls
 ```
root@VM-0-10-ubuntu:/home# ./acem 
2021/03/10 18:20:31 [INFO] acme: Registering account for 917719033@qq.com
2021/03/10 18:20:32 [INFO] [www.lbelieve.cn] acme: Obtaining bundled SAN certificate
2021/03/10 18:20:32 [INFO] [www.lbelieve.cn] AuthURL: https://acme-v02.api.letsencrypt.org/acme/authz-v3/11452689397
2021/03/10 18:20:32 [INFO] [www.lbelieve.cn] acme: use tls-alpn-01 solver
2021/03/10 18:20:32 [INFO] [www.lbelieve.cn] acme: Trying to solve TLS-ALPN-01
2021/03/10 18:20:39 [INFO] Unable to deactivate the authorization: https://acme-v02.api.letsencrypt.org/acme/authz-v3/11452689397
2021/03/10 18:20:39 acme: Error -> One or more domains had a problem:
[www.lbelieve.cn] acme: error: 400 :: urn:ietf:params:acme:error:malformed :: Server only speaks HTTP, not TLS, url:
 ```
 ```
 // 443没监听
2021/03/20 22:32:57 Unable to deactivate the authorization: https://acme-v02.api.letsencrypt.org/acme/authz-v3/11705545896
obtain result2: error: one or more domains had a problem:
[www.lbelieve.cn] acme: error: 400 :: urn:ietf:params:acme:error:connection :: Connection refused
 ```
 ```
 // tls server tlsconfig配置缺东西
%w tls: neither Certificates, GetCertificate, nor GetConfigForClient set in Config
 ```