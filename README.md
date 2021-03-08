 ### acme client demo
 ```
 # 用http方式验证，占用80端口
 ./lego --email="mail@qq.com" --domains="domain.com" --http run

 # 用tls方式验证，占用443端口
 ./lego --email="mail@qq.com" --domains="domain.com" --tls run


 # 用dns方式验证，不占端口，解析需要对,dns provider 很多需要根据云厂商切换
 ./lego --email="mail@qq.com" --domains="domain.com" --dns="route53|namecheap" run
 ```

 ## 问题
 1. http验证
 ```
 http：总是遇到qcloud拦截，貌似是没有备案导致，但是dns没有问题
[app.lt53.cn] acme: error: 403 :: urn:ietf:params:acme:error:unauthorized :: During secondary validation: Invalid response from https://dnspod.qcloud.com/static/webblock.html?d=app.lt53.cn [203.205.224.59]: "<!DOCTYPE html>\n<html>\n\t<head>\n\t\t<meta charset=\"utf-8\" />\n\t\t<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge,chrome=1\" />\n\t\t<", url: 



 ```