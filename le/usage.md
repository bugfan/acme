### lego usage
 ```
 # 用http方式验证，占用80端口
 ./lego --email="mail@qq.com" --domains="domain.com" --http run

 # 用tls方式验证，占用443端口
 ./lego --email="mail@qq.com" --domains="domain.com" --tls run


 # 用dns方式验证，不占端口，解析需要对,dns provider 很多需要根据云厂商切换
 ./lego --email="mail@qq.com" --domains="domain.com" --dns="route53|namecheap" run
 ```
