## acme (use as library)
- [ ] dns
- [x] http01
- [x] tlsalpn1

<br>

## ✨ 简介

HTTP-01：通过HTTP访问服务器80端口的/.well-known/acme-challenge验证。
DNS-01：在DNS中添加_acme-challenge开头的TXT记录，这种方式因为能签发通配符证书（Wildcard）而被大范围使用。
TLS-SNI-01、TLS-ALPN-01：通过TLS的方式对443端口访问进行验证。(TLS-ALPN-01支持的客户端非常少,TLS-SNI因为漏洞被遗弃)

<br>

- tls
```
占用443端口，需要从从连接上拿到临时证书，然后监听，从这个tls上获取证书；或者通过获取现有证书从tls连接上验证并获取新证书
```
- http 
```
占用80，交互只涉及到http固定目录，设随机码校验，校验通过，可以获取证书；也可以在nginx配置验证路由，在golang里面obtain证书
server {
        listen  80 default_server;
        root /usr/local/nginx/html;
        location / {
                return 404;
        }
        location ^~ /.well-known/acme-challenge/ {
                default_type "text/plain";

        }
        location = /.well-known/acme-challenge/ {
                return 404;
        }
```
- dns
```
不占端口，需要知道dns厂商，需要在dns服务器做txt记录，但是可以获取泛域名证书
```

<br>

## 🦊 如何使用？👇是一些例子

- http01方式
```
// demo1
import "github.com/bugfan/acme"

type H struct {}
func (h *H) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println("your http.handler", r.URL.String())
    // todo something

}
func main(){
    h := &H{}
    p := acme.NewHTTP01Provider(h)
	a, err := acme.NewACME("youremail")
	if err != nil {
		fmt.Println("new error:", err)
		return
	}
	a.SetHTTP01Provider(p)
    cert, err := a.Obtain("app.xxx.cn")
    if err != nil {
        fmt.Println("obtain result:", err)
        return
    }
    fmt.Println("obtain result:", cert.Key, cert.Cert, cert.Intermediate)
}
```
```
// demo2
import "github.com/bugfan/acme"

type H struct {}
func (h *H) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println("your http.handler", r.URL.String())
    // todo something

}
func main(){
    h := &H{}
    p := acme.NewHTTP01Provider(h)
	a, err := acme.NewACME("youremail")
	if err != nil {
		fmt.Println("new error:", err)
		return
	}
	// a.SetHTTP01Provider(p) // not set
    cert, err := a.Obtain("app.xxx.cn")
    if err != nil {
        fmt.Println("obtain result:", err)
        return
    }
    fmt.Println("obtain result:", cert.Key, cert.Cert, cert.Intermediate)
	http.ListenAndServe(":80", nil) // if not set,should you to listen at '80'
}
```

- tlsalpn1方式
```
// demo1 你的服务没有占用443（显然这种情况比较少）
import "github.com/bugfan/acme"
func main(){
   a, err := acme.NewACME("your@qq.com")
	if err != nil {
		fmt.Println("new error:", err)
		return
	}
	tp := acme.NewDefaultTLSALPN01Provider()
	a.SetTLSALPN01Provider(tp)
	cert, err := a.Obtain("app.xxx.cn")
	if err != nil {
		fmt.Println("obtain result:", err)
		return
	}
	fmt.Println("obtain result:", cert.Key, cert.Cert, cert.Intermediate)
}
```
```
// demo2 你的服务占用了443
import "github.com/bugfan/acme"
var myacme acme.ACME
func init() {
	var err error
	myacme, err = acme.NewACME("89898989@qq.com")
	if err != nil {
		fmt.Println("new acme error:", err)
	}
}
func main() {
	// ...

	go func() {
		getYourHTTPSServer().ListenAndServeTLS("your-cert-filt-path", "your-key-file-path")
	}()

	go func() {
		time.Sleep(5e9) // or if when you need obtain
		cert, err := myacme.Obtain("app.xxx.cn")
		if err != nil {
			fmt.Println("obtain result:", err)
			return
		}
		fmt.Println("obtain result:", cert.Key, cert.Cert, cert.Intermediate)
	}()

    // ...
	<-chan int(nil)
}
func getYourHTTPSServer() *http.Server {
	tlsConf := &tls.Config{}
	handler := &H{}
    /*
    * one of the following ways is ok
    */
	// demo1 Certificates()
	// certProvider := handler

	//demo2 GetCertificate(*tls.ClientHelloInfo)
	certProvider := handler

	//demo3 GetConfigForClient(*tls.ClientHelloInfo)
	// certProvider := handler

	tc, err := acme.NewACMETLSConfig(tlsConf, certProvider)
	if err != nil {
		fmt.Println("NewACMETLSConfig error:", err)
		panic(err) // or tc=tlsConf
	}
	return &http.Server{
		Handler:   handler,
		TLSConfig: tc,
		Addr:      ":443",
	}
}
type H struct{}
func (h *H) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println("your http.handler", r.URL.String())
	// todo something

}
func (h *H) Certificates() []*tls.Certificate {
	certs := make([]*tls.Certificate, 0)
	certs = append(certs, h.Cert())
	return certs
}
func (h *H) Cert() *tls.Certificate {
	// need read from your cert file
	yourcert, _ := tls.X509KeyPair([]byte(fmt.Sprintf("%s\n%s", "your cert data", "your intermediate data")), []byte("your key"))
	return &yourcert
}
var ServerIP string = "212.45.32.55" // your server ip
func (h *H) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName == ServerIP {
		return h.Cert(), nil
	}
	return nil, nil
}
```

<br>

## 🐛 签发免费证书常见问题
- http 没有备案被云厂商拦截了
 ```
[app.xxx.cn] acme: error: 403 :: urn:ietf:params:acme:error:unauthorized :: During secondary validation: Invalid response from https://dnspod.qcloud.com/static/webblock.html?d=app.xxx.cn [203.205.224.59]: "<!DOCTYPE html>\n<html>\n\t<head>\n\t\t<meta charset=\"utf-8\" />\n\t\t<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge,chrome=1\" />\n\t\t<", url: 
 ```

- tls 不是tls的监听在443
 ```
root@VM-0-10-ubuntu:/home# ./acem 
2021/03/10 18:20:31 [INFO] acme: Registering account for 917719033@qq.com
2021/03/10 18:20:32 [INFO] [www.xxxx.cn] acme: Obtaining bundled SAN certificate
2021/03/10 18:20:32 [INFO] [www.xxxx.cn] AuthURL: https://acme-v02.api.letsencrypt.org/acme/authz-v3/11452689397
2021/03/10 18:20:32 [INFO] [www.xxxx.cn] acme: use tls-alpn-01 solver
2021/03/10 18:20:32 [INFO] [www.xxxx.cn] acme: Trying to solve TLS-ALPN-01
2021/03/10 18:20:39 [INFO] Unable to deactivate the authorization: https://acme-v02.api.letsencrypt.org/acme/authz-v3/11452689397
2021/03/10 18:20:39 acme: Error -> One or more domains had a problem:
[www.xxxx.cn] acme: error: 400 :: urn:ietf:params:acme:error:malformed :: Server only speaks HTTP, not TLS, url:
 ```

- tls 443没起
 ```
 // 443没监听
2021/03/20 22:32:57 Unable to deactivate the authorization: https://acme-v02.api.letsencrypt.org/acme/authz-v3/11705545896
obtain result2: error: one or more domains had a problem:
[www.xxxx.cn] acme: error: 400 :: urn:ietf:params:acme:error:connection :: Connection refused
 ```

- tls 这是tls层的tls.config配置缺东西
 ```
// tls server tlsconfig配置缺东西
%w tls: neither Certificates, GetCertificate, nor GetConfigForClient set in Config
 ```

- rate 这是签发次数太多了
 ```
2021/03/21 19:12:14 [app.xxx.cn] acme: Obtaining bundled SAN certificate
obtain result2: acme: error: 429 :: POST :: https://acme-v02.api.letsencrypt.org/acme/new-order :: urn:ietf:params:acme:error:rateLimited :: Error creating new order :: too many certificates already issued for exact set of domains: app.xxx.cn: see https://letsencrypt.org/docs/rate-limits/
 ```

- 解析不对
 ```
www.xxx.cn 签发失败: get directory at 'https://acme-v02.api.letsencrypt.org/directory': Get "https://acme-v02.api.letsencrypt.org/directory": dial tcp: lookup acme-v02.api.letsencrypt.org on 127.0.0.11:53: server misbehaving

解析不对，进入app这个容器（或者主机）内部，执行 echo '172.65.32.248 acme-v02.api.letsencrypt.org' > /etc/hosts
```
