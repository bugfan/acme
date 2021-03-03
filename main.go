package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"crypto/tls"
	"time"
	

	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/challenge/http01"
	"github.com/go-acme/lego/challenge/tlsalpn01"
	"github.com/go-acme/lego/lego"
	"github.com/go-acme/lego/registration"
)

const PathPrefix = "/.well-known/acme-challenge"

const LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

// const LetsEncrypt = "https://acme-staging-v02.api.letsencrypt.org/directory"

// You'll need a user or account type that implements acme.User
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}


func main() {
	go func(){
		p:=&HTTPSProxy{}
		srv:=p.GetHTTPSServer(":443")
		fmt.Println("https:",srv.ListenAndServeTLS("", ""))
	}()
	go func(){
		p:=&HTTPProxy{}
		srv:=p.GetHTTPServer(":80")
		fmt.Println("http:",srv.ListenAndServe())
	}()
	time.Sleep(5e9)

	// Create a user. New accounts need an email and private key to start.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	myUser := MyUser{
		Email: "908958194@qq.com",
		key:   privateKey,
	}

	config := lego.NewConfig(&myUser)

	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
	config.CADirURL = LetsEncrypt
	config.Certificate.KeyType = certcrypto.RSA2048

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	// We specify an HTTP port of 5002 and an TLS port of 5001 on all interfaces
	// because we aren't running as root and can't bind a listener to port 80 and 443
	// (used later when we attempt to pass challenges). Keep in mind that you still
	// need to proxy challenge traffic to port 5002 and 5001.

	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "5002"))
	if err != nil {
		log.Fatal(err)
	}
	err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", "5001"))
	if err != nil {
		log.Fatal(err)
	}

	// New users will need to register
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	myUser.Registration = reg

	request := certificate.ObtainRequest{
		Domains: []string{"a.flower53.cn"},
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. SAVE THESE TO DISK.
	fmt.Printf("%#v\n", certificates)

	<-chan int(nil)
	// ... all done.
}

type HTTPProxy struct{}

func  (p *HTTPProxy)ServeHTTP(w http.ResponseWriter,r *http.Request)  {
	fmt.Println("ww1,http:",r.URL.String())
	remote, err := url.Parse("http://127.0.0.1:5002")
	if err != nil {
		panic(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxy.ServeHTTP(w, r)
}
func (p *HTTPProxy)GetHTTPServer(listen string)*http.Server{
	return &http.Server{
		Handler:   p,
		Addr:      listen,
	}
}

const ACMETLS1Protocol = "acme-tls/1"
type HTTPSProxy struct{

}

func  (p *HTTPSProxy)ServeHTTP(w http.ResponseWriter,r *http.Request)  {
	fmt.Println("ww2,https:",r.URL.String())
	remote, err := url.Parse("http://127.0.0.1:5001")
	if err != nil {
		panic(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxy.ServeHTTP(w, r)
}


func (p *HTTPSProxy) GetHTTPSServer(listen string) *http.Server {
	tlsconf := &tls.Config{
		// GetCertificate: p.GetCertificate,
		NextProtos:     []string{ACMETLS1Protocol},
	}
	tlsconf.InsecureSkipVerify = true
	
	// tlsconf.MaxVersion = tls.VersionTLS12
	tlsconf.MinVersion = tls.VersionTLS12

	tlsconf.PreferServerCipherSuites = true

	tlsconf.CipherSuites = []uint16{
		//tls.TLS_AES_128_GCM_SHA256,
		//tls.TLS_CHACHA20_POLY1305_SHA256,
		//tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	}

	return &http.Server{
		Handler:   p,
		TLSConfig: tlsconf,
		Addr:      listen,
	}
}