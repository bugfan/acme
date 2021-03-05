package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"

	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/challenge/tlsalpn01"
	"github.com/go-acme/lego/lego"
	"github.com/go-acme/lego/registration"
)

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

	// Create a user. New accounts need an email and private key to start.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	myUser := MyUser{
		Email: "917719033@qq.com",
		key:   privateKey,
	}

	config := lego.NewConfig(&myUser)

	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
	config.CADirURL = "https://acme-v02.api.letsencrypt.org/directory"
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
	err = client.Challenge.SetHTTP01Provider(NewHTTP01Provider())
	if err != nil {
		log.Fatal(err)
	}
	// err = client.Challenge.SetTLSALPN01Provider(NewTLSALPN01Provider())
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// New users will need to register
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	myUser.Registration = reg

	request := certificate.ObtainRequest{
		Domains: []string{"app.lt53.cn"},
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. SAVE THESE TO DISK.
	fmt.Printf("%#v\n", certificates)

	// ... all done.
}

type HTTP01Provider struct {
	tokens   map[string]string
	keyAuths map[string]string
}

func NewHTTP01Provider() *HTTP01Provider {
	return &HTTP01Provider{
		tokens:   make(map[string]string),
		keyAuths: make(map[string]string),
	}
}

func (s *HTTP01Provider) Present(domain, token, keyAuth string) error {
	s.tokens[domain] = token
	s.keyAuths[domain] = keyAuth
	return nil
}

func (s *HTTP01Provider) CleanUp(domain, token, keyAuth string) error {
	if _, ok := s.tokens[domain]; ok {
		delete(s.tokens, token)
	}

	if _, ok := s.keyAuths[domain]; ok {
		delete(s.keyAuths, token)
	}
	return nil
}

func (s *HTTP01Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		token := s.tokens[r.Host]
		if token != "" && r.URL.Path == ChallengePath(token) {
			w.Header().Add("Content-Type", "text/plain")
			w.Write([]byte(s.keyAuths[r.Host]))
			return

		}
	}

	w.WriteHeader(http.StatusUnprocessableEntity)
	w.Write([]byte("Unsupported"))
}

func ChallengePath(token string) string {
	return "/.well-known/acme-challenge/" + token
}

type TLSALPN01Provider struct {
	tokens   map[string]string
	keyAuths map[string]string
}

func NewTLSALPN01Provider() *TLSALPN01Provider {
	return &TLSALPN01Provider{
		tokens:   make(map[string]string),
		keyAuths: make(map[string]string),
	}
}

func (s *TLSALPN01Provider) Present(domain, token, keyAuth string) error {
	s.tokens[domain] = token
	s.keyAuths[domain] = keyAuth
	return nil
}

func (s *TLSALPN01Provider) CleanUp(domain, token, keyAuth string) error {
	if _, ok := s.tokens[domain]; ok {
		delete(s.tokens, domain)
	}

	if _, ok := s.keyAuths[domain]; ok {
		delete(s.keyAuths, domain)
	}
	return nil
}
func (s *TLSALPN01Provider) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	for _, v := range info.SupportedProtos {
		if k, has := s.keyAuths[info.ServerName]; has && v == "acme-tls/1" {
			return tlsalpn01.ChallengeCert(info.ServerName, k)
		}
	}
	return nil, nil
}
