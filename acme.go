package acme

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/bugfan/acme/certcrypto"
	"github.com/bugfan/acme/certificate"
	"github.com/bugfan/acme/lego"
	"github.com/bugfan/acme/registration"
)

const LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

// const LetsEncrypt = "https://acme-staging-v02.api.letsencrypt.org/directory"

type ACME interface {
	SetHTTP01Provider(HTTP01Provider)
	SetTLSALPN01Provider(Provider)
	Obtain(domains ...string) (*Certificate, error)
}

func NewACME(Email string) (ACME, error) {
	return NewACMEWithDir(Email, "")
}

func NewACMEWithDir(Email string, LetsEncryptDIR string) (ACME, error) {
	if !checkEmail(Email) {
		return nil, errors.New(fmt.Sprintf("email:%s is error", Email))
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	user := &acmeUser{
		Email: Email,
		key:   privateKey,
	}
	o := &acme{
		user: user,
	}
	config := lego.NewConfig(o.user)
	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
	config.CADirURL = LetsEncrypt
	// Custom LetsEncrypt dir
	if LetsEncryptDIR != "" {
		config.CADirURL = LetsEncryptDIR
	}
	config.Certificate.KeyType = certcrypto.RSA2048

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}
	o.cli = client
	return o, nil
}

type acme struct {
	cli               *lego.Client
	user              *acmeUser
	http01Provider    HTTP01Provider
	tlsalpn01Provider Provider
}

// if set , use given http handler
func (a *acme) SetHTTP01Provider(p HTTP01Provider) {
	a.http01Provider = p
}

// if set , use given tls handler
func (a *acme) SetTLSALPN01Provider(p Provider) {
	a.tlsalpn01Provider = p
}

func (a *acme) Obtain(domain ...string) (cert *Certificate, err error) {
	// if a.http01Provider == nil && a.tlsalpn01Provider == nil {
	// 	return nil, errors.New("no provider found!")
	// }
	// if a.http01Provider != nil {
	// 	go func() {
	// 		log.Printf("acme http01 bind error:%s", http.ListenAndServe(":80", a.http01Provider))
	// 	}()
	// 	time.Sleep(time.Second / 10)
	// }

	// if a.tlsalpn01Provider != nil {
	// 	go func() {
	// 		log.Printf("acme tlsalpn01 bind error:%s", http.ListenAndServe(":443", nil)) // todo tls
	// 	}()
	// 	time.Sleep(time.Second / 10)
	// }

	// err = a.cli.Challenge.SetHTTP01Provider(a.http01Provider)
	// if err != nil {
	// 	return nil, err
	// }
	// err = a.cli.Challenge.SetTLSALPN01Provider(a.tlsalpn01Provider) //tlsalpn01.NewProviderServer("", "5600"))
	// if err != nil {
	// 	return nil, err
	// }

	reg, err := a.cli.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, err
	}
	a.user.Registration = reg

	request := certificate.ObtainRequest{
		Domains: domain,
		Bundle:  true,
	}
	certificates, err := a.cli.Certificate.Obtain(request)
	if err != nil {
		return nil, err
	}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. SAVE THESE TO DISK.
	return ParseCertificate(string(certificates.Certificate)+string(certificates.IssuerCertificate), string(certificates.PrivateKey))
}

type acmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string {
	return u.Email
}
func (u acmeUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

type Certificate struct {
	Cert         string
	Key          string
	Intermediate string
}

func (c *Certificate) TLSCertficate() (*tls.Certificate, error) {
	crt, err := tls.X509KeyPair([]byte(fmt.Sprintf("%s\n%s", c.Cert, c.Intermediate)), []byte(c.Key))
	if err != nil {
		return nil, err
	}
	return &crt, nil
}

func (c *Certificate) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return c.TLSCertficate()
}

func ParseCertificate(certPEMBlock, keyPEMBlock string) (*Certificate, error) {
	tlsCert, err := tls.X509KeyPair([]byte(certPEMBlock), []byte(keyPEMBlock))
	if err != nil {
		return nil, err
	}
	leaf := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsCert.Certificate[0]}))
	var intermediate string
	if len(tlsCert.Certificate) > 1 {
		buffer := bytes.NewBuffer([]byte{})
		for _, cert := range tlsCert.Certificate[1:] {
			_ = pem.Encode(buffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
		}
		intermediate = buffer.String()
	}
	var key string
	switch k := tlsCert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		key = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		key = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))
	default:
		return nil, errors.New("unsupported privatekey")
	}
	return &Certificate{
		Cert:         leaf,
		Key:          key,
		Intermediate: intermediate,
	}, nil
}

func checkEmail(email string) bool {
	if len(email) == 0 || len(email) >= 255 {
		return false
	}
	emailRegexp := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	if !emailRegexp.MatchString(email) {
		return false
	}
	return true
}
