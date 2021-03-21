package acme

import (
	"bytes"
	"context"
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
	"net/http"
	"os"
	"regexp"

	"github.com/bugfan/acme/certcrypto"
	"github.com/bugfan/acme/certificate"
	"github.com/bugfan/acme/le"
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
	config := le.NewConfig(o.user)
	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
	config.CADirURL = LetsEncrypt
	config.Certificate.KeyType = certcrypto.RSA2048

	// A client facilitates communication with the CA server.
	client, err := le.NewClient(config)
	if err != nil {
		return nil, err
	}
	o.cli = client
	return o, nil
}

type acme struct {
	cli               *le.Client
	user              *acmeUser
	http01Provider    HTTP01Provider
	tlsalpn01Provider Provider
}

func (a *acme) SetHTTP01Provider(p HTTP01Provider) {
	a.http01Provider = p
}

func (a *acme) SetTLSALPN01Provider(p Provider) {
	a.tlsalpn01Provider = p
}

func (a *acme) Obtain(domain ...string) (cert *Certificate, err error) {
	if a.http01Provider == nil && a.tlsalpn01Provider == nil {
		return nil, errors.New("no acme provider found!")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if a.http01Provider != nil {
		p := &http.Server{Handler: a.http01Provider}
		go func() {
			<-ctx.Done()
			if p != nil {
				p.Shutdown(ctx)
			}
		}()
		go func() {
			fmt.Println("Listening At '80'")
			err := p.ListenAndServe()
			fmt.Println("Listen '80' end:", err)
		}()
		err = a.cli.Challenge.SetHTTP01Provider(a.http01Provider)
		if err != nil {
			return nil, err
		}
	}

	if a.tlsalpn01Provider != nil {
		err = a.cli.Challenge.SetTLSALPN01Provider(a.tlsalpn01Provider)
		if err != nil {
			return nil, err
		}
	}

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
