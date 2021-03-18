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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/bugfan/acme/certcrypto"
	"github.com/bugfan/acme/certificate"
	"github.com/bugfan/acme/lego"
	"github.com/bugfan/acme/registration"
)

const LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

// const LetsEncrypt = "https://acme-staging-v02.api.letsencrypt.org/directory"

func NewACME(Email string) (*ACME, error) {
	return NewACMEWithDir(Email, "")
}

func NewACMEWithDir(Email string, LetsEncryptDIR string) (*ACME, error) {
	if !CheckEmail(Email) {
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
	acme := &ACME{
		user: user,
	}
	config := lego.NewConfig(acme.user)
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
	acme.cli = client
	return acme, nil
}

type ACME struct {
	cli           *lego.Client
	user          *acmeUser
	http01Handler http.Handler
}

func (a *ACME) SetHTTPHandler(h http.Handler) {
	a.http01Handler = h
}

func (a *ACME) Obtain(domain ...string) {
	// We specify an HTTP port of 5002 and an TLS port of 5001 on all interfaces
	// because we aren't running as root and can't bind a listener to port 80 and 443
	// (used later when we attempt to pass challenges). Keep in mind that you still
	// need to proxy challenge traffic to port 5002 and 5001.
	http01 := NewHTTP01Provider()
	// tls01 := NewTLSALPN01Provider()

	av := os.Getenv("ACME_V")
	if av == "" {
		go func() {
			http.ListenAndServe(":80", http01)
		}()
	} else {
		// go func() {
		// 	http.ListenAndServe(":443", nil)
		// }()
	}

	if av == "" {
		time.Sleep(1e9)
		err := a.cli.Challenge.SetHTTP01Provider(http01)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		// time.Sleep(1e9)
		// err = client.Challenge.SetTLSALPN01Provider(tls01)
		// if err != nil {
		// 	log.Fatal(err)
		// }
	}

	// // New users will need to register
	reg, err := a.cli.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	a.user.Registration = reg

	request := certificate.ObtainRequest{
		Domains: domain,
		Bundle:  true,
	}
	certificates, err := a.cli.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. SAVE THESE TO DISK.
	fmt.Printf("%#v\n", certificates)
	data, err := json.Marshal(certificates)
	fmt.Println("aaa :", err, string(data))
	crt, err := ParseCertificate(string(certificates.Certificate)+string(certificates.IssuerCertificate), string(certificates.PrivateKey))
	fmt.Println("CERT:", err, crt.Key, crt.Cert, crt.Intermediate)
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

func CheckEmail(email string) bool {
	if len(email) == 0 || len(email) >= 255 {
		return false
	}
	emailRegexp := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	if !emailRegexp.MatchString(email) {
		return false
	}
	return true
}
