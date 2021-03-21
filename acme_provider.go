package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/bugfan/acme/challenge/tlsalpn01"
)

/*
* http01
 */
const PathPrefix = "/.well-known/acme-challenge"

type Provider interface {
	Present(string, string, string) error
	CleanUp(string, string, string) error
}

type HTTP01Provider interface {
	ServeHTTP(http.ResponseWriter, *http.Request)
	Provider
}

func NewHTTP01Provider(h http.Handler) HTTP01Provider {
	http01 := &http01Provider{
		tokens:   make(map[string]string),
		keyAuths: make(map[string]string),
	}
	http01.h = h
	return http01
}

type http01Provider struct {
	tokens   map[string]string
	keyAuths map[string]string
	h        http.Handler
}

func (s *http01Provider) Present(domain, token, keyAuth string) error {
	s.tokens[domain] = token
	s.keyAuths[domain] = keyAuth
	return nil
}

func (s *http01Provider) CleanUp(domain, token, keyAuth string) error {
	if _, ok := s.tokens[domain]; ok {
		delete(s.tokens, token)
	}

	if _, ok := s.keyAuths[domain]; ok {
		delete(s.keyAuths, token)
	}
	return nil
}
func (s *http01Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, PathPrefix) {
		// fmt.Println("http01provider	serverhttp in:", r.URL.String(), s.tokens[r.Host])
		if r.Method == http.MethodGet {
			token := s.tokens[r.Host]
			if token != "" && r.URL.Path == challengePath(token) {
				w.Header().Add("Content-Type", "text/plain")
				w.Write([]byte(s.keyAuths[r.Host]))
				return

			}
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte("Unsupported"))
		return
	}
	s.h.ServeHTTP(w, r)
}

func challengePath(token string) string {
	return PathPrefix + "/" + token
}

/*
*	tlsalpn01
 */

const ACMETLS1Protocol = "acme-tls/1"

/*
*  usage
 */
// 1. port 443 not occupied
func NewDefaultTLSALPN01Provider() Provider {
	return tlsalpn01.NewProviderServer("", "443")
}

type Certificates interface {
	Certificates() []tls.Certificate
}
type GetCertificate interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}
type GetConfigForClient interface {
	GetConfigForClient(*tls.ClientHelloInfo) (*tls.Config, error)
}

// 2. customize tls server
// tls: neither Certificates, GetCertificate, nor GetConfigForClient set in Config
func NewACMETLSConfig(tlsconfig *tls.Config, certProvider interface{}) (*tls.Config, error) {
	if tlsconfig == nil {
		return nil, errors.New("tlsconfig is nil")
	}
	if certProvider == nil {
		return nil, errors.New("at least one certificate provider")
	}
	cpok := false
	if !cpok {
		reflectVal := reflect.ValueOf(certProvider)
		t := reflect.Indirect(reflectVal).Type()
		newObj := reflect.New(t)
		handler, ok := newObj.Interface().(Certificates)
		if ok {
			cpok = true
			tlsconfig.Certificates = handler.Certificates()
		}
	}
	if !cpok {
		reflectVal := reflect.ValueOf(certProvider)
		t := reflect.Indirect(reflectVal).Type()
		newObj := reflect.New(t)
		handler, ok := newObj.Interface().(GetCertificate)
		if ok {
			cpok = true
			tlsconfig.GetCertificate = handler.GetCertificate
		}
	}
	if !cpok {
		reflectVal := reflect.ValueOf(certProvider)
		t := reflect.Indirect(reflectVal).Type()
		newObj := reflect.New(t)
		handler, ok := newObj.Interface().(GetConfigForClient)
		if ok {
			cpok = true
			tlsconfig.GetConfigForClient = handler.GetConfigForClient
		}
	}
	if !cpok {
		return tlsconfig, errors.New("not found tls cert provider")
	}

	np := false
	for _, n := range tlsconfig.NextProtos {
		if n == ACMETLS1Protocol {
			np = true
			break
		}
	}
	if !np {
		tlsconfig.NextProtos = append(tlsconfig.NextProtos, ACMETLS1Protocol)
	}
	return tlsconfig, nil
}

/*
*  3. new method to tls.Config GetCertificate
 */

// GetCertificte returns a function which generates a self-signed Certificate
// and implements tls.Config.GetCertificate.
//
// It takes a string(hosname) or a Certopts{} whith more spceific options.
//
// It panics if arg is not a string or a Certopts{}.
func GetCertificateV2(arg interface{}) func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var opts Certopts
	var err error
	if host, ok := arg.(string); ok {
		opts = Certopts{
			RsaBits:   2048,
			IsCA:      true,
			Host:      host,
			ValidFrom: time.Now(),
		}
	} else if o, ok := arg.(Certopts); ok {
		opts = o
	} else {
		err = errors.New("Invalid arg type, must be string(hostname) or Certopt{...}")
	}

	cert, err := generate(opts)
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return cert, err
	}
}

// Certopts is a struct to define option to generate the certificate.
type Certopts struct {
	RsaBits   int
	Host      string
	IsCA      bool
	ValidFrom time.Time
	ValidFor  time.Duration
}

// generate a certificte for given options.
func generate(opts Certopts) (*tls.Certificate, error) {

	priv, err := rsa.GenerateKey(rand.Reader, opts.RsaBits)
	if err != nil {
		return nil, errors.New(err.Error() + "failed to generate private key")
	}

	notAfter := opts.ValidFrom.Add(opts.ValidFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.New(err.Error() + "Failed to generate serial number\n")
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: opts.ValidFrom,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(opts.Host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if opts.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, errors.New(err.Error() + "Failed to create certificate")
	}

	return &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}
