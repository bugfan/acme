package acme

import (
	"crypto/tls"
	"errors"
	"net/http"
	"reflect"
	"strings"

	"github.com/bugfan/acme/challenge/tlsalpn01"
)

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
