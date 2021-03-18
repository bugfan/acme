package acme

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/bugfan/acme/challenge/tlsalpn01"
)

const PathPrefix = "/.well-known/acme-challenge"

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
	fmt.Println("http01provider	serverhttp in:", r.URL.String(), s.tokens[r.Host])
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
	return PathPrefix + "/" + token
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
