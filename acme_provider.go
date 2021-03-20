package acme

import (
	"net/http"
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
func NewProviderServer(iface, port string) Provider {
	return tlsalpn01.NewProviderServer(iface, port)
}
