package acme

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
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

const (
	// ACMETLS1Protocol is the ALPN Protocol ID for the ACME-TLS/1 Protocol.
	ACMETLS1Protocol = "acme-tls/1"
	defaultTLSPort   = "443"
)

type ProviderServer struct {
	iface    string
	port     string
	listener net.Listener
}

func NewProviderServer(iface, port string) Provider {
	return &ProviderServer{iface: iface, port: port}
}

// Present generates a certificate with a SHA-256 digest of the keyAuth provided
// as the acmeValidation-v1 extension value to conform to the ACME-TLS-ALPN spec.
func (s *ProviderServer) Present(domain, token, keyAuth string) error {
	if s.port == "" {
		// Fallback to port 443 if the port was not provided.
		s.port = defaultTLSPort
	}

	// Generate the challenge certificate using the provided keyAuth and domain.
	cert, err := tlsalpn01.ChallengeCert(domain, keyAuth)
	if err != nil {
		return err
	}

	// Place the generated certificate with the extension into the TLS config
	// so that it can serve the correct details.
	tlsConf := new(tls.Config)
	tlsConf.Certificates = []tls.Certificate{*cert}

	// We must set that the `acme-tls/1` application level protocol is supported
	// so that the protocol negotiation can succeed. Reference:
	// https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-07#section-6.2
	tlsConf.NextProtos = []string{ACMETLS1Protocol}

	// Create the listener with the created tls.Config.
	s.listener, err = tls.Listen("tcp", net.JoinHostPort(s.iface, s.port), tlsConf)
	if err != nil {
		return fmt.Errorf("could not start HTTPS server for challenge: %w", err)
	}

	// Shut the server down when we're finished.
	go func() {
		err := http.Serve(s.listener, nil)
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Println(err)
		}
	}()

	return nil
}

// CleanUp closes the HTTPS server.
func (s *ProviderServer) CleanUp(domain, token, keyAuth string) error {
	if s.listener == nil {
		return nil
	}
	// Server was created, close it.
	if err := s.listener.Close(); err != nil && errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
