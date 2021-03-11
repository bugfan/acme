package provider

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/bugfan/acme/certcrypto"
)

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
			return ChallengeCert(info.ServerName, k)
		}
	}
	return nil, nil
}

var idPeAcmeIdentifierV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// ChallengeBlocks returns PEM blocks (certPEMBlock, keyPEMBlock) with the acmeValidation-v1 extension
// and domain name for the `tls-alpn-01` challenge.
func ChallengeBlocks(domain, keyAuth string) ([]byte, []byte, error) {
	// Compute the SHA-256 digest of the key authorization.
	zBytes := sha256.Sum256([]byte(keyAuth))

	value, err := asn1.Marshal(zBytes[:sha256.Size])
	if err != nil {
		return nil, nil, err
	}

	// Add the keyAuth digest as the acmeValidation-v1 extension
	// (marked as critical such that it won't be used by non-ACME software).
	// Reference: https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-07#section-3
	extensions := []pkix.Extension{
		{
			Id:       idPeAcmeIdentifierV1,
			Critical: true,
			Value:    value,
		},
	}

	// Generate a new RSA key for the certificates.
	tempPrivateKey, err := certcrypto.GeneratePrivateKey(certcrypto.RSA2048)
	if err != nil {
		return nil, nil, err
	}

	rsaPrivateKey := tempPrivateKey.(*rsa.PrivateKey)

	// Generate the PEM certificate using the provided private key, domain, and extra extensions.
	tempCertPEM, err := certcrypto.GeneratePemCert(rsaPrivateKey, domain, extensions)
	if err != nil {
		return nil, nil, err
	}

	// Encode the private key into a PEM format. We'll need to use it to generate the x509 keypair.
	rsaPrivatePEM := certcrypto.PEMEncode(rsaPrivateKey)

	return tempCertPEM, rsaPrivatePEM, nil
}

// ChallengeCert returns a certificate with the acmeValidation-v1 extension
// and domain name for the `tls-alpn-01` challenge.
func ChallengeCert(domain, keyAuth string) (*tls.Certificate, error) {
	tempCertPEM, rsaPrivatePEM, err := ChallengeBlocks(domain, keyAuth)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(tempCertPEM, rsaPrivatePEM)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}
