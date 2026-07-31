package engine

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// NewServerTLSConfig builds a TLS 1.3 config for the server side.
// It loads the server certificate and key via autocert or direct file,
// and requires a valid client certificate signed by the provided CA.
func NewServerTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert/key: %w", err)
	}

	caPool, err := loadCertPool(caFile)
	if err != nil {
		return nil, fmt.Errorf("load CA cert: %w", err)
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		// NextProtos advertises the tunnel protocol on ALPN.
		NextProtos: []string{"tunnel-quic"},
	}, nil
}

// NewClientTLSConfig builds a TLS 1.3 config for the client side.
// It loads the device client certificate and key, and verifies the server
// against the provided CA.
func NewClientTLSConfig(certFile, keyFile, caFile, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client cert/key: %w", err)
	}

	caPool, err := loadCertPool(caFile)
	if err != nil {
		return nil, fmt.Errorf("load CA cert: %w", err)
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   serverName,
		// Enable TLS session tickets for fast 0-RTT resumption on reconnects.
		SessionTicketsDisabled: false,
		NextProtos:             []string{"tunnel-quic"},
	}, nil
}

// loadCertPool reads a PEM-encoded CA certificate file and returns a cert pool.
func loadCertPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("failed to parse CA certificate from %s", caFile)
	}
	return pool, nil
}
