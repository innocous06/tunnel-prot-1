package engine

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// NewClientTLSConfigFromPEM is like NewClientTLSConfig but accepts PEM bytes directly
// instead of file paths. Used by the Android gomobile bridge where certs are stored
// in app-private storage and passed as byte slices across the JNI boundary.
func NewClientTLSConfigFromPEM(certPEM, keyPEM, caPEM []byte, serverName string) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse client cert/key: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{cert},
		RootCAs:                caPool,
		ServerName:             serverName,
		SessionTicketsDisabled: false,
		NextProtos:             []string{"tunnel-quic"},
	}, nil
}
