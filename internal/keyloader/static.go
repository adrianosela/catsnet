// SPDX-FileCopyrightText: 2026 Adriano Sela Aviles (@adrianosela)
// SPDX-License-Identifier: MIT

package keyloader

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type static struct {
	cert *x509.Certificate
	key  crypto.PrivateKey
}

func NewStaticLoader(certPath string, keyPath string) (KeyLoader, error) {
	certRaw, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve cert from %s", certPath)
	}
	certPEM, _ := pem.Decode(certRaw)
	if certPEM == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM data: %v", err)
	}
	cert, err := x509.ParseCertificate(certPEM.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate DER data as x509 certificate: %v", err)
	}

	keyRaw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve key from %s", keyPath)
	}
	keyPEM, _ := pem.Decode(keyRaw)
	if keyPEM == nil {
		return nil, fmt.Errorf("failed to decode private key PEM data: %v", err)
	}
	key, err := x509.ParseECPrivateKey(keyPEM.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key DER data as ECDSA private key: %v", err)
	}

	return &static{
		cert: cert,
		key:  key,
	}, nil
}

func (s *static) Load() (*x509.Certificate, crypto.PrivateKey, error) {
	return s.cert, s.key, nil
}
