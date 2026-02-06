// SPDX-FileCopyrightText: 2026 Adriano Sela Aviles (@adrianosela)
// SPDX-License-Identifier: MIT

package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"tailscale.com/util/set"
)

// Signer signs certificate requests
type Signer struct {
	caCert *x509.Certificate
	caKey  crypto.PrivateKey
}

// New creates a new certificate signer
func New(caCert *x509.Certificate, caKey crypto.PrivateKey) *Signer {
	return &Signer{
		caCert: caCert,
		caKey:  caKey,
	}
}

// SignCSR signs a certificate signing request and returns a PEM-encoded certificate
func (s *Signer) SignCSR(csrPEM string, allowedNames set.Set[string]) (string, error) {
	// Decode PEM
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode CSR PEM")
	}

	// Parse CSR
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse CSR: %v", err)
	}

	// Verify CSR signature
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("CSR signature verification failed: %v", err)
	}

	// Extract all names from CSR (CN + SANs)
	requestedNames := make([]string, 0)
	if csr.Subject.CommonName != "" {
		requestedNames = append(requestedNames, csr.Subject.CommonName)
	}
	requestedNames = append(requestedNames, csr.DNSNames...)

	// Validate all requested names are in allowlist
	if err := validateNames(requestedNames, allowedNames); err != nil {
		return "", err
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", fmt.Errorf("failed to generate serial number: %v", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: csr.Subject.CommonName,
		},
		DNSNames:              csr.DNSNames,
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour), // 1 year validity
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return string(certPEM), nil
}

// validateNames checks if all requested names are in the allowlist
func validateNames(requested []string, allowed set.Set[string]) error {
	if len(requested) == 0 {
		return fmt.Errorf("no names requested in CSR")
	}

	unauthorized := make([]string, 0)
	for _, name := range requested {
		if _, ok := allowed[name]; !ok {
			unauthorized = append(unauthorized, name)
		}
	}

	if len(unauthorized) > 0 {
		return fmt.Errorf("unauthorized names requested: %v (allowed: %v)", unauthorized, allowed.Slice())
	}

	return nil
}
