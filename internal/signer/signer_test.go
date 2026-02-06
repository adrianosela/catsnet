// SPDX-FileCopyrightText: 2026 Adriano Sela Aviles (@adrianosela)
// SPDX-License-Identifier: MIT

package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"tailscale.com/util/set"
)

func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func createTestCSR(cn string, sans []string) (string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
		DNSNames: sans,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	if err != nil {
		return "", err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return string(csrPEM), nil
}

func TestSignCSR_Success(t *testing.T) {
	caCert, caKey, err := generateTestCA(t)
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	signer := New(caCert, caKey)

	cn := "example.com"
	sans := []string{"www.example.com", "api.example.com"}
	csrPEM, err := createTestCSR(cn, sans)
	if err != nil {
		t.Fatalf("failed to create test CSR: %v", err)
	}

	allowedNames := make(set.Set[string])
	allowedNames.AddSlice([]string{"example.com", "www.example.com", "api.example.com"})
	certPEM, err := signer.SignCSR(csrPEM, allowedNames)
	if err != nil {
		t.Fatalf("failed to sign CSR: %v", err)
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	if cert.Subject.CommonName != cn {
		t.Errorf("expected CN=%s, got %s", cn, cert.Subject.CommonName)
	}

	if len(cert.DNSNames) != len(sans) {
		t.Errorf("expected %d SANs, got %d", len(sans), len(cert.DNSNames))
	}

	for i, san := range sans {
		if cert.DNSNames[i] != san {
			t.Errorf("expected SAN[%d]=%s, got %s", i, san, cert.DNSNames[i])
		}
	}

	// Verify certificate is signed by CA
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("certificate signature verification failed: %v", err)
	}

	// Verify it's not a CA
	if cert.IsCA {
		t.Error("certificate should not be a CA")
	}

	// Verify key usage
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("certificate should have digital signature key usage")
	}
}

func TestSignCSR_UnauthorizedName(t *testing.T) {
	caCert, caKey, err := generateTestCA(t)
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	signer := New(caCert, caKey)

	cn := "unauthorized.com"
	csrPEM, err := createTestCSR(cn, nil)
	if err != nil {
		t.Fatalf("failed to create test CSR: %v", err)
	}

	allowedNames := make(set.Set[string])
	allowedNames.AddSlice([]string{"example.com", "www.example.com"})

	_, err = signer.SignCSR(csrPEM, allowedNames)
	if err == nil {
		t.Fatal("expected error for unauthorized name, got nil")
	}

	expectedMsg := "unauthorized names requested"
	if err.Error()[:len(expectedMsg)] != expectedMsg {
		t.Errorf("expected error to start with %q, got %q", expectedMsg, err.Error())
	}
}

func TestSignCSR_PartiallyAuthorized(t *testing.T) {
	caCert, caKey, err := generateTestCA(t)
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	signer := New(caCert, caKey)

	cn := "example.com"
	sans := []string{"www.example.com", "unauthorized.com"}
	csrPEM, err := createTestCSR(cn, sans)
	if err != nil {
		t.Fatalf("failed to create test CSR: %v", err)
	}

	allowedNames := make(set.Set[string])
	allowedNames.AddSlice([]string{"example.com", "www.example.com", "api.example.com"})
	_, err = signer.SignCSR(csrPEM, allowedNames)
	if err == nil {
		t.Fatal("expected error for unauthorized SAN, got nil")
	}
}

func TestSignCSR_InvalidPEM(t *testing.T) {
	caCert, caKey, err := generateTestCA(t)
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	signer := New(caCert, caKey)

	// Invalid PEM
	_, err = signer.SignCSR("not a valid PEM", set.Set[string]{"example.com": {}})
	if err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
}

func TestSignCSR_EmptyAllowlist(t *testing.T) {
	caCert, caKey, err := generateTestCA(t)
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	signer := New(caCert, caKey)

	csrPEM, err := createTestCSR("example.com", nil)
	if err != nil {
		t.Fatalf("failed to create test CSR: %v", err)
	}

	// Empty allowlist
	_, err = signer.SignCSR(csrPEM, set.Set[string]{})
	if err == nil {
		t.Fatal("expected error for empty allowlist, got nil")
	}
}

func TestValidateNames(t *testing.T) {
	tests := []struct {
		name        string
		requested   []string
		allowed     set.Set[string]
		shouldError bool
	}{
		{
			name:      "all authorized",
			requested: []string{"example.com", "www.example.com"},
			allowed: set.Set[string]{
				"example.com":     {},
				"www.example.com": {},
				"api.example.com": {},
			},
			shouldError: false,
		},
		{
			name:      "one unauthorized",
			requested: []string{"example.com", "unauthorized.com"},
			allowed: set.Set[string]{
				"example.com": {},
			},
			shouldError: true,
		},
		{
			name:      "empty requested",
			requested: []string{},
			allowed: set.Set[string]{
				"example.com": {},
			},
			shouldError: true,
		},
		{
			name:      "exact match",
			requested: []string{"example.com"},
			allowed: set.Set[string]{
				"example.com": {},
			},
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNames(tt.requested, tt.allowed)
			if tt.shouldError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}
