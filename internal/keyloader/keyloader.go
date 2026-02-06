// SPDX-FileCopyrightText: 2026 Adriano Sela Aviles (@adrianosela)
// SPDX-License-Identifier: MIT

package keyloader

import (
	"crypto"
	"crypto/x509"
)

type KeyLoader interface {
	Load() (*x509.Certificate, crypto.PrivateKey, error)
}
