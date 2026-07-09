// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-eyaml/eyaml authors

package eyaml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Encryptor is a pluggable eyaml cipher scheme. The default implementation is
// [PKCS7]; other hiera-eyaml schemes (for example gpg) can be added by
// implementing this interface.
type Encryptor interface {
	// Name is the scheme label that appears inside the token, e.g. "PKCS7".
	Name() string
	// Encrypt turns plaintext into raw scheme ciphertext (before base64).
	Encrypt(plaintext []byte) ([]byte, error)
	// Decrypt reverses Encrypt on raw scheme ciphertext.
	Decrypt(ciphertext []byte) ([]byte, error)
}

// PKCS7 is the hiera-eyaml "pkcs7" encryptor: AES-256-CBC content encryption
// with an RSA-wrapped content key, serialised as CMS EnvelopedData. Cert is
// required to Encrypt; Key is required to Decrypt.
type PKCS7 struct {
	// Cert is the recipient certificate used when encrypting.
	Cert *x509.Certificate
	// Key is the RSA private key used when decrypting.
	Key *rsa.PrivateKey
	// Rand overrides the randomness source (defaults to crypto/rand.Reader).
	Rand io.Reader

	// keySize is the AES content-key length in bytes. Zero means 32
	// (AES-256). It exists as a test seam and is not part of the public API.
	keySize int
}

// Name reports the scheme label, "PKCS7".
func (p *PKCS7) Name() string { return "PKCS7" }

func (p *PKCS7) rnd() io.Reader {
	if p.Rand != nil {
		return p.Rand
	}
	return rand.Reader
}

func (p *PKCS7) ks() int {
	if p.keySize != 0 {
		return p.keySize
	}
	return 32
}

// Encrypt seals plaintext for the configured certificate.
func (p *PKCS7) Encrypt(plaintext []byte) ([]byte, error) {
	if p.Cert == nil {
		return nil, errors.New("eyaml: PKCS7 encryption requires a certificate")
	}
	return sealPKCS7(p.rnd(), p.Cert, p.ks(), plaintext)
}

// Decrypt opens ciphertext with the configured private key.
func (p *PKCS7) Decrypt(ciphertext []byte) ([]byte, error) {
	if p.Key == nil {
		return nil, errors.New("eyaml: PKCS7 decryption requires a private key")
	}
	return openPKCS7(ciphertext, p.Key)
}

// tokenRE matches an ENC[SCHEME,payload] token. The payload alphabet is kept
// permissive (base64 plus any whitespace hiera-eyaml inserts when wrapping a
// long value across YAML block-scalar lines); the whitespace is stripped before
// decoding.
var tokenRE = regexp.MustCompile(`ENC\[([A-Za-z0-9]+),([^\]]*)\]`)

// IsToken reports whether s contains an ENC[...] token.
func IsToken(s string) bool { return tokenRE.MatchString(s) }

// ParseToken extracts the scheme name and decoded (base64-removed) ciphertext
// from the first ENC[...] token in s. Whitespace inside the payload, such as the
// line wrapping hiera-eyaml emits, is ignored.
func ParseToken(s string) (scheme string, ciphertext []byte, err error) {
	m := tokenRE.FindStringSubmatch(s)
	if m == nil {
		return "", nil, fmt.Errorf("eyaml: %q is not an ENC[...] token", s)
	}
	payload := stripWhitespace(m[2])
	ct, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", nil, fmt.Errorf("eyaml: decode base64 payload: %w", err)
	}
	return m[1], ct, nil
}

// FormatToken renders scheme and raw ciphertext as an ENC[...] token.
func FormatToken(scheme string, ciphertext []byte) string {
	return "ENC[" + scheme + "," + base64.StdEncoding.EncodeToString(ciphertext) + "]"
}

// Encrypt is the high-level helper: it seals plaintext with enc and returns a
// ready-to-store ENC[...] token.
func Encrypt(enc Encryptor, plaintext []byte) (string, error) {
	ct, err := enc.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	return FormatToken(enc.Name(), ct), nil
}

// Decrypt is the high-level helper: it parses an ENC[...] token, checks the
// scheme matches enc, and returns the recovered plaintext.
func Decrypt(enc Encryptor, token string) ([]byte, error) {
	scheme, ct, err := ParseToken(token)
	if err != nil {
		return nil, err
	}
	if scheme != enc.Name() {
		return nil, fmt.Errorf("eyaml: token scheme %q does not match encryptor %q", scheme, enc.Name())
	}
	return enc.Decrypt(ct)
}

// stripWhitespace removes all ASCII whitespace from s.
func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r', '\v', '\f':
			return -1
		default:
			return r
		}
	}, s)
}
