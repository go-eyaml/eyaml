// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-eyaml/eyaml authors

package eyaml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"
)

// Fault-injection seams: package-level indirections over the fallible standard
// library calls used by CreateKeys, so their error branches are testable
// without contriving a randomness source that fails at a precise offset.
var (
	rsaGenerateKey    = rsa.GenerateKey
	randInt           = rand.Int
	createCertificate = x509.CreateCertificate
)

// KeyPair holds the PEM-encoded material produced by [CreateKeys]: an RSA
// private key and the matching self-signed X.509 certificate that hiera-eyaml
// calls the "public key".
type KeyPair struct {
	PrivateKeyPEM []byte
	PublicKeyPEM  []byte
}

// KeyOptions tunes [CreateKeys]. The zero value yields hiera-eyaml's defaults:
// a 2048-bit key, a 100-year validity window starting now, and a random
// 128-bit serial, drawn from crypto/rand.
type KeyOptions struct {
	// Bits is the RSA modulus size; zero means 2048.
	Bits int
	// Rand overrides the randomness source (defaults to crypto/rand.Reader).
	Rand io.Reader
	// NotBefore/NotAfter bound certificate validity; zero values default to
	// now and now+100 years.
	NotBefore time.Time
	NotAfter  time.Time
	// Serial sets the certificate serial number; nil means a random 128-bit
	// value.
	Serial *big.Int
}

// CreateKeys generates an RSA keypair and a self-signed certificate, mirroring
// hiera-eyaml's "eyaml createkeys". opts may be nil to accept all defaults.
func CreateKeys(opts *KeyOptions) (*KeyPair, error) {
	if opts == nil {
		opts = &KeyOptions{}
	}
	bits := opts.Bits
	if bits == 0 {
		bits = 2048
	}
	rnd := opts.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	key, err := rsaGenerateKey(rnd, bits)
	if err != nil {
		return nil, fmt.Errorf("eyaml: generate RSA key: %w", err)
	}
	serial := opts.Serial
	if serial == nil {
		serial, err = randInt(rnd, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, fmt.Errorf("eyaml: generate serial: %w", err)
		}
	}
	notBefore := opts.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now()
	}
	notAfter := opts.NotAfter
	if notAfter.IsZero() {
		notAfter = notBefore.AddDate(100, 0, 0)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := createCertificate(rnd, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("eyaml: create certificate: %w", err)
	}
	return &KeyPair{
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}),
		PublicKeyPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		}),
	}, nil
}

// LoadPrivateKey parses a PEM-encoded RSA private key (PKCS#1 or PKCS#8).
func LoadPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, errors.New("eyaml: no PEM block found in private key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return key, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("eyaml: parse private key: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("eyaml: private key is %T, not RSA", k)
	}
	return rk, nil
}

// LoadCertificate parses a PEM-encoded X.509 certificate.
func LoadCertificate(pemBytes []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, errors.New("eyaml: no PEM block found in certificate")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("eyaml: parse certificate: %w", err)
	}
	return cert, nil
}

// NewPKCS7 builds a [PKCS7] encryptor from PEM material. Either argument may be
// empty: pass only certPEM for an encrypt-only value, only keyPEM for a
// decrypt-only value, or both for round trips.
func NewPKCS7(certPEM, keyPEM []byte) (*PKCS7, error) {
	p := &PKCS7{}
	if len(certPEM) > 0 {
		c, err := LoadCertificate(certPEM)
		if err != nil {
			return nil, err
		}
		p.Cert = c
	}
	if len(keyPEM) > 0 {
		k, err := LoadPrivateKey(keyPEM)
		if err != nil {
			return nil, err
		}
		p.Key = k
	}
	return p, nil
}
