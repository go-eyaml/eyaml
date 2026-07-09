// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-eyaml/eyaml authors

package eyaml

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"
)

func TestCreateKeysDefaults(t *testing.T) {
	// nil opts exercises every default (2048 bits, crypto/rand, now/+100y,
	// random serial). Round-trip through the loaders to confirm usability.
	kp, err := CreateKeys(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCertificate(kp.PublicKeyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(kp.PrivateKeyPEM); err != nil {
		t.Fatal(err)
	}
}

func TestCreateKeysExplicitOptions(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	kp, err := CreateKeys(&KeyOptions{
		Bits:      1024,
		Rand:      rand.Reader,
		NotBefore: nb,
		NotAfter:  nb.AddDate(1, 0, 0),
		Serial:    big.NewInt(42),
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := LoadCertificate(kp.PublicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if cert.SerialNumber.Int64() != 42 {
		t.Fatalf("serial = %v", cert.SerialNumber)
	}
	if !cert.NotBefore.Equal(nb) {
		t.Fatalf("notBefore = %v", cert.NotBefore)
	}
}

func TestCreateKeysGenerateError(t *testing.T) {
	orig := rsaGenerateKey
	defer func() { rsaGenerateKey = orig }()
	sentinel := errors.New("boom-gen")
	rsaGenerateKey = func(io.Reader, int) (*rsa.PrivateKey, error) { return nil, sentinel }
	if _, err := CreateKeys(&KeyOptions{Bits: 1024}); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateKeysSerialError(t *testing.T) {
	orig := randInt
	defer func() { randInt = orig }()
	sentinel := errors.New("boom-serial")
	randInt = func(io.Reader, *big.Int) (*big.Int, error) { return nil, sentinel }
	if _, err := CreateKeys(&KeyOptions{Bits: 1024}); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateKeysCertError(t *testing.T) {
	orig := createCertificate
	defer func() { createCertificate = orig }()
	sentinel := errors.New("boom-cert")
	createCertificate = func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error) {
		return nil, sentinel
	}
	if _, err := CreateKeys(&KeyOptions{Bits: 1024, Serial: big.NewInt(1)}); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadPrivateKeyPKCS8(t *testing.T) {
	kp, err := CreateKeys(&KeyOptions{Bits: 1024})
	if err != nil {
		t.Fatal(err)
	}
	rk, err := LoadPrivateKey(kp.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	// Re-encode as PKCS#8 to exercise the fallback branch.
	der, err := x509.MarshalPKCS8PrivateKey(rk)
	if err != nil {
		t.Fatal(err)
	}
	p8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := LoadPrivateKey(p8); err != nil {
		t.Fatalf("pkcs8 load: %v", err)
	}
}

func TestLoadPrivateKeyErrors(t *testing.T) {
	if _, err := LoadPrivateKey([]byte("not pem")); err == nil {
		t.Error("want no-PEM error")
	}
	// A PEM block that is neither valid PKCS#1 nor PKCS#8.
	junk := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x01, 0x02}})
	if _, err := LoadPrivateKey(junk); err == nil {
		t.Error("want parse error")
	}
	// Valid PKCS#8 but not RSA (ed25519).
	_, ek, _ := ed25519.GenerateKey(rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(ek)
	if err != nil {
		t.Fatal(err)
	}
	nonRSA := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := LoadPrivateKey(nonRSA); err == nil {
		t.Error("want non-RSA error")
	}
}

func TestLoadCertificateErrors(t *testing.T) {
	if _, err := LoadCertificate([]byte("not pem")); err == nil {
		t.Error("want no-PEM error")
	}
	junk := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x01, 0x02}})
	if _, err := LoadCertificate(junk); err == nil {
		t.Error("want parse error")
	}
}

func TestNewPKCS7Variants(t *testing.T) {
	kp, err := CreateKeys(&KeyOptions{Bits: 1024})
	if err != nil {
		t.Fatal(err)
	}
	// both
	if p, err := NewPKCS7(kp.PublicKeyPEM, kp.PrivateKeyPEM); err != nil || p.Cert == nil || p.Key == nil {
		t.Fatalf("both: %v", err)
	}
	// cert only
	if p, err := NewPKCS7(kp.PublicKeyPEM, nil); err != nil || p.Cert == nil || p.Key != nil {
		t.Fatalf("cert only: %v", err)
	}
	// key only
	if p, err := NewPKCS7(nil, kp.PrivateKeyPEM); err != nil || p.Cert != nil || p.Key == nil {
		t.Fatalf("key only: %v", err)
	}
	// neither
	if p, err := NewPKCS7(nil, nil); err != nil || p.Cert != nil || p.Key != nil {
		t.Fatalf("neither: %v", err)
	}
	// bad cert
	if _, err := NewPKCS7([]byte("bad"), nil); err == nil {
		t.Error("want bad-cert error")
	}
	// bad key
	if _, err := NewPKCS7(nil, []byte("bad")); err == nil {
		t.Error("want bad-key error")
	}
}
