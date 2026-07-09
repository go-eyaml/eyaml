// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-eyaml/eyaml authors

package eyaml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"testing"
)

// --- shared test key material (generated once, small key for speed) ---

var (
	kpOnce sync.Once
	kpPair *KeyPair
	kpCert *x509.Certificate
	kpKey  *rsa.PrivateKey
)

func testKeys(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	kpOnce.Do(func() {
		p, err := CreateKeys(&KeyOptions{Bits: 1024})
		if err != nil {
			panic(err)
		}
		kpPair = p
		if kpCert, err = LoadCertificate(p.PublicKeyPEM); err != nil {
			panic(err)
		}
		if kpKey, err = LoadPrivateKey(p.PrivateKeyPEM); err != nil {
			panic(err)
		}
	})
	return kpCert, kpKey
}

func testPKCS7(t *testing.T) *PKCS7 {
	t.Helper()
	c, k := testKeys(t)
	return &PKCS7{Cert: c, Key: k}
}

// nReader yields the bytes it was seeded with, then returns an error once
// exhausted. It makes "fail after N bytes" deterministic for io.ReadFull.
type nReader struct{ data []byte }

func (r *nReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, errors.New("nReader: exhausted")
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// passReader is a non-nil randomness source that simply delegates to
// crypto/rand, used to exercise the PKCS7.Rand != nil branch.
type passReader struct{}

func (passReader) Read(p []byte) (int, error) { return rand.Read(p) }

// --- token helpers ---

func TestIsToken(t *testing.T) {
	if !IsToken("ENC[PKCS7,AAAA]") {
		t.Error("want token")
	}
	if IsToken("plain value") {
		t.Error("plain string is not a token")
	}
}

func TestFormatAndParseToken(t *testing.T) {
	tok := FormatToken("PKCS7", []byte{0xDE, 0xAD, 0xBE, 0xEF})
	if tok != "ENC[PKCS7,3q2+7w==]" {
		t.Fatalf("token = %q", tok)
	}
	scheme, ct, err := ParseToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	if scheme != "PKCS7" || string(ct) != "\xde\xad\xbe\xef" {
		t.Fatalf("scheme=%q ct=%x", scheme, ct)
	}
}

func TestParseTokenWhitespaceWrapped(t *testing.T) {
	// hiera-eyaml wraps long payloads across YAML block-scalar lines.
	wrapped := "ENC[PKCS7,3q2+\n    7w==\t\r\n]"
	scheme, ct, err := ParseToken(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if scheme != "PKCS7" || string(ct) != "\xde\xad\xbe\xef" {
		t.Fatalf("scheme=%q ct=%x", scheme, ct)
	}
}

func TestParseTokenErrors(t *testing.T) {
	if _, _, err := ParseToken("not a token"); err == nil {
		t.Error("want not-a-token error")
	}
	if _, _, err := ParseToken("ENC[PKCS7,@@@notbase64@@@]"); err == nil {
		t.Error("want base64 error")
	}
}

// --- high-level Encrypt / Decrypt ---

func TestHighLevelRoundTrip(t *testing.T) {
	p := testPKCS7(t)
	for _, msg := range []string{"", "short", strings.Repeat("x", 16), strings.Repeat("y", 33)} {
		tok, err := Encrypt(p, []byte(msg))
		if err != nil {
			t.Fatalf("encrypt %q: %v", msg, err)
		}
		if !IsToken(tok) || !strings.HasPrefix(tok, "ENC[PKCS7,") {
			t.Fatalf("bad token %q", tok)
		}
		got, err := Decrypt(p, tok)
		if err != nil {
			t.Fatalf("decrypt %q: %v", msg, err)
		}
		if string(got) != msg {
			t.Fatalf("round trip: got %q want %q", got, msg)
		}
	}
}

func TestHighLevelEncryptError(t *testing.T) {
	// no certificate => underlying Encrypt fails, high-level propagates.
	if _, err := Encrypt(&PKCS7{}, []byte("x")); err == nil {
		t.Error("want encrypt error")
	}
}

func TestHighLevelDecryptErrors(t *testing.T) {
	p := testPKCS7(t)
	// bad token
	if _, err := Decrypt(p, "nope"); err == nil {
		t.Error("want parse error")
	}
	// scheme mismatch
	if _, err := Decrypt(p, "ENC[GPG,AAAA]"); err == nil {
		t.Error("want scheme mismatch error")
	}
	// underlying decrypt error (garbage ciphertext)
	if _, err := Decrypt(p, FormatToken("PKCS7", []byte{0x01, 0x02})); err == nil {
		t.Error("want decrypt error")
	}
}

// --- PKCS7 method surface ---

func TestPKCS7Name(t *testing.T) {
	if (&PKCS7{}).Name() != "PKCS7" {
		t.Error("name")
	}
}

func TestPKCS7EncryptRequiresCert(t *testing.T) {
	if _, err := (&PKCS7{}).Encrypt([]byte("x")); err == nil {
		t.Error("want cert-required error")
	}
}

func TestPKCS7DecryptRequiresKey(t *testing.T) {
	if _, err := (&PKCS7{}).Decrypt([]byte("x")); err == nil {
		t.Error("want key-required error")
	}
}

func TestPKCS7CustomKeySize(t *testing.T) {
	// keySize seam set to a non-default (AES-128) value: exercises ks()'s
	// override branch and confirms the content-key length round-trips.
	c, k := testKeys(t)
	p := &PKCS7{Cert: c, Key: k, keySize: 16}
	tok, err := Encrypt(p, []byte("aes-128 please"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(p, tok)
	if err != nil || string(got) != "aes-128 please" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestPKCS7CustomRand(t *testing.T) {
	c, k := testKeys(t)
	p := &PKCS7{Cert: c, Key: k, Rand: passReader{}}
	tok, err := Encrypt(p, []byte("via custom rand"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(p, tok)
	if err != nil || string(got) != "via custom rand" {
		t.Fatalf("got %q err %v", got, err)
	}
}
