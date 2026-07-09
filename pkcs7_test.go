// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-eyaml/eyaml authors

package eyaml

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"os"
	"testing"
)

// wrapCI serialises ed into a ContentInfo. When context is true the content is
// wrapped in the correct [0] EXPLICIT tag; when false it is left as a bare
// universal value (to exercise the malformed-wrapper branch).
func wrapCI(t *testing.T, contentType asn1.ObjectIdentifier, ed envelopedData, context bool) []byte {
	t.Helper()
	edDER, err := asn1.Marshal(ed)
	if err != nil {
		t.Fatal(err)
	}
	var content asn1.RawValue
	if context {
		content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: edDER}
	} else {
		content = asn1.RawValue{FullBytes: edDER}
	}
	der, err := asn1.Marshal(contentInfo{ContentType: contentType, Content: content})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// baseED returns a valid EnvelopedData built with the shared test keypair.
func baseED(t *testing.T) envelopedData {
	t.Helper()
	cert, _ := testKeys(t)
	der, err := sealPKCS7(rand.Reader, cert, 32, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		t.Fatal(err)
	}
	var ed envelopedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
		t.Fatal(err)
	}
	return ed
}

// octetString DER-encodes b as an OCTET STRING.
func octetString(t *testing.T, b []byte) asn1.RawValue {
	t.Helper()
	raw, err := asn1.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return asn1.RawValue{FullBytes: raw}
}

func TestSealPKCS7NonRSACert(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	cert := &x509.Certificate{PublicKey: pub}
	if _, err := sealPKCS7(rand.Reader, cert, 32, []byte("x")); err == nil {
		t.Error("want non-RSA error")
	}
}

func TestSealPKCS7RandErrors(t *testing.T) {
	cert, _ := testKeys(t)
	// content-key read fails immediately
	if _, err := sealPKCS7(&nReader{}, cert, 32, []byte("x")); err == nil {
		t.Error("want content-key read error")
	}
	// key ok (32), IV read fails
	if _, err := sealPKCS7(&nReader{data: make([]byte, 32)}, cert, 32, []byte("x")); err == nil {
		t.Error("want iv read error")
	}
}

func TestSealPKCS7WrapError(t *testing.T) {
	cert, _ := testKeys(t)
	orig := rsaEncrypt
	defer func() { rsaEncrypt = orig }()
	sentinel := errors.New("boom-wrap")
	rsaEncrypt = func(io.Reader, *rsa.PublicKey, []byte) ([]byte, error) { return nil, sentinel }
	if _, err := sealPKCS7(rand.Reader, cert, 32, []byte("x")); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v", err)
	}
}

func TestSealPKCS7BadKeySize(t *testing.T) {
	cert, _ := testKeys(t)
	// 10-byte content key: enough randomness read, but aes.NewCipher rejects it.
	if _, err := sealPKCS7(&nReader{data: make([]byte, 10)}, cert, 10, []byte("x")); err == nil {
		t.Error("want aes.NewCipher error")
	}
}

func TestOpenPKCS7ParseErrors(t *testing.T) {
	_, key := testKeys(t)

	// 1. not DER at all
	if _, err := openPKCS7([]byte{0xFF, 0xFF}, key); err == nil {
		t.Error("want ContentInfo parse error")
	}

	// 2. trailing data after a valid structure
	good := wrapCI(t, oidEnvelopedData, baseED(t), true)
	if _, err := openPKCS7(append(append([]byte{}, good...), 0x00), key); err == nil {
		t.Error("want trailing-data error")
	}

	// 3. wrong outer content type
	if _, err := openPKCS7(wrapCI(t, oidData, baseED(t), true), key); err == nil {
		t.Error("want content-type error")
	}

	// 4. content not wrapped in [0] context tag
	if _, err := openPKCS7(wrapCI(t, oidEnvelopedData, baseED(t), false), key); err == nil {
		t.Error("want malformed-wrapper error")
	}

	// 5. [0] wrapper containing non-SEQUENCE garbage
	badInner, err := asn1.Marshal(contentInfo{
		ContentType: oidEnvelopedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: []byte{0xFF, 0xFF}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openPKCS7(badInner, key); err == nil {
		t.Error("want EnvelopedData parse error")
	}
}

func TestOpenPKCS7NoRecipients(t *testing.T) {
	_, key := testKeys(t)
	ed := baseED(t)
	ed.RecipientInfos = nil
	if _, err := openPKCS7(wrapCI(t, oidEnvelopedData, ed, true), key); err == nil {
		t.Error("want no-recipients error")
	}
}

func TestOpenPKCS7KeyAlgNotRSA(t *testing.T) {
	_, key := testKeys(t)
	ed := baseED(t)
	ed.RecipientInfos[0].KeyEncryptionAlgorithm.Algorithm = oidAES256CBC
	if _, err := openPKCS7(wrapCI(t, oidEnvelopedData, ed, true), key); err == nil {
		t.Error("want key-alg error")
	}
}

func TestOpenPKCS7UnwrapError(t *testing.T) {
	_, key := testKeys(t)
	ed := baseED(t)
	// Wrong-length encrypted key => rsa.DecryptPKCS1v15 rejects deterministically.
	ed.RecipientInfos[0].EncryptedKey = []byte{0x01, 0x02, 0x03}
	if _, err := openPKCS7(wrapCI(t, oidEnvelopedData, ed, true), key); err == nil {
		t.Error("want unwrap error")
	}
}

func TestOpenPKCS7ContentCipherNotAES(t *testing.T) {
	_, key := testKeys(t)
	ed := baseED(t)
	ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm = oidData
	if _, err := openPKCS7(wrapCI(t, oidEnvelopedData, ed, true), key); err == nil {
		t.Error("want content-cipher error")
	}
}

func TestOpenPKCS7IVParseError(t *testing.T) {
	_, key := testKeys(t)
	ed := baseED(t)
	// Replace IV params with NULL, which does not decode into an OCTET STRING.
	ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters = asn1.NullRawValue
	if _, err := openPKCS7(wrapCI(t, oidEnvelopedData, ed, true), key); err == nil {
		t.Error("want IV parse error")
	}
}

func TestOpenPKCS7BadContentKeyLength(t *testing.T) {
	cert, key := testKeys(t)
	ed := baseED(t)
	// RSA-encrypt a 10-byte "content key": IV parses, then aes.NewCipher fails.
	pub := cert.PublicKey.(*rsa.PublicKey)
	enc, err := rsa.EncryptPKCS1v15(rand.Reader, pub, make([]byte, 10))
	if err != nil {
		t.Fatal(err)
	}
	ed.RecipientInfos[0].EncryptedKey = enc
	ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters = octetString(t, make([]byte, 16))
	if _, err := openPKCS7(wrapCI(t, oidEnvelopedData, ed, true), key); err == nil {
		t.Error("want aes.NewCipher error")
	}
}

func TestOpenPKCS7IVLengthMismatch(t *testing.T) {
	_, key := testKeys(t)
	ed := baseED(t)
	ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters = octetString(t, make([]byte, 8))
	if _, err := openPKCS7(wrapCI(t, oidEnvelopedData, ed, true), key); err == nil {
		t.Error("want IV length error")
	}
}

func TestOpenPKCS7BadCiphertextLength(t *testing.T) {
	_, key := testKeys(t)
	ed := baseED(t)
	ed.EncryptedContentInfo.EncryptedContent = []byte{0x01, 0x02, 0x03}
	if _, err := openPKCS7(wrapCI(t, oidEnvelopedData, ed, true), key); err == nil {
		t.Error("want ciphertext-length error")
	}
	ed2 := baseED(t)
	ed2.EncryptedContentInfo.EncryptedContent = nil
	if _, err := openPKCS7(wrapCI(t, oidEnvelopedData, ed2, true), key); err == nil {
		t.Error("want empty-ciphertext error")
	}
}

func TestPKCS7PadUnpad(t *testing.T) {
	// pad to a partial block and to a full extra block
	if got := pkcs7Pad([]byte{1, 2, 3}, 8); len(got) != 8 || got[7] != 5 {
		t.Fatalf("partial pad = %x", got)
	}
	full := pkcs7Pad(make([]byte, 8), 8)
	if len(full) != 16 || full[15] != 8 {
		t.Fatalf("full pad = %x", full)
	}
	// unpad round trip
	out, err := pkcs7Unpad(full, 8)
	if err != nil || len(out) != 8 {
		t.Fatalf("unpad full: %v %x", err, out)
	}
	// pad byte 0 is invalid
	if _, err := pkcs7Unpad([]byte{1, 2, 3, 0}, 8); err == nil {
		t.Error("want zero-pad error")
	}
	// pad byte > block size is invalid
	if _, err := pkcs7Unpad([]byte{1, 2, 3, 99}, 8); err == nil {
		t.Error("want oversized-pad error")
	}
	// inconsistent padding bytes
	if _, err := pkcs7Unpad([]byte{1, 2, 5, 3}, 8); err == nil {
		t.Error("want inconsistent-pad error")
	}
}

// TestOpenSSLInteropVector decrypts a fixed CMS EnvelopedData token produced by
// the OpenSSL CLI ("openssl cms -encrypt -aes-256-cbc"), proving the engine
// reads the exact on-wire format hiera-eyaml emits.
func TestOpenSSLInteropVector(t *testing.T) {
	certPEM, err := os.ReadFile("testdata/cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile("testdata/key.pem")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := os.ReadFile("testdata/openssl_token.txt")
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPKCS7(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(p, string(tok))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "openssl-made-secret" {
		t.Fatalf("interop plaintext = %q", pt)
	}
}
