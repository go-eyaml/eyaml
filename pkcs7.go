// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-eyaml/eyaml authors

package eyaml

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// rsaEncrypt is a seam over rsa.EncryptPKCS1v15 so its error branch is
// testable. (Since Go 1.26 the standard library ignores the randomness reader
// for this call, so a failing reader cannot exercise the branch.)
var rsaEncrypt = rsa.EncryptPKCS1v15

// Object identifiers used by the CMS EnvelopedData structure (RFC 5652).
var (
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidAES256CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// algorithmIdentifier is the AlgorithmIdentifier SEQUENCE. Parameters is the
// per-algorithm blob: NULL for rsaEncryption, an OCTET STRING IV for
// aes-256-cbc.
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// issuerAndSerial identifies the recipient certificate.
type issuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// recipientInfo is a KeyTransRecipientInfo (issuerAndSerialNumber form).
type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  issuerAndSerial
	KeyEncryptionAlgorithm algorithmIdentifier
	EncryptedKey           []byte
}

// encryptedContentInfo holds the symmetrically-encrypted payload.
type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm algorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

// envelopedData is the EnvelopedData SEQUENCE.
type envelopedData struct {
	Version              int
	RecipientInfos       []recipientInfo `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
}

// contentInfo is the outer ContentInfo wrapper. Content carries the
// [0] EXPLICIT wrapper as a raw context-specific value: this is built and read
// by hand (see sealPKCS7/openPKCS7) because an asn1.RawValue set via FullBytes
// bypasses struct-tag wrapping.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

// sealPKCS7 builds a CMS EnvelopedData token body: a random AES content key
// encrypts plaintext under AES-256-CBC, and the content key is RSA-wrapped for
// cert. rnd supplies all randomness (content key, IV, RSA blinding). keySize is
// the content-key length in bytes (32 for AES-256).
func sealPKCS7(rnd io.Reader, cert *x509.Certificate, keySize int, plaintext []byte) ([]byte, error) {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("eyaml: certificate public key is %T, not RSA", cert.PublicKey)
	}
	key := make([]byte, keySize)
	if _, err := io.ReadFull(rnd, key); err != nil {
		return nil, fmt.Errorf("eyaml: read content key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("eyaml: new content cipher: %w", err)
	}
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rnd, iv); err != nil {
		return nil, fmt.Errorf("eyaml: read iv: %w", err)
	}
	padded := pkcs7Pad(plaintext, block.BlockSize())
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	encKey, err := rsaEncrypt(rnd, pub, key)
	if err != nil {
		return nil, fmt.Errorf("eyaml: wrap content key: %w", err)
	}

	ivParam, _ := asn1.Marshal(iv) // marshalling an []byte OCTET STRING cannot fail
	ed := envelopedData{
		Version: 0,
		RecipientInfos: []recipientInfo{{
			Version: 0,
			IssuerAndSerialNumber: issuerAndSerial{
				Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
				SerialNumber: cert.SerialNumber,
			},
			KeyEncryptionAlgorithm: algorithmIdentifier{
				Algorithm:  oidRSAEncryption,
				Parameters: asn1.NullRawValue,
			},
			EncryptedKey: encKey,
		}},
		EncryptedContentInfo: encryptedContentInfo{
			ContentType: oidData,
			ContentEncryptionAlgorithm: algorithmIdentifier{
				Algorithm:  oidAES256CBC,
				Parameters: asn1.RawValue{FullBytes: ivParam},
			},
			EncryptedContent: ct,
		},
	}
	edDER, _ := asn1.Marshal(ed) // well-formed structs cannot fail to marshal
	ci := contentInfo{
		ContentType: oidEnvelopedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      edDER,
		},
	}
	out, _ := asn1.Marshal(ci)
	return out, nil
}

// openPKCS7 reverses sealPKCS7: it RSA-unwraps the content key with priv and
// AES-CBC-decrypts the payload.
func openPKCS7(der []byte, priv *rsa.PrivateKey) ([]byte, error) {
	var ci contentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		return nil, fmt.Errorf("eyaml: parse ContentInfo: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("eyaml: trailing data after PKCS7 structure")
	}
	if !ci.ContentType.Equal(oidEnvelopedData) {
		return nil, fmt.Errorf("eyaml: content type %v is not envelopedData", ci.ContentType)
	}
	if ci.Content.Class != asn1.ClassContextSpecific || ci.Content.Tag != 0 {
		return nil, errors.New("eyaml: malformed ContentInfo content wrapper")
	}
	var ed envelopedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
		return nil, fmt.Errorf("eyaml: parse EnvelopedData: %w", err)
	}
	if len(ed.RecipientInfos) == 0 {
		return nil, errors.New("eyaml: no recipients in PKCS7 structure")
	}
	ri := ed.RecipientInfos[0]
	if !ri.KeyEncryptionAlgorithm.Algorithm.Equal(oidRSAEncryption) {
		return nil, fmt.Errorf("eyaml: recipient key algorithm %v is not RSA", ri.KeyEncryptionAlgorithm.Algorithm)
	}
	contentKey, err := rsa.DecryptPKCS1v15(nil, priv, ri.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("eyaml: unwrap content key: %w", err)
	}

	eci := ed.EncryptedContentInfo
	if !eci.ContentEncryptionAlgorithm.Algorithm.Equal(oidAES256CBC) {
		return nil, fmt.Errorf("eyaml: content cipher %v is not AES-256-CBC", eci.ContentEncryptionAlgorithm.Algorithm)
	}
	var iv []byte
	if _, err := asn1.Unmarshal(eci.ContentEncryptionAlgorithm.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("eyaml: parse IV: %w", err)
	}
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, fmt.Errorf("eyaml: new content cipher: %w", err)
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("eyaml: IV length %d != block size %d", len(iv), block.BlockSize())
	}
	ct := eci.EncryptedContent
	if len(ct) == 0 || len(ct)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("eyaml: ciphertext length %d is not a positive multiple of block size", len(ct))
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	return pkcs7Unpad(pt, block.BlockSize())
}

// pkcs7Pad appends PKCS#7 padding so the result is a whole number of blocks.
func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// pkcs7Unpad removes and validates PKCS#7 padding. data is assumed non-empty
// and a whole number of blocks (the caller guarantees this).
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize {
		return nil, errors.New("eyaml: invalid PKCS7 padding")
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, errors.New("eyaml: invalid PKCS7 padding")
		}
	}
	return data[:len(data)-pad], nil
}
