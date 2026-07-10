// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-eyaml/eyaml authors

// Package eyaml is a pure-Go (no cgo) implementation of the encryption schemes
// used by Puppet's hiera-eyaml: the ENC[PKCS7,<base64>] and ENC[GPG,<base64>]
// token formats that carry an encrypted value inside otherwise-plaintext YAML.
//
// The PKCS7 engine is built exclusively on the Go standard library's crypto
// packages (crypto/rsa, crypto/x509, crypto/aes, crypto/cipher, crypto/rand,
// encoding/pem and encoding/asn1). The PKCS#7 / CMS EnvelopedData structure
// (RFC 5652) is assembled by hand on those primitives. The GPG engine adds the
// maintained pure-Go OpenPGP implementation
// github.com/ProtonMail/go-crypto/openpgp; it is CGO-free and built from source,
// so the whole package still needs no cgo.
//
// # Schemes
//
// [PKCS7] mirrors hiera-eyaml's pkcs7 encryptor:
//
//   - a random 256-bit AES content key encrypts the plaintext with
//     AES-256-CBC (PKCS#7 block padding);
//   - the content key is wrapped for the recipient with RSA (PKCS#1 v1.5)
//     under the recipient's X.509 certificate;
//   - the whole thing is serialised as a CMS EnvelopedData ContentInfo and
//     base64-wrapped into an ENC[PKCS7,...] token.
//
// [GPG] mirrors hiera-eyaml's gpg encryptor:
//
//   - a random session key is public-key-encrypted to one or more recipient
//     OpenPGP keys and encrypts the payload, exactly as "gpg --encrypt" does;
//   - the resulting binary (non-armored) OpenPGP message is base64-wrapped into
//     an ENC[GPG,...] token, byte-for-byte the format hiera-eyaml's GPGME
//     encryptor emits. Recipient and secret keyrings are accepted armored or
//     binary; passphrase-protected secret keys are supported.
//
// [CreateKeys] generates the RSA keypair plus self-signed certificate that
// hiera-eyaml's "eyaml createkeys" would produce (PKCS7); GPG keyrings are
// supplied by the caller and loaded with [LoadGPGKeyRing] / [NewGPG].
//
// # Extending
//
// [Encryptor] is a pluggable seam: both [PKCS7] and [GPG] implement it, and
// further schemes can be added the same way.
package eyaml
