// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-eyaml/eyaml authors

// Package eyaml is a pure-Go (no cgo) implementation of the encryption scheme
// used by Puppet's hiera-eyaml: the ENC[PKCS7,<base64>] token format that
// carries an encrypted value inside otherwise-plaintext YAML.
//
// The engine is built exclusively on the Go standard library's crypto packages
// (crypto/rsa, crypto/x509, crypto/aes, crypto/cipher, crypto/rand,
// encoding/pem and encoding/asn1). The PKCS#7 / CMS EnvelopedData structure
// (RFC 5652) is assembled by hand on those primitives so the package needs no
// third-party crypto and no cgo.
//
// # Scheme
//
// The default and only shipped [Encryptor] is [PKCS7], which mirrors
// hiera-eyaml's pkcs7 encryptor:
//
//   - a random 256-bit AES content key encrypts the plaintext with
//     AES-256-CBC (PKCS#7 block padding);
//   - the content key is wrapped for the recipient with RSA (PKCS#1 v1.5)
//     under the recipient's X.509 certificate;
//   - the whole thing is serialised as a CMS EnvelopedData ContentInfo and
//     base64-wrapped into an ENC[PKCS7,...] token.
//
// [CreateKeys] generates the RSA keypair plus self-signed certificate that
// hiera-eyaml's "eyaml createkeys" would produce.
//
// # Extending
//
// [Encryptor] is a pluggable seam: additional schemes (for example the
// hiera-eyaml "gpg" encryptor) can be added by implementing the interface.
// The gpg scheme is intentionally deferred and not implemented here, because it
// would pull in OpenPGP machinery beyond the standard-library crypto surface.
package eyaml
