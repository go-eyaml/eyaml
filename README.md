<!--
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026, the go-eyaml/eyaml authors
-->

# go-eyaml

[![CI](https://github.com/go-eyaml/eyaml/actions/workflows/ci.yml/badge.svg)](https://github.com/go-eyaml/eyaml/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-eyaml/eyaml.svg)](https://pkg.go.dev/github.com/go-eyaml/eyaml)
[![Documentation](https://img.shields.io/badge/docs-mkdocs--material-4F46E5?style=flat-square)](https://go-eyaml.github.io/docs/)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue?style=flat-square)](LICENSE)
![Go 1.26.4+](https://img.shields.io/badge/go-1.26.4%2B-00ADD8?style=flat-square&logo=go&logoColor=white)
![Coverage 100%](https://img.shields.io/badge/coverage-100%25-1a7f37?style=flat-square)

**Pure-Go (`CGO_ENABLED=0`) implementation of hiera-eyaml's encryption
schemes** — the `ENC[PKCS7,<base64>]` and `ENC[GPG,<base64>]` token formats
that carry an encrypted value inside otherwise-plaintext YAML.

- **PKCS7** — built exclusively on the Go standard library's crypto packages
  (`crypto/rsa`, `crypto/x509`, `crypto/aes`, `crypto/cipher`, `crypto/rand`,
  `encoding/pem`, `encoding/asn1`); the PKCS#7 / CMS `EnvelopedData` structure
  (RFC 5652) is hand-assembled on those primitives.
- **GPG** — adds the maintained pure-Go OpenPGP implementation
  [`github.com/ProtonMail/go-crypto`](https://github.com/ProtonMail/go-crypto);
  still `CGO_ENABLED=0` and built from source, so the whole module needs no
  cgo, just one additional (pure-Go) dependency for this scheme.

Both schemes cross-compile to the six 64-bit Go targets (amd64, arm64,
riscv64, loong64, ppc64le, s390x) and to WebAssembly, and hold **100% test
coverage**, including error branches, as a CI gate.

## Install

```sh
go get github.com/go-eyaml/eyaml
```

## Usage

```go
import "github.com/go-eyaml/eyaml"

// PKCS7
kp, _ := eyaml.CreateKeys(nil) // *KeyPair: PrivateKeyPEM, PublicKeyPEM
enc, _ := eyaml.NewPKCS7(kp.PublicKeyPEM, kp.PrivateKeyPEM)
token, _ := eyaml.Encrypt(enc, []byte("s3cret")) // ENC[PKCS7,...]

if eyaml.IsToken(token) {
	plain, _ := eyaml.Decrypt(enc, token) // "s3cret"
	_ = plain
}
```

```go
// GPG — pubKeyRing/privKeyRing accept armored or binary OpenPGP keyrings.
enc, _ := eyaml.NewGPG(pubKeyRing, privKeyRing, passphrase)
token, _ := eyaml.Encrypt(enc, []byte("s3cret")) // ENC[GPG,...]
plain, _ := eyaml.Decrypt(enc, token)
```

See the [API docs](https://go-eyaml.github.io/docs/api/) and
[`go doc github.com/go-eyaml/eyaml`](https://pkg.go.dev/github.com/go-eyaml/eyaml)
for the full surface (`Encryptor`, `KeyOptions`, token helpers `IsToken` /
`ParseToken` / `FormatToken`, `LoadPrivateKey` / `LoadCertificate` /
`LoadGPGKeyRing`).

## Performance

See [BENCHMARKS.md](BENCHMARKS.md) for measured PKCS7/GPG figures against
`openssl cms` and `gpg` on real hardware (IBM z15 / s390x).

## License

BSD-3-Clause. See [LICENSE](LICENSE).
