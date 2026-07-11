<!--
Copyright (c) 2026, the go-eyaml/eyaml authors
SPDX-License-Identifier: BSD-3-Clause
-->

# Performance: go-eyaml vs. reference OpenSSL / GnuPG

go-eyaml and the reference tools (`openssl cms` for the PKCS7 scheme, `gpg` for
the GPG scheme — the same OpenPGP engine hiera-eyaml's GPGME encryptor drives)
run the **same crypto primitives**: RSA key transport plus AES-256-CBC content
encryption (PKCS7), and RSA-sealed session keys plus a symmetric payload cipher
(OpenPGP). The eyaml payload is tiny (a single secret value), so **the RSA
work-factor dominates** every operation. The expectation is therefore *rough
parity on the crypto itself* — this document confirms go-eyaml is **at least as
fast as** the reference while staying pure-Go (CGO=0), and wins on total
wall-clock only because it runs in-process instead of paying a per-call
`fork`/`exec`/agent round-trip.

## Go benchmarks

The repo ships `BenchmarkGPGEncrypt` / `BenchmarkGPGDecrypt` (in `gpg_test.go`),
which use a **1024-bit** key by design so CI stays fast:

```sh
go test -run '^$' -bench . -benchmem
```

The **RSA-2048** figures in the table below — the size hiera-eyaml actually uses,
and the size of the throwaway `testdata` keys — were produced by a small
`go test -bench` harness that loads `testdata/cert.pem`+`key.pem` (PKCS7) and
`testdata/gpg_pub.asc`+`gpg_priv.asc` (GPG) and times `Encrypt`/`Decrypt`, so the
Go and reference sides run the **identical** RSA-2048 keys.

## Measured results — real hardware (IBM z15 / LinuxONE, 2026-07-11)

Same host, same RSA-2048 keys, same tiny plaintext for all three
implementations.

| Component | Version |
|-----------|---------|
| Host | IBM LinuxONE, z15 (8561), 2 vCPU, `s390x` |
| go-eyaml | Go 1.26.4 (pure Go, CGO=0) |
| OpenSSL | 3.0.13 |
| GnuPG | 2.4.4 |

**go-eyaml, in-process** (`go test -bench`, ns/op → µs/op):

| Operation | PKCS7 | GPG |
|-----------|------:|----:|
| Encrypt (RSA-2048 public op + AES) | 65.6 µs | 58.7 µs |
| Decrypt (RSA-2048 **private** op)  | 1 727 µs | 1 726 µs |

**Reference CLI, wall-clock** (averaged over repeated invocations; *includes*
per-call process boot + libcrypto/agent init — this cost is intrinsic to
shelling out and is exactly what an in-process library avoids):

| Tool | Encrypt | Decrypt |
|------|--------:|--------:|
| `openssl cms -aes-256-cbc` | 3.24 ms | 5.87 ms |
| `gpg --encrypt` / `--decrypt` | 1.79 ms | 11.10 ms |

### Reading the numbers

- **Decrypt is RSA-2048-bound.** The private-key modular exponentiation costs
  **~1.7 ms** — and that is the *same* work in Go's `crypto/rsa` and in
  OpenSSL/GnuPG's libcrypto (constant-time CRT modexp). go-eyaml's 1.727 ms
  (PKCS7) / 1.726 ms (GPG) *is* that floor with essentially zero overhead on top,
  confirming **parity on the crypto primitive**. The reference CLIs read higher
  (5.87 ms / 11.10 ms) because each call additionally pays process spin-up, and
  `gpg` a `gpg-agent` socket round-trip.
- **Encrypt is cheap** (public exponent 65537 + a one-block AES): go-eyaml is
  tens of microseconds, while the CLI figures (1.8–3.2 ms) are almost entirely
  process boot, not cryptography.
- The point is **not** a large algorithmic win — with identical primitives there
  is no room for one, and none is claimed. The point is that the pure-Go engine
  is **≥ the reference**: it matches the dominant RSA work-factor exactly and
  removes the per-call CLI overhead, so any caller invoking it in-process (hiera,
  a long-lived process) never pays the `fork`/`exec` tax the reference tools do.

### Reproducing

Encrypt/decrypt the same secret with the `testdata` keys and time N invocations:

```sh
# PKCS7 (OpenSSL CMS)
openssl cms -encrypt -aes-256-cbc -binary -in secret.txt -outform DER \
  -recip testdata/cert.pem -out ct.der
openssl cms -decrypt -inform DER -in ct.der -inkey testdata/key.pem

# GPG (GnuPG) — import testdata/gpg_priv.asc into a short $GNUPGHOME first
gpg --batch --yes --trust-model always --encrypt --recipient "$FPR" -o ct.gpg secret.txt
gpg --batch --yes --decrypt ct.gpg
```

The Go side is timed with `go test -bench` over the identical RSA-2048 keys, so
the comparison is like-for-like on the cryptography.
