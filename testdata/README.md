<!--
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2026, the go-eyaml/eyaml authors
-->

# Interop test vectors

These fixtures are permanent regression vectors: they pin the exact on-wire
formats that the reference tools (OpenSSL, GnuPG — the same OpenPGP engine
hiera-eyaml's GPGME encryptor drives) produce, so a future refactor cannot
silently diverge from them. All keys here are throwaway, generated only for
these tests.

## PKCS7 (`ENC[PKCS7,...]`)

- `cert.pem`, `key.pem` — a throwaway RSA keypair / self-signed cert.
- `openssl_token.txt` — a CMS EnvelopedData token produced by the OpenSSL CLI
  (`openssl cms -encrypt -aes-256-cbc`) of the plaintext `openssl-made-secret`.
  Decrypted by `TestOpenSSLInteropVector`.

## GPG (`ENC[GPG,...]`)

- `gpg_pub.asc`, `gpg_priv.asc` — a throwaway 2048-bit RSA OpenPGP keypair
  (armored), fingerprint `4BB5B3E34ECF4BEE72E5BF830DC7BF6D0FD3E685`,
  no passphrase.
- `gpg_token.txt` — `ENC[GPG,<base64>]` where the base64 payload is the raw
  binary OpenPGP message produced by the **real GnuPG CLI** encrypting the
  plaintext `gpg-made-secret` to the key above. Decrypted by
  `TestGPGInteropVector`, proving go-eyaml reads exactly what `gpg --encrypt`
  (and therefore hiera-eyaml's GPGME encryptor) emits.

Reproduction of the GPG vector (short `GNUPGHOME` avoids the agent-socket
path-length limit):

```sh
export GNUPGHOME=/tmp/egh; mkdir -p $GNUPGHOME; chmod 700 $GNUPGHOME
cat > $GNUPGHOME/kp <<'EOF'
%no-protection
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: eyaml interop
Name-Email: interop@go-eyaml.test
Expire-Date: 0
%commit
EOF
gpg --batch --gen-key $GNUPGHOME/kp
FPR=$(gpg --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')
gpg --armor --export "$FPR"             > gpg_pub.asc
gpg --armor --export-secret-keys "$FPR" > gpg_priv.asc
printf 'gpg-made-secret' \
  | gpg --encrypt --recipient "$FPR" --trust-model always \
  | base64 | tr -d '\n' | sed 's/.*/ENC[GPG,&]/' > gpg_token.txt
```

The reverse direction (real `gpg` decrypting a go-eyaml-produced token) was also
verified during development; `TestGPGInteropVectorEncryptReadback` keeps a
gpg-free half of that guarantee green in CI.
