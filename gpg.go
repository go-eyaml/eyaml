// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-eyaml/eyaml authors

package eyaml

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// openpgpEncrypt is a seam over openpgp.Encrypt so the write/close error
// branches of GPG.Encrypt are testable without a crypto sink that fails at a
// precise byte offset. Production always uses the real implementation.
var openpgpEncrypt = openpgp.Encrypt

// GPG is the hiera-eyaml "gpg" encryptor: it produces and consumes the binary
// OpenPGP message that hiera-eyaml's GPGME-backed encryptor emits, base64-
// wrapped into an ENC[GPG,...] token. Public-key encryption seals a random
// session key to one or more recipients and that session key encrypts the
// payload, exactly as "gpg --encrypt" does.
//
// Recipients (public keys) are required to Encrypt; PrivateKeys are required to
// Decrypt. Passphrase unlocks a passphrase-protected private key and may be nil
// for an unprotected one.
type GPG struct {
	// Recipients are the public keys the payload is encrypted to.
	Recipients openpgp.EntityList
	// PrivateKeys are the secret keys tried when decrypting.
	PrivateKeys openpgp.EntityList
	// Passphrase unlocks passphrase-protected private keys; nil if none.
	Passphrase []byte
	// Rand overrides the randomness source (defaults to crypto/rand.Reader
	// via packet.Config).
	Rand io.Reader
}

// Name reports the scheme label, "GPG".
func (g *GPG) Name() string { return "GPG" }

func (g *GPG) config() *packet.Config {
	return &packet.Config{Rand: g.Rand}
}

// Encrypt seals plaintext to the configured recipient public keys, returning
// the raw (non-armored) OpenPGP message that hiera-eyaml base64-wraps.
func (g *GPG) Encrypt(plaintext []byte) ([]byte, error) {
	if len(g.Recipients) == 0 {
		return nil, errors.New("eyaml: GPG encryption requires at least one recipient public key")
	}
	var buf bytes.Buffer
	w, err := openpgpEncrypt(&buf, g.Recipients, nil, nil, g.config())
	if err != nil {
		return nil, fmt.Errorf("eyaml: GPG encrypt setup: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("eyaml: GPG write plaintext: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("eyaml: GPG finalize: %w", err)
	}
	return buf.Bytes(), nil
}

// Decrypt opens an OpenPGP message with the configured private keys.
func (g *GPG) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(g.PrivateKeys) == 0 {
		return nil, errors.New("eyaml: GPG decryption requires a private key")
	}
	md, err := openpgp.ReadMessage(bytes.NewReader(ciphertext), g.PrivateKeys, g.prompt, g.config())
	if err != nil {
		return nil, fmt.Errorf("eyaml: GPG read message: %w", err)
	}
	pt, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("eyaml: GPG read plaintext: %w", err)
	}
	return pt, nil
}

// prompt is the openpgp.PromptFunction: it is invoked only when a candidate
// private key is passphrase-protected. It unlocks each candidate in place with
// the configured passphrase, failing loudly when none is set or it is wrong.
func (g *GPG) prompt(keys []openpgp.Key, _ bool) ([]byte, error) {
	if g.Passphrase == nil {
		return nil, errors.New("eyaml: GPG private key is passphrase-protected but no passphrase configured")
	}
	for _, k := range keys {
		if k.PrivateKey == nil || !k.PrivateKey.Encrypted {
			continue
		}
		if err := k.PrivateKey.Decrypt(g.Passphrase); err != nil {
			return nil, fmt.Errorf("eyaml: GPG unlock private key: %w", err)
		}
	}
	return g.Passphrase, nil
}

// LoadGPGKeyRing parses an OpenPGP keyring, accepting either ASCII-armored or
// binary form. It is used for both public (recipient) and private keyrings.
func LoadGPGKeyRing(data []byte) (openpgp.EntityList, error) {
	if el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data)); err == nil {
		return el, nil
	}
	el, err := openpgp.ReadKeyRing(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("eyaml: parse GPG keyring: %w", err)
	}
	return el, nil
}

// NewGPG builds a [GPG] encryptor from keyring material. Either keyring may be
// empty: pass only pubKeyRing for an encrypt-only value, only privKeyRing for a
// decrypt-only value, or both for round trips. passphrase may be nil when the
// private key is unprotected.
func NewGPG(pubKeyRing, privKeyRing, passphrase []byte) (*GPG, error) {
	g := &GPG{Passphrase: passphrase}
	if len(pubKeyRing) > 0 {
		el, err := LoadGPGKeyRing(pubKeyRing)
		if err != nil {
			return nil, err
		}
		g.Recipients = el
	}
	if len(privKeyRing) > 0 {
		el, err := LoadGPGKeyRing(privKeyRing)
		if err != nil {
			return nil, err
		}
		g.PrivateKeys = el
	}
	return g, nil
}
