// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-eyaml/eyaml authors

package eyaml

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// armorEncoder wraps w in an ASCII-armor public-key encoder.
func armorEncoder(w io.Writer) (io.WriteCloser, error) {
	return armor.Encode(w, openpgp.PublicKeyType, nil)
}

// --- shared GPG test key material (generated once, small key for speed) ---

var (
	gpgOnce   sync.Once
	gpgEntity *openpgp.Entity
)

// fastGPGConfig keeps in-test key generation and encryption cheap.
func fastGPGConfig() *packet.Config { return &packet.Config{RSABits: 1024} }

func testEntity(t *testing.T) *openpgp.Entity {
	t.Helper()
	gpgOnce.Do(func() {
		e, err := openpgp.NewEntity("eyaml test", "gpg", "gpg@example.com", fastGPGConfig())
		if err != nil {
			panic(err)
		}
		gpgEntity = e
	})
	return gpgEntity
}

func testGPG(t *testing.T) *GPG {
	t.Helper()
	e := testEntity(t)
	return &GPG{Recipients: openpgp.EntityList{e}, PrivateKeys: openpgp.EntityList{e}}
}

// armorEntity serialises an entity's private key (armored) so it can be
// reloaded as an independent copy.
func armorPrivate(t *testing.T, e *openpgp.Entity) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := e.SerializePrivate(&buf, nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func armorPublic(t *testing.T, e *openpgp.Entity) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := e.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// failWriteCloser fails on Write when writeErr is set, else on Close.
type failWriteCloser struct{ writeErr bool }

func (f failWriteCloser) Write(p []byte) (int, error) {
	if f.writeErr {
		return 0, errors.New("boom write")
	}
	return len(p), nil
}
func (f failWriteCloser) Close() error { return errors.New("boom close") }

// --- method surface ---

func TestGPGName(t *testing.T) {
	if (&GPG{}).Name() != "GPG" {
		t.Error("name")
	}
}

func TestGPGEncryptRequiresRecipient(t *testing.T) {
	if _, err := (&GPG{}).Encrypt([]byte("x")); err == nil {
		t.Error("want recipient-required error")
	}
}

func TestGPGDecryptRequiresKey(t *testing.T) {
	if _, err := (&GPG{}).Decrypt([]byte("x")); err == nil {
		t.Error("want key-required error")
	}
}

// --- round trip ---

func TestGPGRoundTrip(t *testing.T) {
	g := testGPG(t)
	for _, msg := range []string{"", "short", strings.Repeat("z", 40)} {
		tok, err := Encrypt(g, []byte(msg))
		if err != nil {
			t.Fatalf("encrypt %q: %v", msg, err)
		}
		if !IsToken(tok) || !strings.HasPrefix(tok, "ENC[GPG,") {
			t.Fatalf("bad token %q", tok)
		}
		got, err := Decrypt(g, tok)
		if err != nil {
			t.Fatalf("decrypt %q: %v", msg, err)
		}
		if string(got) != msg {
			t.Fatalf("round trip: got %q want %q", got, msg)
		}
	}
}

func TestGPGCustomRand(t *testing.T) {
	e := testEntity(t)
	g := &GPG{Recipients: openpgp.EntityList{e}, PrivateKeys: openpgp.EntityList{e}, Rand: passReader{}}
	tok, err := Encrypt(g, []byte("via custom rand"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(g, tok)
	if err != nil || string(got) != "via custom rand" {
		t.Fatalf("got %q err %v", got, err)
	}
}

// --- Encrypt error branches (via the openpgpEncrypt seam) ---

func TestGPGEncryptSetupError(t *testing.T) {
	defer func(orig func(io.Writer, []*openpgp.Entity, *openpgp.Entity, *openpgp.FileHints, *packet.Config) (io.WriteCloser, error)) {
		openpgpEncrypt = orig
	}(openpgpEncrypt)
	openpgpEncrypt = func(io.Writer, []*openpgp.Entity, *openpgp.Entity, *openpgp.FileHints, *packet.Config) (io.WriteCloser, error) {
		return nil, errors.New("setup boom")
	}
	if _, err := testGPG(t).Encrypt([]byte("x")); err == nil {
		t.Error("want setup error")
	}
}

func TestGPGEncryptWriteError(t *testing.T) {
	defer func(orig func(io.Writer, []*openpgp.Entity, *openpgp.Entity, *openpgp.FileHints, *packet.Config) (io.WriteCloser, error)) {
		openpgpEncrypt = orig
	}(openpgpEncrypt)
	openpgpEncrypt = func(io.Writer, []*openpgp.Entity, *openpgp.Entity, *openpgp.FileHints, *packet.Config) (io.WriteCloser, error) {
		return failWriteCloser{writeErr: true}, nil
	}
	if _, err := testGPG(t).Encrypt([]byte("x")); err == nil {
		t.Error("want write error")
	}
}

func TestGPGEncryptCloseError(t *testing.T) {
	defer func(orig func(io.Writer, []*openpgp.Entity, *openpgp.Entity, *openpgp.FileHints, *packet.Config) (io.WriteCloser, error)) {
		openpgpEncrypt = orig
	}(openpgpEncrypt)
	openpgpEncrypt = func(io.Writer, []*openpgp.Entity, *openpgp.Entity, *openpgp.FileHints, *packet.Config) (io.WriteCloser, error) {
		return failWriteCloser{}, nil
	}
	if _, err := testGPG(t).Encrypt([]byte("x")); err == nil {
		t.Error("want close error")
	}
}

// --- Decrypt error branches ---

func TestGPGDecryptReadMessageError(t *testing.T) {
	g := testGPG(t)
	// Garbage that is not a parseable OpenPGP message.
	if _, err := g.Decrypt([]byte{0x00, 0x01, 0x02, 0x03}); err == nil {
		t.Error("want read-message error")
	}
}

func TestGPGDecryptBodyError(t *testing.T) {
	g := testGPG(t)
	ct, err := g.Encrypt([]byte("tamper me please, long enough to survive flipping"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte deep in the encrypted body: the integrity check (MDC/AEAD)
	// then fails while the body is read, exercising the ReadAll error branch.
	ct[len(ct)-3] ^= 0xFF
	if _, err := g.Decrypt(ct); err == nil {
		t.Error("want body/integrity error")
	}
}

func TestGPGDecryptNoMatchingRecipient(t *testing.T) {
	sender := testEntity(t)
	// A fresh, unrelated key: it is not a recipient of sender's ciphertext.
	other, err := openpgp.NewEntity("other", "gpg", "other@example.com", fastGPGConfig())
	if err != nil {
		t.Fatal(err)
	}
	enc := &GPG{Recipients: openpgp.EntityList{sender}}
	ct, err := enc.Encrypt([]byte("for sender only"))
	if err != nil {
		t.Fatal(err)
	}
	dec := &GPG{PrivateKeys: openpgp.EntityList{other}}
	if _, err := dec.Decrypt(ct); err == nil {
		t.Error("want no-matching-recipient error")
	}
}

// --- prompt / passphrase branches ---

// passEntity returns a freshly generated entity plus an independent copy of it
// whose private keys are encrypted under passphrase.
func passEntity(t *testing.T, passphrase []byte) (recipient *openpgp.Entity, encrypted openpgp.EntityList) {
	t.Helper()
	e, err := openpgp.NewEntity("pass", "gpg", "pass@example.com", fastGPGConfig())
	if err != nil {
		t.Fatal(err)
	}
	// Reload an independent copy and lock it.
	el, err := LoadGPGKeyRing(armorPrivate(t, e))
	if err != nil {
		t.Fatal(err)
	}
	if err := el[0].EncryptPrivateKeys(passphrase, nil); err != nil {
		t.Fatal(err)
	}
	return e, el
}

func TestGPGPassphraseRoundTrip(t *testing.T) {
	pass := []byte("s3kr1t")
	recip, locked := passEntity(t, pass)
	enc := &GPG{Recipients: openpgp.EntityList{recip}}
	ct, err := enc.Encrypt([]byte("passphrase-protected"))
	if err != nil {
		t.Fatal(err)
	}
	dec := &GPG{PrivateKeys: locked, Passphrase: pass}
	got, err := dec.Decrypt(ct)
	if err != nil || string(got) != "passphrase-protected" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestGPGPassphraseMissing(t *testing.T) {
	pass := []byte("s3kr1t")
	recip, locked := passEntity(t, pass)
	enc := &GPG{Recipients: openpgp.EntityList{recip}}
	ct, err := enc.Encrypt([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	dec := &GPG{PrivateKeys: locked} // Passphrase nil
	if _, err := dec.Decrypt(ct); err == nil {
		t.Error("want missing-passphrase error")
	}
}

func TestGPGPassphraseWrong(t *testing.T) {
	pass := []byte("s3kr1t")
	recip, locked := passEntity(t, pass)
	enc := &GPG{Recipients: openpgp.EntityList{recip}}
	ct, err := enc.Encrypt([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	dec := &GPG{PrivateKeys: locked, Passphrase: []byte("wrong")}
	if _, err := dec.Decrypt(ct); err == nil {
		t.Error("want wrong-passphrase error")
	}
}

// TestGPGPromptContinue exercises prompt's skip branch for a candidate whose
// private key is nil or already unlocked, which ReadMessage never produces but
// the code must still handle.
func TestGPGPromptContinue(t *testing.T) {
	g := &GPG{Passphrase: []byte("p")}
	e := testEntity(t)
	pass, err := g.prompt([]openpgp.Key{
		{PrivateKey: nil},          // nil private key -> continue
		{PrivateKey: e.PrivateKey}, // unlocked -> continue
	}, false)
	if err != nil || string(pass) != "p" {
		t.Fatalf("prompt continue: pass=%q err=%v", pass, err)
	}
}

// --- key loading ---

func TestLoadGPGKeyRingArmored(t *testing.T) {
	e := testEntity(t)
	var buf bytes.Buffer
	w, err := armorEncoder(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Serialize(w); err != nil {
		t.Fatal(err)
	}
	w.Close()
	el, err := LoadGPGKeyRing(buf.Bytes())
	if err != nil || len(el) != 1 {
		t.Fatalf("armored load: %d entities, err %v", len(el), err)
	}
}

func TestLoadGPGKeyRingBinary(t *testing.T) {
	e := testEntity(t)
	el, err := LoadGPGKeyRing(armorPublic(t, e))
	if err != nil || len(el) != 1 {
		t.Fatalf("binary load: %d entities, err %v", len(el), err)
	}
}

func TestLoadGPGKeyRingError(t *testing.T) {
	if _, err := LoadGPGKeyRing([]byte("not a keyring at all")); err == nil {
		t.Error("want parse error")
	}
}

// --- NewGPG ---

func TestNewGPGBoth(t *testing.T) {
	e := testEntity(t)
	pub := armorPublic(t, e)
	priv := armorPrivate(t, e)
	g, err := NewGPG(pub, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := Encrypt(g, []byte("newgpg"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(g, tok)
	if err != nil || string(got) != "newgpg" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestNewGPGPubError(t *testing.T) {
	if _, err := NewGPG([]byte("garbage"), nil, nil); err == nil {
		t.Error("want pub load error")
	}
}

func TestNewGPGPrivError(t *testing.T) {
	e := testEntity(t)
	if _, err := NewGPG(armorPublic(t, e), []byte("garbage"), nil); err == nil {
		t.Error("want priv load error")
	}
}

func TestNewGPGEmpty(t *testing.T) {
	g, err := NewGPG(nil, nil, nil)
	if err != nil || g == nil {
		t.Fatalf("empty NewGPG: %v", err)
	}
}

// --- real-gpg interop regression vector ---

// TestGPGInteropVector decrypts a fixed ENC[GPG,...] token that the real GnuPG
// CLI produced ("gpg --encrypt"), proving the engine reads the exact on-wire
// OpenPGP format hiera-eyaml's GPGME encryptor emits. The armored private key
// beside it is the matching secret key. See testdata/README for provenance.
func TestGPGInteropVector(t *testing.T) {
	priv, err := os.ReadFile("testdata/gpg_priv.asc")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := os.ReadFile("testdata/gpg_token.txt")
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewGPG(nil, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt(g, string(tok))
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "gpg-made-secret" {
		t.Fatalf("interop plaintext = %q", pt)
	}
}

// TestGPGInteropVectorEncryptReadback seals with go-eyaml against the vector's
// public key and reads it back with the vector's private key, the round-trip
// half of the interop guarantee that does not need gpg present in CI.
func TestGPGInteropVectorEncryptReadback(t *testing.T) {
	pub, err := os.ReadFile("testdata/gpg_pub.asc")
	if err != nil {
		t.Fatal(err)
	}
	priv, err := os.ReadFile("testdata/gpg_priv.asc")
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewGPG(pub, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := Encrypt(g, []byte("go-eyaml-made-secret"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(g, tok)
	if err != nil || string(got) != "go-eyaml-made-secret" {
		t.Fatalf("got %q err %v", got, err)
	}
}

// --- benchmarks (dominated by the OpenPGP public-key crypto, as expected) ---

func BenchmarkGPGEncrypt(b *testing.B) {
	e, err := openpgp.NewEntity("bench", "gpg", "bench@example.com", fastGPGConfig())
	if err != nil {
		b.Fatal(err)
	}
	g := &GPG{Recipients: openpgp.EntityList{e}}
	msg := []byte("benchmark secret value")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := g.Encrypt(msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGPGDecrypt(b *testing.B) {
	e, err := openpgp.NewEntity("bench", "gpg", "bench@example.com", fastGPGConfig())
	if err != nil {
		b.Fatal(err)
	}
	g := &GPG{Recipients: openpgp.EntityList{e}, PrivateKeys: openpgp.EntityList{e}}
	ct, err := g.Encrypt([]byte("benchmark secret value"))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := g.Decrypt(ct); err != nil {
			b.Fatal(err)
		}
	}
}
