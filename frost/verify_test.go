package frost

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyInvalidInputs(t *testing.T) {
	t.Parallel()

	// Wrong-length public key.
	assert.False(t, Verify([]byte{1, 2, 3}, []byte("msg"), &Signature{R: make([]byte, 32), Z: make([]byte, 32)}))

	// Wrong-length R.
	assert.False(t, Verify(make([]byte, 32), []byte("msg"), &Signature{R: make([]byte, 31), Z: make([]byte, 32)}))

	// Wrong-length Z.
	assert.False(t, Verify(make([]byte, 32), []byte("msg"), &Signature{R: make([]byte, 32), Z: make([]byte, 31)}))
}

func TestVerifyBytesCompat(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	msg := []byte("verify bytes test")

	sig := fullSign(t, keyShares, []int{1, 2, 3}, msg)

	// VerifyBytes should work.
	assert.True(t, VerifyBytes(keyShares[1].PublicKey, msg, sig.Bytes()))

	// Wrong length should fail.
	assert.False(t, VerifyBytes(keyShares[1].PublicKey, msg, make([]byte, 63)))
}

func TestVerifyCofactored(t *testing.T) {
	t.Parallel()
	// Generate a standard Ed25519 key and sign.
	pub, priv, _ := ed25519.GenerateKey(nil)
	msg := []byte("standard ed25519 signature")
	stdSig := ed25519.Sign(priv, msg)

	// Our cofactored verifier should also accept standard Ed25519 sigs
	// (well-formed sigs are in the prime-order subgroup, so cofactored
	// verification agrees with standard verification).
	sig := &Signature{R: stdSig[:32], Z: stdSig[32:]}
	assert.True(t, Verify([]byte(pub), msg, sig))
}

func TestVerifyWrongMessage(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	sig := fullSign(t, keyShares, []int{1, 2, 3}, []byte("correct"))
	assert.False(t, Verify(keyShares[1].PublicKey, []byte("wrong"), sig))
}

func TestVerifyWrongPublicKey(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	msg := []byte("test")
	sig := fullSign(t, keyShares, []int{1, 2, 3}, msg)

	// Generate a different key.
	otherShares, err := buildDKG([]int{1, 2, 3}, 3)
	assert.NoError(t, err)
	assert.False(t, Verify(otherShares[1].PublicKey, msg, sig))
}

func TestVerifyCorruptedR(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	msg := []byte("test")
	sig := fullSign(t, keyShares, []int{1, 2, 3}, msg)

	// Flip a bit in R.
	corrupted := &Signature{R: make([]byte, 32), Z: sig.Z}
	copy(corrupted.R, sig.R)
	corrupted.R[0] ^= 0x01
	assert.False(t, Verify(keyShares[1].PublicKey, msg, corrupted))
}

func TestVerifyCorruptedZ(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	msg := []byte("test")
	sig := fullSign(t, keyShares, []int{1, 2, 3}, msg)

	// Flip a bit in Z.
	corrupted := &Signature{R: sig.R, Z: make([]byte, 32)}
	copy(corrupted.Z, sig.Z)
	corrupted.Z[0] ^= 0x01
	assert.False(t, Verify(keyShares[1].PublicKey, msg, corrupted))
}

func TestVerifyNonCanonicalPoint(t *testing.T) {
	t.Parallel()
	// R with all 0xff is not a valid Edwards point.
	badR := make([]byte, 32)
	for i := range badR {
		badR[i] = 0xff
	}
	sig := &Signature{R: badR, Z: make([]byte, 32)}
	assert.False(t, Verify(make([]byte, 32), []byte("msg"), sig))
}

func TestVerifyNonCanonicalScalar(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	msg := []byte("test")
	sig := fullSign(t, keyShares, []int{1, 2, 3}, msg)

	// Z with all 0xff is not a canonical scalar (>= group order).
	badZ := make([]byte, 32)
	for i := range badZ {
		badZ[i] = 0xff
	}
	corrupted := &Signature{R: sig.R, Z: badZ}
	assert.False(t, Verify(keyShares[1].PublicKey, msg, corrupted))
}
