package frost

import (
	"filippo.io/edwards25519"
)

// Verify checks a FROST Ed25519 signature against the group public key.
// Uses cofactored verification per RFC 9591 Section 6.5:
//
//	[8][z]B == [8]R + [8][c]PK
//
// where c = H2(R || PK || msg).
//
// The signature is also verifiable by crypto/ed25519.Verify since
// H2 matches the standard Ed25519 challenge hash (no domain prefix).
func Verify(publicKey []byte, message []byte, sig *Signature) bool {
	if len(sig.R) != ElementLen || len(sig.Z) != ScalarLen || len(publicKey) != ElementLen {
		return false
	}

	R, err := edwards25519.NewIdentityPoint().SetBytes(sig.R)
	if err != nil {
		return false
	}
	z, err := edwards25519.NewScalar().SetCanonicalBytes(sig.Z)
	if err != nil {
		return false
	}
	PK, err := edwards25519.NewIdentityPoint().SetBytes(publicKey)
	if err != nil {
		return false
	}

	// c = H2(R || PK || msg) — standard Ed25519 challenge (no domain prefix).
	input := make([]byte, 0, ElementLen+ElementLen+len(message))
	input = append(input, sig.R...)
	input = append(input, publicKey...)
	input = append(input, message...)
	c := H2(input)

	// Cofactored verification: [8]([z]B) == [8](R + [c]PK)
	cofactor := scalarFromUint64(8)

	// LHS = [8][z]B
	zB := edwards25519.NewGeneratorPoint().ScalarBaseMult(z)
	lhs := edwards25519.NewIdentityPoint().ScalarMult(cofactor, zB)

	// RHS = [8](R + [c]PK)
	cPK := edwards25519.NewIdentityPoint().ScalarMult(c, PK)
	rCPK := edwards25519.NewIdentityPoint().Add(R, cPK)
	rhs := edwards25519.NewIdentityPoint().ScalarMult(cofactor, rCPK)

	return lhs.Equal(rhs) == 1
}

// VerifyBytes verifies a 64-byte Ed25519 signature (R || z).
func VerifyBytes(publicKey []byte, message []byte, sigBytes []byte) bool {
	if len(sigBytes) != 64 {
		return false
	}
	sig := &Signature{
		R: sigBytes[:32],
		Z: sigBytes[32:],
	}
	return Verify(publicKey, message, sig)
}
