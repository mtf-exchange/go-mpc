// Package frost implements the FROST threshold Schnorr signature protocol
// for Ed25519 as specified in RFC 9591 (FROST(Ed25519, SHA-512)).
//
// # Protocol components
//
//   - 2-round distributed Feldman VSS DKG
//   - 2-round threshold signing (RFC 9591 Section 5.2)
//   - Signature aggregation and verification (RFC 9591 Section 5.3)
//   - Proactive key share refresh (zero-constant polynomial Feldman VSS)
//
// # Ciphersuite
//
// FROST-ED25519-SHA512-v1 with cofactored verification per RFC 9591 Section 6.5.
// Signatures are compatible with standard Ed25519 verification (RFC 8032).
//
// # Security model
//
// The protocol operates in a t-of-n threshold setting over the Ed25519
// curve (edwards25519). All secret scalar arithmetic uses constant-time
// operations via filippo.io/edwards25519. Cheating parties are detected
// during share verification and signature share verification; detected
// parties are blacklisted and excluded from future sessions.
//
// # Concurrency
//
// [SignerState] is safe for concurrent reads (parallel signing sessions).
// Mutating operations acquire a write lock internally.
//
// # Usage flow
//
// DKG (2 rounds + finalize) -> signing (2 rounds + aggregate) -> verify -> optional refresh.
package frost

import (
	"filippo.io/edwards25519"
)

// Ciphersuite constants per RFC 9591 Section 6.5.
const (
	// ContextString is the FROST ciphersuite identifier (RFC 9591 Section 6.5).
	ContextString = "FROST-ED25519-SHA512-v1"

	// ScalarLen is the byte length of an Ed25519 scalar (little-endian).
	ScalarLen = 32

	// ElementLen is the byte length of a compressed Edwards25519 point.
	ElementLen = 32

	// SaltLen is the byte length of commitment salts: 2*128/8 = 32 bytes.
	SaltLen = 32
)

// maxPartyID caps party identifiers to prevent overflow in Lagrange arithmetic.
const maxPartyID = 1<<31 - 1

// orderMinus2 is L-2 for the Ed25519 group order, used by scalarInverse.
// L   = 2^252 + 27742317777372353535851937790883648493
// L   = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED (big-endian)
// L-2 = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3EB (big-endian)
//
// Stored as 32 bytes little-endian (Ed25519 native encoding):
var orderMinus2 = [32]byte{
	0xeb, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

// scalarInverse computes val^(-1) mod L in constant time using Fermat's
// little theorem: a^(-1) = a^(L-2) mod L for prime L.
//
// The exponent L-2 is a public constant, so the square-and-multiply
// loop's branch pattern is fixed and leaks no information about val.
func scalarInverse(val *edwards25519.Scalar) *edwards25519.Scalar {
	// Convert L-2 to big-endian for bit scanning.
	var expBE [32]byte
	for i := 0; i < 32; i++ {
		expBE[i] = orderMinus2[31-i]
	}

	result := edwards25519.NewScalar()
	one := scalarFromUint64(1)
	result.Set(one)

	for i := 0; i < 32; i++ {
		for bit := 7; bit >= 0; bit-- {
			result.Multiply(result, result)
			if (expBE[i]>>uint(bit))&1 == 1 {
				result.Multiply(result, val)
			}
		}
	}
	return result
}

// scalarFromUint64 creates a Scalar from a uint64 value.
func scalarFromUint64(v uint64) *edwards25519.Scalar {
	var buf [32]byte
	buf[0] = byte(v)
	buf[1] = byte(v >> 8)
	buf[2] = byte(v >> 16)
	buf[3] = byte(v >> 24)
	buf[4] = byte(v >> 32)
	buf[5] = byte(v >> 40)
	buf[6] = byte(v >> 48)
	buf[7] = byte(v >> 56)
	s, _ := edwards25519.NewScalar().SetCanonicalBytes(buf[:])
	return s
}

// scalarFromInt creates a Scalar from a positive int.
func scalarFromInt(v int) *edwards25519.Scalar {
	return scalarFromUint64(uint64(v))
}
