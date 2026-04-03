package frost

import (
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// Domain separation tags for the five hash functions (RFC 9591 Section 6.5).
const (
	domainRho   = "rho"
	domainNonce = "nonce"
	domainMsg   = "msg"
	domainCom   = "com"
)

// H1 maps arbitrary data to a Scalar. Domain: "rho" (binding factor derivation).
//
//	H1(m) = SHA-512(ContextString || "rho" || m) mod L
//
// (RFC 9591 Section 6.5, H1)
func H1(msg []byte) *edwards25519.Scalar {
	prefix := []byte(ContextString + domainRho)
	return hashToScalar(prefix, msg)
}

// H2 computes the challenge scalar per RFC 8032: NO domain prefix.
//
//	H2(m) = SHA-512(m) mod L
//
// This is the standard Ed25519 challenge hash to ensure RFC 8032 compatibility.
// The input m is typically R_encoded || PK_encoded || msg.
// (RFC 9591 Section 6.5, H2)
func H2(msg []byte) *edwards25519.Scalar {
	return hashToScalar(nil, msg)
}

// H3 maps arbitrary data to a Scalar. Domain: "nonce" (nonce derivation).
//
//	H3(m) = SHA-512(ContextString || "nonce" || m) mod L
//
// (RFC 9591 Section 6.5, H3)
func H3(msg []byte) *edwards25519.Scalar {
	prefix := []byte(ContextString + domainNonce)
	return hashToScalar(prefix, msg)
}

// H4 hashes arbitrary data to a byte string. Domain: "msg" (message hash).
//
//	H4(m) = SHA-512(ContextString || "msg" || m)
//
// (RFC 9591 Section 6.5, H4)
func H4(msg []byte) []byte {
	return hashToBytes([]byte(ContextString+domainMsg), msg)
}

// H5 hashes arbitrary data to a byte string. Domain: "com" (commitment hash).
//
//	H5(m) = SHA-512(ContextString || "com" || m)
//
// (RFC 9591 Section 6.5, H5)
func H5(msg []byte) []byte {
	return hashToBytes([]byte(ContextString+domainCom), msg)
}

// hashToScalar computes SHA-512(prefix || msg) and reduces mod L.
// If prefix is nil (H2), only msg is hashed.
func hashToScalar(prefix []byte, msg []byte) *edwards25519.Scalar {
	h := sha512.New()
	if prefix != nil {
		h.Write(prefix)
	}
	h.Write(msg)
	digest := h.Sum(nil) // 64 bytes

	s, err := edwards25519.NewScalar().SetUniformBytes(digest)
	if err != nil {
		// SetUniformBytes only fails if len != 64, which cannot happen with SHA-512.
		panic("frost: SHA-512 produced non-64-byte output")
	}
	return s
}

// hashToBytes computes SHA-512(prefix || msg) and returns the 64-byte digest.
func hashToBytes(prefix []byte, msg []byte) []byte {
	h := sha512.New()
	if prefix != nil {
		h.Write(prefix)
	}
	h.Write(msg)
	return h.Sum(nil)
}
