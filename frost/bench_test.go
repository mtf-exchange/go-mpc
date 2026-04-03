package frost

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
)

func BenchmarkDKG3of3(b *testing.B) {
	for b.Loop() {
		_, err := buildDKG([]int{1, 2, 3}, 3)
		require.NoError(b, err)
	}
}

func BenchmarkSign3of3(b *testing.B) {
	keyShares := fullSetup(b)
	msg := []byte("benchmark signing")

	b.ResetTimer()
	for b.Loop() {
		fullSign(b, keyShares, []int{1, 2, 3}, msg)
	}
}

func BenchmarkVerify(b *testing.B) {
	keyShares := fullSetup(b)
	msg := []byte("benchmark verify")
	sig := fullSign(b, keyShares, []int{1, 2, 3}, msg)

	b.ResetTimer()
	for b.Loop() {
		Verify(keyShares[1].PublicKey, msg, sig)
	}
}

func BenchmarkScalarInverse(b *testing.B) {
	s := scalarFromUint64(12345)
	b.ResetTimer()
	for b.Loop() {
		scalarInverse(s)
	}
}

func BenchmarkLagrangeCoeff(b *testing.B) {
	ids := []int{1, 2, 3}
	b.ResetTimer()
	for b.Loop() {
		lagrangeCoeff(1, ids)
	}
}

func BenchmarkH1(b *testing.B) {
	msg := make([]byte, 128)
	b.ResetTimer()
	for b.Loop() {
		H1(msg)
	}
}

func BenchmarkEvalPoly(b *testing.B) {
	coeffs := make([]*edwards25519.Scalar, 3)
	for i := range coeffs {
		coeffs[i] = scalarFromUint64(uint64(i + 1))
	}
	b.ResetTimer()
	for b.Loop() {
		evalPoly(coeffs, 5)
	}
}
