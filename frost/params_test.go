package frost

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScalarInverse(t *testing.T) {
	t.Parallel()

	// a * a^{-1} == 1
	a := scalarFromUint64(42)
	aInv := scalarInverse(a)
	product := edwards25519.NewScalar().Multiply(a, aInv)
	one := scalarFromUint64(1)
	assert.Equal(t, one.Bytes(), product.Bytes())
}

func TestScalarInverseLarger(t *testing.T) {
	t.Parallel()

	// Test with a larger value.
	s, err := sampleScalar()
	require.NoError(t, err)

	sInv := scalarInverse(s)
	product := edwards25519.NewScalar().Multiply(s, sInv)
	one := scalarFromUint64(1)
	assert.Equal(t, one.Bytes(), product.Bytes())
}

func TestLagrangeCoeff(t *testing.T) {
	t.Parallel()

	// For a 2-of-3 scheme with IDs {1,2}, check that Lagrange coefficients
	// reconstruct a known polynomial evaluated at x=0.
	allIDs := []int{1, 2}
	l1 := lagrangeCoeff(1, allIDs)
	l2 := lagrangeCoeff(2, allIDs)

	// If f(1) = s1, f(2) = s2, then f(0) = l1*s1 + l2*s2.
	// For f(x) = a + b*x, s1 = a+b, s2 = a+2b.
	// l1 should be 2, l2 should be -1 (mod L).
	two := scalarFromUint64(2)
	negOne := edwards25519.NewScalar().Subtract(edwards25519.NewScalar(), scalarFromUint64(1))

	assert.Equal(t, two.Bytes(), l1.Bytes())
	assert.Equal(t, negOne.Bytes(), l2.Bytes())
}

func TestScalarFromInt(t *testing.T) {
	t.Parallel()
	s := scalarFromInt(256)
	var expected [32]byte
	expected[0] = 0
	expected[1] = 1 // 256 in LE
	sExpected, _ := edwards25519.NewScalar().SetCanonicalBytes(expected[:])
	assert.Equal(t, sExpected.Bytes(), s.Bytes())
}
