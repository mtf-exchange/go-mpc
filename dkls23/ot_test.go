package dkls23

import (
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestBaseOT(t *testing.T) {
	t.Parallel()
	n := LambdaC // 128 OT instances

	// Generate random choice bits.
	choiceBytes := make([]byte, (n+7)/8)
	_, err := rand.Read(choiceBytes)
	require.NoError(t, err)
	choices := make([]bool, n)
	for k := 0; k < n; k++ {
		choices[k] = (choiceBytes[k/8]>>(uint(k)%8))&1 == 1
	}

	// Sender generates key pairs.
	privKeys, pubKeys, err := BaseSenderRound1(n)
	require.NoError(t, err)

	// Receiver computes responses.
	responses, receiverSeeds, err := BaseReceiverRound1(pubKeys, choices)
	require.NoError(t, err)

	// Sender finalizes to get seed pairs.
	seeds0, seeds1, err := BaseSenderFinalize(privKeys, pubKeys, responses)
	require.NoError(t, err)

	// Verify: receiverSeeds[k] matches seeds0[k] when choice=false, seeds1[k] when choice=true.
	for k := 0; k < n; k++ {
		if choices[k] {
			require.Equal(t, seeds1[k], receiverSeeds[k], "OT seed mismatch at k=%d (choice=true)", k)
		} else {
			require.Equal(t, seeds0[k], receiverSeeds[k], "OT seed mismatch at k=%d (choice=false)", k)
		}
	}
}

func TestScalarInverseCorrectness(t *testing.T) {
	for i := 0; i < 10; i++ {
		a, err := sampleScalar()
		require.NoError(t, err)
		aInv := scalarInverse(&a)
		var product btcec.ModNScalar
		product.Mul2(&a, &aInv)
		var one btcec.ModNScalar
		one.SetInt(1)
		require.True(t, product.Equals(&one), "a * a^(-1) must equal 1")
	}
}

func TestScalarInverseKnownValue(t *testing.T) {
	var two btcec.ModNScalar
	two.SetInt(2)
	inv := scalarInverse(&two)
	var product btcec.ModNScalar
	product.Mul2(&two, &inv)
	var one btcec.ModNScalar
	one.SetInt(1)
	require.True(t, product.Equals(&one))
}
