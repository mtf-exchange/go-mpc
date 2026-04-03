package frost

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDKG3of3(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)

	// All parties agree on the same public key.
	pk := keyShares[1].PublicKey
	for _, id := range []int{2, 3} {
		assert.Equal(t, pk, keyShares[id].PublicKey, "public key mismatch for party %d", id)
	}

	// All parties agree on the same group commitments.
	for _, id := range []int{2, 3} {
		assert.Equal(t, keyShares[1].GroupCommitments, keyShares[id].GroupCommitments, "group commitments mismatch for party %d", id)
	}

	// Verification shares are valid: s_i * B matches.
	for _, id := range []int{1, 2, 3} {
		sk, err := edwards25519.NewScalar().SetCanonicalBytes(keyShares[id].SecretShare)
		require.NoError(t, err)
		expected := edwards25519.NewGeneratorPoint().ScalarBaseMult(sk).Bytes()
		assert.Equal(t, expected, keyShares[id].VerificationShare, "verification share mismatch for party %d", id)
	}
}

func TestDKG2of3(t *testing.T) {
	t.Parallel()
	keyShares, err := buildDKG([]int{1, 2, 3}, 2)
	require.NoError(t, err)

	// All parties agree on public key.
	pk := keyShares[1].PublicKey
	for _, id := range []int{2, 3} {
		assert.Equal(t, pk, keyShares[id].PublicKey)
	}
}

func TestDKGSharesAreShamir(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)

	// Reconstruct secret via Lagrange interpolation at x=0.
	allIDs := []int{1, 2, 3}
	reconstructed := edwards25519.NewScalar()
	for _, id := range allIDs {
		sk, err := edwards25519.NewScalar().SetCanonicalBytes(keyShares[id].SecretShare)
		require.NoError(t, err)
		lc := lagrangeCoeff(id, allIDs)
		term := edwards25519.NewScalar().Multiply(sk, lc)
		reconstructed.Add(reconstructed, term)
	}

	// Reconstructed secret * B should equal group public key.
	expected := edwards25519.NewGeneratorPoint().ScalarBaseMult(reconstructed).Bytes()
	assert.Equal(t, keyShares[1].PublicKey, expected)
}

func TestDKG2of3SubsetReconstruction(t *testing.T) {
	t.Parallel()
	keyShares, err := buildDKG([]int{1, 2, 3}, 2)
	require.NoError(t, err)

	// Any 2-of-3 subset should reconstruct the same secret.
	subsets := [][]int{{1, 2}, {1, 3}, {2, 3}}
	var secrets []*edwards25519.Scalar
	for _, subset := range subsets {
		reconstructed := edwards25519.NewScalar()
		for _, id := range subset {
			sk, err := edwards25519.NewScalar().SetCanonicalBytes(keyShares[id].SecretShare)
			require.NoError(t, err)
			lc := lagrangeCoeff(id, subset)
			term := edwards25519.NewScalar().Multiply(sk, lc)
			reconstructed.Add(reconstructed, term)
		}
		secrets = append(secrets, reconstructed)
	}

	// All subsets reconstruct the same secret.
	for i := 1; i < len(secrets); i++ {
		assert.Equal(t, secrets[0].Bytes(), secrets[i].Bytes(), "subset %d produced different secret", i)
	}

	// And the reconstructed secret matches the public key.
	expected := edwards25519.NewGeneratorPoint().ScalarBaseMult(secrets[0]).Bytes()
	assert.Equal(t, keyShares[1].PublicKey, expected)
}

func TestDKGInvalidInputs(t *testing.T) {
	t.Parallel()

	_, _, err := DKGRound1(DKGPartyConfig{MyID: 1, AllIDs: []int{1, 2}, Threshold: 0})
	assert.Error(t, err, "zero threshold")

	_, _, err = DKGRound1(DKGPartyConfig{MyID: 1, AllIDs: []int{1, 2}, Threshold: 3})
	assert.Error(t, err, "threshold exceeds party count")

	_, _, err = DKGRound1(DKGPartyConfig{MyID: 5, AllIDs: []int{1, 2}, Threshold: 2})
	assert.Error(t, err, "myID not in AllIDs")

	_, _, err = DKGRound1(DKGPartyConfig{MyID: 1, AllIDs: []int{1, 1}, Threshold: 2})
	assert.Error(t, err, "duplicate IDs")

	_, _, err = DKGRound1(DKGPartyConfig{MyID: 0, AllIDs: []int{0, 1}, Threshold: 2})
	assert.Error(t, err, "zero party ID")
}

func TestDKGFinalizeMissingRound1(t *testing.T) {
	t.Parallel()

	allIDs := []int{1, 2, 3}
	configs := make(map[int]DKGPartyConfig)
	coeffs := make(map[int][]*edwards25519.Scalar)
	r1 := make(map[int]*DKGRound1Output)

	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: 3}
		configs[id] = cfg
		out, c, err := DKGRound1(cfg)
		require.NoError(t, err)
		r1[id] = out
		coeffs[id] = c
	}

	r2 := make(map[int]*DKGRound2Output)
	for _, id := range allIDs {
		out, err := DKGRound2(configs[id], coeffs[id])
		require.NoError(t, err)
		r2[id] = out
	}

	// Remove party 2's round 1 output — party 1 should detect it.
	r1Missing := make(map[int]*DKGRound1Output)
	r1Missing[1] = r1[1]
	r1Missing[3] = r1[3]
	// nil for party 2

	_, err := DKGFinalize(configs[1], coeffs[1], r1Missing, r2)
	require.Error(t, err)
	var cheatErr *CheatingPartyError
	require.ErrorAs(t, err, &cheatErr)
	assert.Contains(t, cheatErr.PartyIDs, 2)
}

func TestDKGCheatingDetection(t *testing.T) {
	t.Parallel()

	allIDs := []int{1, 2, 3}
	configs := make(map[int]DKGPartyConfig)
	coeffs := make(map[int][]*edwards25519.Scalar)
	r1 := make(map[int]*DKGRound1Output)

	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: 3}
		configs[id] = cfg
		out, c, err := DKGRound1(cfg)
		require.NoError(t, err)
		r1[id] = out
		coeffs[id] = c
	}

	r2 := make(map[int]*DKGRound2Output)
	for _, id := range allIDs {
		out, err := DKGRound2(configs[id], coeffs[id])
		require.NoError(t, err)
		r2[id] = out
	}

	// Corrupt party 2's share sent to party 1.
	r2[2].SecretShares[1] = make([]byte, 32) // zero share won't match commitments

	_, err := DKGFinalize(configs[1], coeffs[1], r1, r2)
	require.Error(t, err)
	var cheatErr *CheatingPartyError
	require.ErrorAs(t, err, &cheatErr)
	assert.Contains(t, cheatErr.PartyIDs, 2)
}

func TestDKG2of2Minimal(t *testing.T) {
	t.Parallel()
	keyShares, err := buildDKG([]int{1, 2}, 2)
	require.NoError(t, err)
	assert.Equal(t, keyShares[1].PublicKey, keyShares[2].PublicKey)

	// Sign with the minimal 2-of-2 setup.
	msg := []byte("2-of-2 minimal threshold")
	sig := fullSign(t, keyShares, []int{1, 2}, msg)
	assert.True(t, Verify(keyShares[1].PublicKey, msg, sig))
}

func TestDKGWrongCommitmentCount(t *testing.T) {
	t.Parallel()

	allIDs := []int{1, 2, 3}
	configs := make(map[int]DKGPartyConfig)
	coeffs := make(map[int][]*edwards25519.Scalar)
	r1 := make(map[int]*DKGRound1Output)

	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: 3}
		configs[id] = cfg
		out, c, err := DKGRound1(cfg)
		require.NoError(t, err)
		r1[id] = out
		coeffs[id] = c
	}

	r2 := make(map[int]*DKGRound2Output)
	for _, id := range allIDs {
		out, err := DKGRound2(configs[id], coeffs[id])
		require.NoError(t, err)
		r2[id] = out
	}

	// Party 2 sends wrong number of Feldman commitments (2 instead of 3).
	r1[2].FeldmanCommitments = r1[2].FeldmanCommitments[:2]

	_, err := DKGFinalize(configs[1], coeffs[1], r1, r2)
	require.Error(t, err)
	var cheatErr *CheatingPartyError
	require.ErrorAs(t, err, &cheatErr)
	assert.Contains(t, cheatErr.PartyIDs, 2)
}

func TestDKGBadShareLength(t *testing.T) {
	t.Parallel()

	allIDs := []int{1, 2, 3}
	configs := make(map[int]DKGPartyConfig)
	coeffs := make(map[int][]*edwards25519.Scalar)
	r1 := make(map[int]*DKGRound1Output)

	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: 3}
		configs[id] = cfg
		out, c, err := DKGRound1(cfg)
		require.NoError(t, err)
		r1[id] = out
		coeffs[id] = c
	}

	r2 := make(map[int]*DKGRound2Output)
	for _, id := range allIDs {
		out, err := DKGRound2(configs[id], coeffs[id])
		require.NoError(t, err)
		r2[id] = out
	}

	// Party 2 sends a truncated share to party 1.
	r2[2].SecretShares[1] = []byte{0x01, 0x02} // too short

	_, err := DKGFinalize(configs[1], coeffs[1], r1, r2)
	require.Error(t, err)
	var cheatErr *CheatingPartyError
	require.ErrorAs(t, err, &cheatErr)
	assert.Contains(t, cheatErr.PartyIDs, 2)
}

func TestDKGNonCanonicalShare(t *testing.T) {
	t.Parallel()

	allIDs := []int{1, 2, 3}
	configs := make(map[int]DKGPartyConfig)
	coeffs := make(map[int][]*edwards25519.Scalar)
	r1 := make(map[int]*DKGRound1Output)

	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: 3}
		configs[id] = cfg
		out, c, err := DKGRound1(cfg)
		require.NoError(t, err)
		r1[id] = out
		coeffs[id] = c
	}

	r2 := make(map[int]*DKGRound2Output)
	for _, id := range allIDs {
		out, err := DKGRound2(configs[id], coeffs[id])
		require.NoError(t, err)
		r2[id] = out
	}

	// Party 2 sends a non-canonical scalar (all 0xff, >= group order).
	nonCanonical := make([]byte, 32)
	for i := range nonCanonical {
		nonCanonical[i] = 0xff
	}
	r2[2].SecretShares[1] = nonCanonical

	_, err := DKGFinalize(configs[1], coeffs[1], r1, r2)
	require.Error(t, err)
	var cheatErr *CheatingPartyError
	require.ErrorAs(t, err, &cheatErr)
	assert.Contains(t, cheatErr.PartyIDs, 2)
}
