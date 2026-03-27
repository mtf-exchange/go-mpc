package dkls23

import (
	"errors"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// runDKG runs a complete DKG for the given party IDs and threshold.
// Returns (shares, publicKey, allRound1, allRound2, allCoeffs).
func runDKG(t *testing.T, allIDs []int, threshold int) (shares map[int]btcec.ModNScalar, pubKey []byte, allRound1 map[int]*DKGRound1Output, allRound2 map[int]*DKGRound2Output, allCoeffs map[int][]btcec.ModNScalar) {
	t.Helper()
	allRound1 = make(map[int]*DKGRound1Output)
	allRound2 = make(map[int]*DKGRound2Output)
	allCoeffs = make(map[int][]btcec.ModNScalar)

	// Round 1.
	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: threshold}
		r1, coeffs, err := DKGRound1(cfg)
		require.NoError(t, err)
		allRound1[id] = r1
		allCoeffs[id] = coeffs
	}

	// Round 2.
	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: threshold}
		r2, err := DKGRound2(cfg, allCoeffs[id], allRound1)
		require.NoError(t, err)
		allRound2[id] = r2
	}

	// Finalize.
	shares = make(map[int]btcec.ModNScalar)
	var pk []byte
	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: threshold}
		share, pubkey, err := DKGFinalize(cfg, allCoeffs[id], allRound1, allRound2)
		require.NoError(t, err)
		shares[id] = share
		if pk == nil {
			pk = pubkey
		} else {
			require.Equal(t, pk, pubkey, "all parties must agree on public key")
		}
	}
	pubKey = pk
	return
}

func TestDKG3of3(t *testing.T) {
	allIDs := []int{1, 2, 3}
	shares, pubKey, _, _, _ := runDKG(t, allIDs, 3)
	require.NotNil(t, pubKey)
	require.Len(t, shares, 3)
	t.Logf("3-of-3 DKG: pubkey=%x", pubKey)
}

func TestDKG2of3(t *testing.T) {
	allIDs := []int{1, 2, 3}
	shares, pubKey, _, _, _ := runDKG(t, allIDs, 2)
	require.NotNil(t, pubKey)
	require.Len(t, shares, 3)
	t.Logf("2-of-3 DKG: pubkey=%x", pubKey)
}

func TestDKGSharesAreShamir(t *testing.T) {
	// Verify that the shares are valid Shamir shares by checking that Lagrange interpolation
	// of all t shares reconstructs the master public key:
	//   sum_i lagrange(i, allIDs) * share_i * G == pk
	// This verifies the Shamir property without knowing the secret.
	allIDs := []int{1, 2, 3}
	shares, pubKey, _, _, _ := runDKG(t, allIDs, 3)

	q := curveOrder

	// Compute sum_i lagrange(i, allIDs) * share_i as a scalar.
	// Convert to big.Int for arithmetic accumulation.
	reconstructed := new(big.Int)
	for _, id := range allIDs {
		lc := lagrangeCoeff(id, allIDs)
		lcBytes := lc.Bytes()
		lcBig := new(big.Int).SetBytes(lcBytes[:])

		sh := shares[id]
		shareBytes := sh.Bytes()
		shareBig := new(big.Int).SetBytes(shareBytes[:])

		term := new(big.Int).Mul(lcBig, shareBig)
		reconstructed.Add(reconstructed, term)
	}
	reconstructed.Mod(reconstructed, q)

	// LHS = reconstructed * G
	var reconstructedScalar btcec.ModNScalar
	reconstructedScalar.SetByteSlice(reconstructed.Bytes())
	var lhs btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&reconstructedScalar, &lhs)
	lhs.ToAffine()

	// RHS = pk
	pkPoint, err := compressedToPoint(pubKey)
	require.NoError(t, err)
	pkPoint.ToAffine()

	require.True(t, lhs.X.Equals(&pkPoint.X) && lhs.Y.Equals(&pkPoint.Y),
		"Lagrange interpolation of shares must equal the master public key")
	t.Log("Shamir reconstruction check passed")
}

func TestDKGBadFeldmanCommitment(t *testing.T) {
	allIDs := []int{1, 2, 3}
	threshold := 2

	allRound1 := make(map[int]*DKGRound1Output)
	allRound2 := make(map[int]*DKGRound2Output)
	allCoeffs := make(map[int][]btcec.ModNScalar)

	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: threshold}
		r1, coeffs, err := DKGRound1(cfg)
		require.NoError(t, err)
		allRound1[id] = r1
		allCoeffs[id] = coeffs
	}
	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: threshold}
		r2, err := DKGRound2(cfg, allCoeffs[id], allRound1)
		require.NoError(t, err)
		allRound2[id] = r2
	}

	// Party 2 sends a bad Feldman commitment.
	allRound1[2].FeldmanCommitments[0][0] ^= 0xff

	// Party 1 tries to finalize — must get error.
	cfg := DKGPartyConfig{MyID: 1, AllIDs: allIDs, Threshold: threshold}
	_, _, err := DKGFinalize(cfg, allCoeffs[1], allRound1, allRound2)
	require.Error(t, err, "must detect bad Feldman commitment from party 2")
	t.Logf("Correctly detected bad Feldman commitment: %v", err)
}

func TestDKGBadShare(t *testing.T) {
	allIDs := []int{1, 2, 3}
	threshold := 2

	allRound1 := make(map[int]*DKGRound1Output)
	allRound2 := make(map[int]*DKGRound2Output)
	allCoeffs := make(map[int][]btcec.ModNScalar)

	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: threshold}
		r1, coeffs, err := DKGRound1(cfg)
		require.NoError(t, err)
		allRound1[id] = r1
		allCoeffs[id] = coeffs
	}
	for _, id := range allIDs {
		cfg := DKGPartyConfig{MyID: id, AllIDs: allIDs, Threshold: threshold}
		r2, err := DKGRound2(cfg, allCoeffs[id], allRound1)
		require.NoError(t, err)
		allRound2[id] = r2
	}

	// Party 2 sends a bad share to party 1 (wrong value but re-committed).
	// We need to corrupt the secret share AND its commitment.
	badShare := make([]byte, 32)
	badShare[31] = 0x42
	allRound2[2].SecretShares[1] = badShare

	// Now recompute the commitment for the bad share.
	com, salt, err := Commit(badShare)
	require.NoError(t, err)
	allRound1[2].PairwiseCommitments[1] = com
	allRound1[2].PairwiseSalts[1] = salt

	// Party 1 finalizes — Feldman check must fail.
	cfg := DKGPartyConfig{MyID: 1, AllIDs: allIDs, Threshold: threshold}
	_, _, err = DKGFinalize(cfg, allCoeffs[1], allRound1, allRound2)
	require.Error(t, err, "must detect bad share from party 2")
	t.Logf("Correctly detected bad share: %v", err)
}

func TestDKGRound1InvalidThreshold(t *testing.T) {
	cfg := DKGPartyConfig{MyID: 1, AllIDs: []int{1, 2, 3}, Threshold: 0}
	_, _, err := DKGRound1(cfg)
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))

	cfg.Threshold = 4
	_, _, err = DKGRound1(cfg)
	require.Error(t, err)
	require.True(t, errors.As(err, &inputErr))
}

func TestDKGRound1MyIDNotInAllIDs(t *testing.T) {
	cfg := DKGPartyConfig{MyID: 99, AllIDs: []int{1, 2, 3}, Threshold: 2}
	_, _, err := DKGRound1(cfg)
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "99")
}

func TestDKGRound1DuplicateIDs(t *testing.T) {
	cfg := DKGPartyConfig{MyID: 1, AllIDs: []int{1, 1, 2}, Threshold: 2}
	_, _, err := DKGRound1(cfg)
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "duplicate")
}

func TestDKGRound1NegativeID(t *testing.T) {
	cfg := DKGPartyConfig{MyID: -1, AllIDs: []int{-1, 1, 2}, Threshold: 2}
	_, _, err := DKGRound1(cfg)
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "out of range")
}

func TestDKGRound1ZeroID(t *testing.T) {
	cfg := DKGPartyConfig{MyID: 0, AllIDs: []int{0, 1, 2}, Threshold: 2}
	_, _, err := DKGRound1(cfg)
	require.Error(t, err)
	var inputErr *InvalidInputError
	require.True(t, errors.As(err, &inputErr))
	require.Contains(t, inputErr.Detail, "out of range")
}

func TestDKG2of3Sign2of3(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2, 3}
	setups := setupSigners(t, allIDs, 2)
	signers := []int{1, 3}
	msg := []byte("2-of-3 threshold signing")
	r, s := runSigning(t, setups, signers, msg)
	verifyECDSA(t, setups[1].PubKey, msg, r, s)
}

func TestDKG2of2(t *testing.T) {
	t.Parallel()
	allIDs := []int{1, 2}
	setups := setupSigners(t, allIDs, 2)
	msg := []byte("2-of-2 minimal threshold")
	r, s := runSigning(t, setups, allIDs, msg)
	verifyECDSA(t, setups[1].PubKey, msg, r, s)
}

func TestValidatePartyIDsEmpty(t *testing.T) {
	err := validatePartyIDs([]int{}, "test")
	require.NoError(t, err)
}

func TestValidatePartyIDsLargeID(t *testing.T) {
	err := validatePartyIDs([]int{1, maxPartyID + 1}, "test")
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of range")
}
