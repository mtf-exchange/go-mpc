package frost

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignRoundTrip3of3(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	msg := []byte("hello FROST threshold Ed25519")

	sig := fullSign(t, keyShares, []int{1, 2, 3}, msg)

	// Verify with our cofactored verifier.
	assert.True(t, Verify(keyShares[1].PublicKey, msg, sig))
}

func TestSignRoundTrip2of3(t *testing.T) {
	t.Parallel()
	keyShares, err := buildDKG([]int{1, 2, 3}, 2)
	require.NoError(t, err)
	msg := []byte("2-of-3 signing test")

	// All 3 possible 2-of-3 subsets should produce valid signatures.
	subsets := [][]int{{1, 2}, {1, 3}, {2, 3}}
	for _, subset := range subsets {
		sig := fullSign(t, keyShares, subset, msg)
		assert.True(t, Verify(keyShares[1].PublicKey, msg, sig), "failed for subset %v", subset)
	}
}

func TestSignatureRFC8032Compatible(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	msg := []byte("RFC 8032 compatibility test")

	sig := fullSign(t, keyShares, []int{1, 2, 3}, msg)

	// Verify with Go's standard crypto/ed25519 library.
	pk := ed25519.PublicKey(keyShares[1].PublicKey)
	sigBytes := sig.Bytes()
	assert.True(t, ed25519.Verify(pk, msg, sigBytes), "crypto/ed25519.Verify failed on FROST signature")
}

func TestSignDifferentMessages(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)

	msg1 := []byte("message one")
	msg2 := []byte("message two")

	sig1 := fullSign(t, keyShares, []int{1, 2, 3}, msg1)
	sig2 := fullSign(t, keyShares, []int{1, 2, 3}, msg2)

	// Both valid for their messages.
	assert.True(t, Verify(keyShares[1].PublicKey, msg1, sig1))
	assert.True(t, Verify(keyShares[1].PublicKey, msg2, sig2))

	// Cross-verify should fail.
	assert.False(t, Verify(keyShares[1].PublicKey, msg2, sig1))
	assert.False(t, Verify(keyShares[1].PublicKey, msg1, sig2))
}

func TestSignEmptyMessage(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	msg := []byte{}

	sig := fullSign(t, keyShares, []int{1, 2, 3}, msg)
	assert.True(t, Verify(keyShares[1].PublicKey, msg, sig))
}

func TestSignNonceReuseBlocked(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	signers := []int{1, 2, 3}
	msg := []byte("test")

	signer := NewSignerState(keyShares[1])
	state, _, err := SignRound1(signer, signers)
	require.NoError(t, err)

	// Build full commitments for round 2.
	allComm := make(map[int]*NonceCommitment)
	allComm[1] = state.Commitment
	for _, id := range []int{2, 3} {
		s := NewSignerState(keyShares[id])
		_, comm, err := SignRound1(s, signers)
		require.NoError(t, err)
		allComm[id] = comm
	}

	input := &Round2Input{Message: msg, AllCommitments: allComm}
	_, err = SignRound2(signer, state, input)
	require.NoError(t, err)

	// Second call with same state should fail (consumed).
	_, err = SignRound2(signer, state, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already consumed")
}

func TestSignBelowThreshold(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)

	signer := NewSignerState(keyShares[1])
	// 3-of-3 threshold, only 2 signers.
	_, _, err := SignRound1(signer, []int{1, 2})
	assert.Error(t, err)
}

func TestSignBlacklist(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)

	signer := NewSignerState(keyShares[1])
	signer.Blacklist[2] = true

	_, _, err := SignRound1(signer, []int{1, 2, 3})
	require.Error(t, err)
	var blErr *BlacklistedPartyError
	assert.ErrorAs(t, err, &blErr)
	assert.Contains(t, blErr.PartyIDs, 2)
}

func TestSignAggregateWithoutVerificationShares(t *testing.T) {
	t.Parallel()
	keyShares, err := buildDKG([]int{1, 2, 3}, 2)
	require.NoError(t, err)
	signers := []int{1, 2}
	msg := []byte("no share verification")

	states := make(map[int]*SignerState)
	r1States := make(map[int]*Round1State)
	allComm := make(map[int]*NonceCommitment)
	for _, id := range signers {
		states[id] = NewSignerState(keyShares[id])
		st, comm, err := SignRound1(states[id], signers)
		require.NoError(t, err)
		r1States[id] = st
		allComm[id] = comm
	}

	allShares := make(map[int]*SignatureShare)
	input := &Round2Input{Message: msg, AllCommitments: allComm}
	for _, id := range signers {
		share, err := SignRound2(states[id], r1States[id], input)
		require.NoError(t, err)
		allShares[id] = share
	}

	// Pass nil for verification shares — skips individual share verification.
	sig, err := Aggregate(allComm, allShares, msg, keyShares[1].PublicKey, nil, signers)
	require.NoError(t, err)
	assert.True(t, Verify(keyShares[1].PublicKey, msg, sig))
}

func TestSignRound2MissingCommitment(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	signers := []int{1, 2, 3}

	signer := NewSignerState(keyShares[1])
	state, _, err := SignRound1(signer, signers)
	require.NoError(t, err)

	// Missing commitment for signer 3.
	input := &Round2Input{
		Message: []byte("test"),
		AllCommitments: map[int]*NonceCommitment{
			1: state.Commitment,
			2: state.Commitment,
		},
	}
	_, err = SignRound2(signer, state, input)
	assert.Error(t, err)
}

func TestSignMyIDNotInSigners(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	signer := NewSignerState(keyShares[1])
	_, _, err := SignRound1(signer, []int{2, 3, 4})
	assert.Error(t, err)
}

func TestSignCheatingShareDetection(t *testing.T) {
	t.Parallel()
	keyShares, err := buildDKG([]int{1, 2, 3}, 2)
	require.NoError(t, err)
	signers := []int{1, 2}
	msg := []byte("test cheating detection")

	states := make(map[int]*SignerState)
	r1States := make(map[int]*Round1State)
	allComm := make(map[int]*NonceCommitment)
	for _, id := range signers {
		states[id] = NewSignerState(keyShares[id])
		st, comm, err := SignRound1(states[id], signers)
		require.NoError(t, err)
		r1States[id] = st
		allComm[id] = comm
	}

	allShares := make(map[int]*SignatureShare)
	input := &Round2Input{Message: msg, AllCommitments: allComm}
	for _, id := range signers {
		share, err := SignRound2(states[id], r1States[id], input)
		require.NoError(t, err)
		allShares[id] = share
	}

	// Corrupt signer 2's share.
	allShares[2].Zi = make([]byte, 32) // zero

	verShares := make(map[int][]byte)
	for _, id := range signers {
		verShares[id] = keyShares[id].VerificationShare
	}

	_, err = Aggregate(allComm, allShares, msg, keyShares[1].PublicKey, verShares, signers)
	require.Error(t, err)
	var cheatErr *CheatingPartyError
	require.ErrorAs(t, err, &cheatErr)
	assert.Contains(t, cheatErr.PartyIDs, 2)
}

func TestSignInvalidPartyIDs(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	signer := NewSignerState(keyShares[1])

	// Duplicate IDs.
	_, _, err := SignRound1(signer, []int{1, 1, 3})
	assert.Error(t, err)

	// Zero ID.
	_, _, err = SignRound1(signer, []int{0, 1, 3})
	assert.Error(t, err)
}

func TestSignCorruptedCommitmentPoint(t *testing.T) {
	t.Parallel()
	keyShares, err := buildDKG([]int{1, 2, 3}, 2)
	require.NoError(t, err)
	signers := []int{1, 2}

	states := make(map[int]*SignerState)
	r1States := make(map[int]*Round1State)
	allComm := make(map[int]*NonceCommitment)
	for _, id := range signers {
		states[id] = NewSignerState(keyShares[id])
		st, comm, err := SignRound1(states[id], signers)
		require.NoError(t, err)
		r1States[id] = st
		allComm[id] = comm
	}

	// Corrupt signer 2's hiding nonce commitment with a y-coordinate not on the curve.
	// y=2 (LE: 0x02, 0x00, ...) is not on Edwards25519 (x^2 has no square root).
	badPoint := make([]byte, 32)
	badPoint[0] = 0x02
	allComm[2].HidingNonceCommitment = badPoint

	input := &Round2Input{Message: []byte("test"), AllCommitments: allComm}
	_, err = SignRound2(states[1], r1States[1], input)
	assert.Error(t, err, "should fail on invalid commitment point")
}

func TestAggregateMissingShare(t *testing.T) {
	t.Parallel()
	keyShares, err := buildDKG([]int{1, 2, 3}, 2)
	require.NoError(t, err)
	signers := []int{1, 2}

	states := make(map[int]*SignerState)
	r1States := make(map[int]*Round1State)
	allComm := make(map[int]*NonceCommitment)
	for _, id := range signers {
		states[id] = NewSignerState(keyShares[id])
		st, comm, err := SignRound1(states[id], signers)
		require.NoError(t, err)
		r1States[id] = st
		allComm[id] = comm
	}

	allShares := make(map[int]*SignatureShare)
	input := &Round2Input{Message: []byte("test"), AllCommitments: allComm}
	for _, id := range signers {
		share, err := SignRound2(states[id], r1States[id], input)
		require.NoError(t, err)
		allShares[id] = share
	}

	// Remove signer 2's share — aggregate with verification should detect.
	verShares := map[int][]byte{1: keyShares[1].VerificationShare, 2: keyShares[2].VerificationShare}
	delete(allShares, 2)
	_, err = Aggregate(allComm, allShares, []byte("test"), keyShares[1].PublicKey, verShares, signers)
	assert.Error(t, err)
}

func TestAggregateInvalidShareScalar(t *testing.T) {
	t.Parallel()
	keyShares, err := buildDKG([]int{1, 2, 3}, 2)
	require.NoError(t, err)
	signers := []int{1, 2}

	states := make(map[int]*SignerState)
	r1States := make(map[int]*Round1State)
	allComm := make(map[int]*NonceCommitment)
	for _, id := range signers {
		states[id] = NewSignerState(keyShares[id])
		st, comm, err := SignRound1(states[id], signers)
		require.NoError(t, err)
		r1States[id] = st
		allComm[id] = comm
	}

	allShares := make(map[int]*SignatureShare)
	input := &Round2Input{Message: []byte("test"), AllCommitments: allComm}
	for _, id := range signers {
		share, err := SignRound2(states[id], r1States[id], input)
		require.NoError(t, err)
		allShares[id] = share
	}

	// Give signer 2 a non-canonical scalar (all 0xff bytes).
	allShares[2].Zi = make([]byte, 32)
	for i := range allShares[2].Zi {
		allShares[2].Zi[i] = 0xff
	}

	// Without verification shares, aggregate should fail at scalar parse or final verify.
	_, err = Aggregate(allComm, allShares, []byte("test"), keyShares[1].PublicKey, nil, signers)
	assert.Error(t, err)
}

func TestSignPostPersistenceRoundTrip(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	msg := []byte("persistence round-trip signing")

	// Marshal and unmarshal each key share, then sign with the restored copies.
	restored := make(map[int]*KeyShare)
	for id, ks := range keyShares {
		data, err := MarshalKeyShare(ks)
		require.NoError(t, err)
		got, err := UnmarshalKeyShare(data)
		require.NoError(t, err)
		restored[id] = got
	}

	sig := fullSign(t, restored, []int{1, 2, 3}, msg)
	assert.True(t, Verify(restored[1].PublicKey, msg, sig))
	assert.True(t, ed25519.Verify(ed25519.PublicKey(restored[1].PublicKey), msg, sig.Bytes()))
}
