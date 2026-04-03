package frost

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyShareRoundTrip(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	for id, ks := range keyShares {
		got := roundTrip(t, "KeyShare", ks)
		assert.Equal(t, id, got.ID)
		assert.Equal(t, ks.SecretShare, got.SecretShare)
		assert.Equal(t, ks.PublicKey, got.PublicKey)
	}
}

func TestSignerStateRoundTrip(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	ss := NewSignerState(keyShares[1])
	ss.Blacklist[2] = true

	got := roundTrip(t, "SignerState", ss)
	assert.Equal(t, keyShares[1].ID, got.KeyShare.ID)
	assert.True(t, got.Blacklist[2])
}

func TestDKGRound1OutputRoundTrip(t *testing.T) {
	t.Parallel()
	cfg := DKGPartyConfig{MyID: 1, AllIDs: []int{1, 2, 3}, Threshold: 3}
	out, _, err := DKGRound1(cfg)
	require.NoError(t, err)
	roundTrip(t, "DKGRound1Output", out)
}

func TestDKGRound2OutputRoundTrip(t *testing.T) {
	t.Parallel()
	cfg := DKGPartyConfig{MyID: 1, AllIDs: []int{1, 2, 3}, Threshold: 3}
	_, coeffs, err := DKGRound1(cfg)
	require.NoError(t, err)
	out, err := DKGRound2(cfg, coeffs)
	require.NoError(t, err)
	roundTrip(t, "DKGRound2Output", out)
}

func TestNonceCommitmentRoundTrip(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	signer := NewSignerState(keyShares[1])
	_, comm, err := SignRound1(signer, []int{1, 2, 3})
	require.NoError(t, err)
	roundTrip(t, "NonceCommitment", comm)
}

func TestSignatureShareRoundTrip(t *testing.T) {
	t.Parallel()
	ss := &SignatureShare{SignerID: 1, Zi: make([]byte, 32)}
	roundTrip(t, "SignatureShare", ss)
}

func TestSignatureRoundTrip(t *testing.T) {
	t.Parallel()
	keyShares := fullSetup(t)
	sig := fullSign(t, keyShares, []int{1, 2, 3}, []byte("encoding test"))
	roundTrip(t, "Signature", sig)
}
