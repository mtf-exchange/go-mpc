package dkls23

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCommitOpen(t *testing.T) {
	msg := []byte("hello world")
	com, salt, err := Commit(msg)
	require.NoError(t, err)

	// Valid commitment must open.
	err = Open(msg, com, salt)
	require.NoError(t, err)
}

func TestCommitOpenTamperedMsg(t *testing.T) {
	msg := []byte("hello world")
	com, salt, err := Commit(msg)
	require.NoError(t, err)

	// Tampered message must fail.
	err = Open([]byte("tampered"), com, salt)
	require.Error(t, err)
}

func TestCommitOpenTamperedSalt(t *testing.T) {
	msg := []byte("hello world")
	com, salt, err := Commit(msg)
	require.NoError(t, err)

	// Tamper salt.
	salt[0] ^= 0xff
	err = Open(msg, com, salt)
	require.Error(t, err)
}

func TestFZeroThreePartiesSum(t *testing.T) {
	// Run FZero setup between all pairs among 3 parties.
	parties := []int{1, 2, 3}
	// seeds[i][j] = shared seed between party i and j
	seeds := map[int]map[int][16]byte{}
	for _, id := range parties {
		seeds[id] = map[int][16]byte{}
	}

	for pi := 0; pi < len(parties); pi++ {
		for pj := pi + 1; pj < len(parties); pj++ {
			idI := parties[pi]
			idJ := parties[pj]

			comI, saltI, seedI, err := FZeroSetupRound1()
			require.NoError(t, err)
			comJ, saltJ, seedJ, err := FZeroSetupRound1()
			require.NoError(t, err)

			sharedIJ, err := FZeroSetupFinalize(seedI, comJ, saltJ, seedJ)
			require.NoError(t, err)
			sharedJI, err := FZeroSetupFinalize(seedJ, comI, saltI, seedI)
			require.NoError(t, err)

			// Both parties must compute the same shared seed.
			require.Equal(t, sharedIJ, sharedJI)

			seeds[idI][idJ] = sharedIJ
			seeds[idJ][idI] = sharedJI
		}
	}

	index := []byte("test-index")
	q := curveOrder

	// Sum all shares: must be 0 mod q.
	// FZeroSample returns btcec.ModNScalar; convert to big.Int for summation.
	total := new(big.Int)
	for _, id := range parties {
		z := FZeroSample(seeds[id], id, index)
		zBytes := z.Bytes()
		zBig := new(big.Int).SetBytes(zBytes[:])
		total.Add(total, zBig)
	}
	total.Mod(total, q)
	require.Equal(t, 0, total.Sign(), "FZero shares must sum to 0 mod q")
}

func TestFZeroTamperedCommitment(t *testing.T) {
	comI, saltI, seedI, err := FZeroSetupRound1()
	require.NoError(t, err)
	_ = comI
	_ = saltI

	_, _, seedJ, err := FZeroSetupRound1()
	require.NoError(t, err)

	// Tamper comI before passing to J.
	var badCom [32]byte
	badCom[0] ^= 0xff

	_, err = FZeroSetupFinalize(seedJ, badCom, saltI, seedI)
	require.Error(t, err)
}
