package dkls23

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOTExtCorrectionsMsgRoundTrip(t *testing.T) {
	m := &OTExtCorrectionsMsg{
		Corrections: make([][Xi / 8]byte, LambdaC),
	}
	for i := range m.Corrections {
		rand.Read(m.Corrections[i][:])
	}
	got := roundTrip(t, "OTExtCorrectionsMsg", m)
	require.Equal(t, m.Corrections, got.Corrections)
}

func TestFZeroCommitMsgRoundTrip(t *testing.T) {
	var m FZeroCommitMsg
	rand.Read(m.Commitment[:])
	got := roundTrip(t, "FZeroCommitMsg", &m)
	require.Equal(t, m.Commitment, got.Commitment)
}

func TestFZeroRevealMsgRoundTrip(t *testing.T) {
	var m FZeroRevealMsg
	rand.Read(m.Seed[:])
	rand.Read(m.Salt[:])
	got := roundTrip(t, "FZeroRevealMsg", &m)
	require.Equal(t, m.Seed, got.Seed)
	require.Equal(t, m.Salt, got.Salt)
}

func TestBaseOTSenderMsgRoundTrip(t *testing.T) {
	_, pubs, err := BaseSenderRound1(LambdaC)
	require.NoError(t, err)
	m := &BaseOTSenderMsg{PubKeys: pubs}
	got := roundTrip(t, "BaseOTSenderMsg", m)
	require.Equal(t, len(m.PubKeys), len(got.PubKeys))
	for i := range m.PubKeys {
		require.Equal(t, m.PubKeys[i], got.PubKeys[i])
	}
}

func TestBaseOTReceiverMsgRoundTrip(t *testing.T) {
	_, pubs, err := BaseSenderRound1(LambdaC)
	require.NoError(t, err)
	choices := make([]bool, LambdaC)
	for i := range choices {
		b := make([]byte, 1)
		rand.Read(b)
		choices[i] = b[0]&1 == 1
	}
	responses, _, err := BaseReceiverRound1(pubs, choices)
	require.NoError(t, err)
	m := &BaseOTReceiverMsg{Responses: responses}
	got := roundTrip(t, "BaseOTReceiverMsg", m)
	require.Equal(t, len(m.Responses), len(got.Responses))
}
