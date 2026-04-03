package frost

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// bad is invalid hex that passes JSON parsing but fails hex decoding.
const bad = "ZZZZ"

// valid32 is 64 hex chars (32 bytes) — valid for hex decoding.
const valid32 = "0000000000000000000000000000000000000000000000000000000000000001"

func TestUnmarshalKeyShareErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		json string
	}{
		{"bad secret_share", `{"id":1,"secret_share":"` + bad + `","public_key":"","verification_share":"","group_commitments":[],"threshold":1,"all_ids":[1]}`},
		{"bad public_key", `{"id":1,"secret_share":"` + valid32 + `","public_key":"` + bad + `","verification_share":"","group_commitments":[],"threshold":1,"all_ids":[1]}`},
		{"bad verification_share", `{"id":1,"secret_share":"` + valid32 + `","public_key":"` + valid32 + `","verification_share":"` + bad + `","group_commitments":[],"threshold":1,"all_ids":[1]}`},
		{"bad group_commitment", `{"id":1,"secret_share":"` + valid32 + `","public_key":"` + valid32 + `","verification_share":"` + valid32 + `","group_commitments":["` + bad + `"],"threshold":1,"all_ids":[1]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v KeyShare
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalSignerStateErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		json string
	}{
		{"bad json", `not json`},
		{"bad blacklist key", `{"key_share":null,"blacklist":{"notint":true}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v SignerState
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalDKGRound1OutputErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		json string
	}{
		{"bad feldman", `{"feldman_commitments":["` + bad + `"],"pairwise_commitments":{},"pairwise_salts":{}}`},
		{"bad pairwise_commitment", `{"feldman_commitments":[],"pairwise_commitments":{"1":"` + bad + `"},"pairwise_salts":{}}`},
		{"bad pairwise_salt", `{"feldman_commitments":[],"pairwise_commitments":{},"pairwise_salts":{"1":"` + bad + `"}}`},
		{"bad pairwise_commitment key", `{"feldman_commitments":[],"pairwise_commitments":{"abc":"aa"},"pairwise_salts":{}}`},
		{"bad pairwise_salt key", `{"feldman_commitments":[],"pairwise_commitments":{},"pairwise_salts":{"abc":"aa"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v DKGRound1Output
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalDKGRound2OutputErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		json string
	}{
		{"bad share hex", `{"secret_shares":{"1":"` + bad + `"}}`},
		{"bad share key", `{"secret_shares":{"abc":"aa"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v DKGRound2Output
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalNonceCommitmentErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		json string
	}{
		{"bad hiding", `{"hiding_nonce_commitment":"` + bad + `","binding_nonce_commitment":""}`},
		{"bad binding", `{"hiding_nonce_commitment":"aa","binding_nonce_commitment":"` + bad + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v NonceCommitment
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalSignatureShareErrors(t *testing.T) {
	t.Parallel()
	var v SignatureShare
	require.Error(t, json.Unmarshal([]byte(`{"signer_id":1,"zi":"`+bad+`"}`), &v))
}

func TestUnmarshalRefreshRound1OutputErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		json string
	}{
		{"bad feldman", `{"feldman_commitments":["` + bad + `"],"pairwise_commitments":{},"pairwise_salts":{},"seed_commitment":"","seed_salt":""}`},
		{"bad pairwise_commitment", `{"feldman_commitments":[],"pairwise_commitments":{"1":"` + bad + `"},"pairwise_salts":{},"seed_commitment":"","seed_salt":""}`},
		{"bad pairwise_salt", `{"feldman_commitments":[],"pairwise_commitments":{},"pairwise_salts":{"1":"` + bad + `"},"seed_commitment":"","seed_salt":""}`},
		{"bad seed_commitment", `{"feldman_commitments":[],"pairwise_commitments":{},"pairwise_salts":{},"seed_commitment":"` + bad + `","seed_salt":""}`},
		{"bad seed_salt", `{"feldman_commitments":[],"pairwise_commitments":{},"pairwise_salts":{},"seed_commitment":"` + valid32 + `","seed_salt":"` + bad + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v RefreshRound1Output
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalRefreshRound2OutputErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		json string
	}{
		{"bad share", `{"secret_shares":{"1":"` + bad + `"},"seed":""}`},
		{"bad seed", `{"secret_shares":{},"seed":"` + bad + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v RefreshRound2Output
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}

func TestUnmarshalSignatureErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		json string
	}{
		{"bad r", `{"r":"` + bad + `","z":""}`},
		{"bad z", `{"r":"aa","z":"` + bad + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v Signature
			require.Error(t, json.Unmarshal([]byte(tc.json), &v))
		})
	}
}
