package dkls23

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVOLECorrectnessRandom(t *testing.T) {
	t.Parallel()
	aliceState, bobState, err := runVOLEPairwise()
	require.NoError(t, err)

	// Sample random inputs for Alice.
	r_i, err := sampleScalar()
	require.NoError(t, err)
	sk_i, err := sampleScalar()
	require.NoError(t, err)

	sid := "test-vole-sid"
	c_u, c_v, voleMsg, err := VOLEAliceMultiply(aliceState, sid, &r_i, &sk_i)
	require.NoError(t, err)

	d_u, d_v, err := VOLEBobReceive(bobState, sid, voleMsg)
	require.NoError(t, err)

	q := curveOrder

	// Convert ModNScalar values to big.Int for arithmetic verification.
	cuBytes := c_u.Bytes()
	cuBig := new(big.Int).SetBytes(cuBytes[:])
	duBytes := d_u.Bytes()
	duBig := new(big.Int).SetBytes(duBytes[:])
	cvBytes := c_v.Bytes()
	cvBig := new(big.Int).SetBytes(cvBytes[:])
	dvBytes := d_v.Bytes()
	dvBig := new(big.Int).SetBytes(dvBytes[:])
	riBytes := r_i.Bytes()
	riBig := new(big.Int).SetBytes(riBytes[:])
	skiBytes := sk_i.Bytes()
	skiBig := new(big.Int).SetBytes(skiBytes[:])
	chiBytes := bobState.Chi.Bytes()
	chiBig := new(big.Int).SetBytes(chiBytes[:])

	// Verify: c_u + d_u == r_i * chi mod q.
	sum_u := new(big.Int).Add(cuBig, duBig)
	sum_u.Mod(sum_u, q)
	expected_u := new(big.Int).Mul(riBig, chiBig)
	expected_u.Mod(expected_u, q)
	require.Equal(t, 0, expected_u.Cmp(sum_u), "c_u + d_u must equal r_i * chi mod q")

	// Verify: c_v + d_v == sk_i * chi mod q.
	sum_v := new(big.Int).Add(cvBig, dvBig)
	sum_v.Mod(sum_v, q)
	expected_v := new(big.Int).Mul(skiBig, chiBig)
	expected_v.Mod(expected_v, q)
	require.Equal(t, 0, expected_v.Cmp(sum_v), "c_v + d_v must equal sk_i * chi mod q")
}

func TestVOLEMaliciousATilde(t *testing.T) {
	t.Parallel()
	aliceState, bobState, err := runVOLEPairwise()
	require.NoError(t, err)

	r_i, err := sampleScalar()
	require.NoError(t, err)
	sk_i, err := sampleScalar()
	require.NoError(t, err)

	sid := "test-vole-malicious"
	_, _, voleMsg, err := VOLEAliceMultiply(aliceState, sid, &r_i, &sk_i)
	require.NoError(t, err)

	// Tamper aTilde to simulate a malicious Alice.
	voleMsg.ATilde[0][0][0] ^= 0xff

	_, _, err = VOLEBobReceive(bobState, sid, voleMsg)
	require.Error(t, err, "Bob must detect tampered aTilde")
}

func TestVOLEMultipleRounds(t *testing.T) {
	t.Parallel()
	// Run 3 independent VOLE instances to check no state corruption.
	for trial := 0; trial < 3; trial++ {
		aliceState, bobState, err := runVOLEPairwise()
		require.NoError(t, err)

		r_i, err := sampleScalar()
		require.NoError(t, err)
		sk_i, err := sampleScalar()
		require.NoError(t, err)

		sid := "trial-vole"
		c_u, c_v, voleMsg, err := VOLEAliceMultiply(aliceState, sid, &r_i, &sk_i)
		require.NoError(t, err)

		d_u, d_v, err := VOLEBobReceive(bobState, sid, voleMsg)
		require.NoError(t, err)

		q := curveOrder

		cuBytes := c_u.Bytes()
		cuBig := new(big.Int).SetBytes(cuBytes[:])
		duBytes := d_u.Bytes()
		duBig := new(big.Int).SetBytes(duBytes[:])
		cvBytes := c_v.Bytes()
		cvBig := new(big.Int).SetBytes(cvBytes[:])
		dvBytes := d_v.Bytes()
		dvBig := new(big.Int).SetBytes(dvBytes[:])
		riBytes := r_i.Bytes()
		riBig := new(big.Int).SetBytes(riBytes[:])
		skiBytes := sk_i.Bytes()
		skiBig := new(big.Int).SetBytes(skiBytes[:])
		chiBytes := bobState.Chi.Bytes()
		chiBig := new(big.Int).SetBytes(chiBytes[:])

		sum_u := new(big.Int).Add(cuBig, duBig)
		sum_u.Mod(sum_u, q)
		expected_u := new(big.Int).Mul(riBig, chiBig)
		expected_u.Mod(expected_u, q)
		require.Equal(t, 0, expected_u.Cmp(sum_u))

		sum_v := new(big.Int).Add(cvBig, dvBig)
		sum_v.Mod(sum_v, q)
		expected_v := new(big.Int).Mul(skiBig, chiBig)
		expected_v.Mod(expected_v, q)
		require.Equal(t, 0, expected_v.Cmp(sum_v))
	}
}
