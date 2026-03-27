package dkls23

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/sha3"
)

// --- Masny-Rindal Endemic Base OT (MR19) over secp256k1 ---
//
// Implements LambdaC=128 base OTs as required by IKNP OT Extension.
// In the IKNP role mapping: the VOLE Bob (OTE receiver) plays the base OT sender,
// and VOLE Alice (OTE sender) plays the base OT receiver.

// shake256Seed computes SHAKE256("base-ot" || k_bytes || point_compressed) → 32 bytes.
func shake256Seed(k int, pointCompressed []byte) []byte {
	h := sha3.NewShake256()
	h.Write([]byte(domainBaseOT))
	var kbuf [8]byte
	binary.BigEndian.PutUint64(kbuf[:], uint64(k))
	h.Write(kbuf[:])
	h.Write(pointCompressed)
	out := make([]byte, 32)
	h.Read(out)
	return out
}

// sampleScalar samples a uniformly random scalar in [1, q-1].
func sampleScalar() (btcec.ModNScalar, error) {
	for {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return btcec.ModNScalar{}, err
		}
		var s btcec.ModNScalar
		s.SetByteSlice(b)
		if !s.IsZero() {
			return s, nil
		}
	}
}

// pointToCompressed serializes a JacobianPoint to 33-byte compressed form.
func pointToCompressed(p *btcec.JacobianPoint) ([]byte, error) {
	p.ToAffine()
	if p.X.IsZero() && p.Y.IsZero() {
		return nil, errors.New("dkls23: cannot serialize point at infinity")
	}
	pub := btcec.NewPublicKey(&p.X, &p.Y)
	return pub.SerializeCompressed(), nil
}

// compressedToPoint parses a 33-byte compressed point.
func compressedToPoint(b []byte) (*btcec.JacobianPoint, error) {
	pub, err := btcec.ParsePubKey(b)
	if err != nil {
		return nil, err
	}
	var jp btcec.JacobianPoint
	pub.AsJacobian(&jp)
	return &jp, nil
}

// scalarMulGCompressed computes s*G and returns the compressed 33-byte encoding.
func scalarMulGCompressed(s *btcec.ModNScalar) ([]byte, error) {
	var result btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(s, &result)
	return pointToCompressed(&result)
}

// scalarMul computes s*P and returns the result as a JacobianPoint.
func scalarMul(s *btcec.ModNScalar, p *btcec.JacobianPoint) *btcec.JacobianPoint {
	var result btcec.JacobianPoint
	btcec.ScalarMultNonConst(s, p, &result)
	return &result
}

// pointAdd computes P+Q.
func pointAdd(p, q *btcec.JacobianPoint) *btcec.JacobianPoint {
	var result btcec.JacobianPoint
	btcec.AddNonConst(p, q, &result)
	return &result
}

// pointNeg returns -P.
func pointNeg(p *btcec.JacobianPoint) *btcec.JacobianPoint {
	neg := *p
	neg.ToAffine()
	neg.Y.Negate(1)
	neg.Y.Normalize()
	return &neg
}

// BaseSenderRound1 generates base OT sender key pairs for n OT instances.
// For each k in [n]: samples a_k ← Zq, computes T_k = a_k*G (33-byte compressed).
// Returns private keys and public keys.
// In the DKLS23 protocol, the OTE receiver (VOLE Bob) calls this as the base OT sender.
func BaseSenderRound1(n int) (privKeys []btcec.ModNScalar, pubKeys [][]byte, err error) {
	privKeys = make([]btcec.ModNScalar, n)
	pubKeys = make([][]byte, n)
	for k := 0; k < n; k++ {
		a, e := sampleScalar()
		if e != nil {
			return nil, nil, e
		}
		privKeys[k] = a
		T, e := scalarMulGCompressed(&a)
		if e != nil {
			return nil, nil, e
		}
		pubKeys[k] = T
	}
	return
}

// BaseReceiverRound1 computes base OT receiver messages and derives receiver seeds.
// For each k in [n]: samples b_k ← Zq; R_k = b_k*G + choices[k]*T_k.
// receiverSeeds[k] = SHAKE256("base-ot" || k_bytes || (b_k*T_k compressed)) — 32 bytes.
// The choice bit determines which OT seed the receiver gets.
// In the DKLS23 protocol, VOLE Alice calls this as the base OT receiver.
func BaseReceiverRound1(senderPubKeys [][]byte, choices []bool) (responses [][]byte, receiverSeeds [][]byte, err error) {
	n := len(senderPubKeys)
	if len(choices) != n {
		return nil, nil, errors.New("dkls23 BaseReceiverRound1: choices length mismatch")
	}
	responses = make([][]byte, n)
	receiverSeeds = make([][]byte, n)

	for k := 0; k < n; k++ {
		Tk, e := compressedToPoint(senderPubKeys[k])
		if e != nil {
			return nil, nil, e
		}
		b, e := sampleScalar()
		if e != nil {
			return nil, nil, e
		}

		// b_k * G
		var bG btcec.JacobianPoint
		btcec.ScalarBaseMultNonConst(&b, &bG)

		// R_k = b_k*G + choices[k]*T_k
		// Branchless: multiply T_k by 0 or 1, then always add.
		var choiceMask btcec.ModNScalar
		choiceMask.SetInt(condUint32(choices[k]))
		choicePt := scalarMul(&choiceMask, Tk)
		var Rk btcec.JacobianPoint
		btcec.AddNonConst(&bG, choicePt, &Rk)

		respBytes, e := pointToCompressed(&Rk)
		if e != nil {
			return nil, nil, e
		}
		responses[k] = respBytes

		// receiverSeeds[k] = SHAKE256("base-ot" || k || (b_k * T_k compressed))
		bTk := scalarMul(&b, Tk)
		bTkBytes, e := pointToCompressed(bTk)
		if e != nil {
			return nil, nil, e
		}
		receiverSeeds[k] = shake256Seed(k, bTkBytes)
	}
	return
}

// BaseSenderFinalize derives sender OT seed pairs from receiver responses.
// For each k:
//   - K0 = SHAKE256("base-ot" || k || (a_k*R_k compressed))
//   - K1 = SHAKE256("base-ot" || k || (a_k*(R_k - T_k) compressed))
//
// seeds0[k] = K0 (matches receiverSeed when choice=false).
// seeds1[k] = K1 (matches receiverSeed when choice=true).
// In the DKLS23 protocol, VOLE Bob calls this as the base OT sender.
func BaseSenderFinalize(privKeys []btcec.ModNScalar, senderPubKeys [][]byte, responses [][]byte) (seeds0, seeds1 [][]byte, err error) {
	n := len(privKeys)
	if len(senderPubKeys) != n || len(responses) != n {
		return nil, nil, errors.New("dkls23 BaseSenderFinalize: length mismatch")
	}
	seeds0 = make([][]byte, n)
	seeds1 = make([][]byte, n)

	for k := 0; k < n; k++ {
		Tk, e := compressedToPoint(senderPubKeys[k])
		if e != nil {
			return nil, nil, e
		}
		Rk, e := compressedToPoint(responses[k])
		if e != nil {
			return nil, nil, e
		}

		// a_k * R_k
		aRk := scalarMul(&privKeys[k], Rk)
		aRkBytes, e := pointToCompressed(aRk)
		if e != nil {
			return nil, nil, e
		}
		seeds0[k] = shake256Seed(k, aRkBytes)

		// a_k * (R_k - T_k)
		negTk := pointNeg(Tk)
		RkMinusTk := pointAdd(Rk, negTk)
		aRkMinusTk := scalarMul(&privKeys[k], RkMinusTk)
		aRkMinusTkBytes, e := pointToCompressed(aRkMinusTk)
		if e != nil {
			return nil, nil, e
		}
		seeds1[k] = shake256Seed(k, aRkMinusTkBytes)
	}
	return
}
