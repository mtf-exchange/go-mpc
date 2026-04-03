package frost

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
)

// JSON encoding conventions:
// - Scalars: hex-encoded 64 characters (32 bytes little-endian)
// - Points: hex-encoded 64 characters (32 bytes compressed Edwards)
// - Maps with int keys: encoded as string keys (JSON doesn't support int keys)

// --- KeyShare ---

type keyShareJSON struct {
	ID                int                `json:"id"`
	SecretShare       string             `json:"secret_share"`
	PublicKey         string             `json:"public_key"`
	VerificationShare string             `json:"verification_share"`
	GroupCommitments  []string           `json:"group_commitments"`
	Threshold         int                `json:"threshold"`
	AllIDs            []int              `json:"all_ids"`
}

func (ks *KeyShare) MarshalJSON() ([]byte, error) {
	j := keyShareJSON{
		ID:                ks.ID,
		SecretShare:       hex.EncodeToString(ks.SecretShare),
		PublicKey:         hex.EncodeToString(ks.PublicKey),
		VerificationShare: hex.EncodeToString(ks.VerificationShare),
		Threshold:         ks.Threshold,
		AllIDs:            ks.AllIDs,
	}
	j.GroupCommitments = make([]string, len(ks.GroupCommitments))
	for i, c := range ks.GroupCommitments {
		j.GroupCommitments[i] = hex.EncodeToString(c)
	}
	return json.Marshal(j)
}

func (ks *KeyShare) UnmarshalJSON(data []byte) error {
	var j keyShareJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	ks.ID = j.ID
	ks.SecretShare, err = hex.DecodeString(j.SecretShare)
	if err != nil {
		return fmt.Errorf("frost: decode secret_share: %w", err)
	}
	ks.PublicKey, err = hex.DecodeString(j.PublicKey)
	if err != nil {
		return fmt.Errorf("frost: decode public_key: %w", err)
	}
	ks.VerificationShare, err = hex.DecodeString(j.VerificationShare)
	if err != nil {
		return fmt.Errorf("frost: decode verification_share: %w", err)
	}
	ks.GroupCommitments = make([][]byte, len(j.GroupCommitments))
	for i, c := range j.GroupCommitments {
		ks.GroupCommitments[i], err = hex.DecodeString(c)
		if err != nil {
			return fmt.Errorf("frost: decode group_commitment[%d]: %w", i, err)
		}
	}
	ks.Threshold = j.Threshold
	ks.AllIDs = j.AllIDs
	return nil
}

// --- SignerState ---

type signerStateJSON struct {
	KeyShare  *KeyShare        `json:"key_share"`
	Blacklist map[string]bool  `json:"blacklist"`
	Epoch     int              `json:"epoch"`
}

func (ss *SignerState) MarshalJSON() ([]byte, error) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	j := signerStateJSON{
		KeyShare:  ss.KeyShare,
		Blacklist: intBoolMapToString(ss.Blacklist),
		Epoch:     ss.Epoch,
	}
	return json.Marshal(j)
}

func (ss *SignerState) UnmarshalJSON(data []byte) error {
	var j signerStateJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	ss.KeyShare = j.KeyShare
	bl, err := stringBoolMapToInt(j.Blacklist)
	if err != nil {
		return err
	}
	ss.Blacklist = bl
	ss.Epoch = j.Epoch
	return nil
}

// --- DKGRound1Output ---

type dkgRound1JSON struct {
	FeldmanCommitments  []string            `json:"feldman_commitments"`
	PairwiseCommitments map[string]string   `json:"pairwise_commitments"`
	PairwiseSalts       map[string]string   `json:"pairwise_salts"`
}

func (o *DKGRound1Output) MarshalJSON() ([]byte, error) {
	j := dkgRound1JSON{
		FeldmanCommitments:  make([]string, len(o.FeldmanCommitments)),
		PairwiseCommitments: make(map[string]string),
		PairwiseSalts:       make(map[string]string),
	}
	for i, c := range o.FeldmanCommitments {
		j.FeldmanCommitments[i] = hex.EncodeToString(c)
	}
	for k, v := range o.PairwiseCommitments {
		j.PairwiseCommitments[strconv.Itoa(k)] = hex.EncodeToString(v[:])
	}
	for k, v := range o.PairwiseSalts {
		j.PairwiseSalts[strconv.Itoa(k)] = hex.EncodeToString(v[:])
	}
	return json.Marshal(j)
}

func (o *DKGRound1Output) UnmarshalJSON(data []byte) error {
	var j dkgRound1JSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	o.FeldmanCommitments = make([][]byte, len(j.FeldmanCommitments))
	for i, s := range j.FeldmanCommitments {
		b, err := hex.DecodeString(s)
		if err != nil {
			return fmt.Errorf("frost: decode feldman[%d]: %w", i, err)
		}
		o.FeldmanCommitments[i] = b
	}
	o.PairwiseCommitments = make(map[int][32]byte)
	for k, v := range j.PairwiseCommitments {
		id, err := strconv.Atoi(k)
		if err != nil {
			return err
		}
		b, err := hex.DecodeString(v)
		if err != nil {
			return err
		}
		var arr [32]byte
		copy(arr[:], b)
		o.PairwiseCommitments[id] = arr
	}
	o.PairwiseSalts = make(map[int][SaltLen]byte)
	for k, v := range j.PairwiseSalts {
		id, err := strconv.Atoi(k)
		if err != nil {
			return err
		}
		b, err := hex.DecodeString(v)
		if err != nil {
			return err
		}
		var arr [SaltLen]byte
		copy(arr[:], b)
		o.PairwiseSalts[id] = arr
	}
	return nil
}

// --- DKGRound2Output ---

type dkgRound2JSON struct {
	SecretShares map[string]string `json:"secret_shares"`
}

func (o *DKGRound2Output) MarshalJSON() ([]byte, error) {
	j := dkgRound2JSON{SecretShares: make(map[string]string)}
	for k, v := range o.SecretShares {
		j.SecretShares[strconv.Itoa(k)] = hex.EncodeToString(v)
	}
	return json.Marshal(j)
}

func (o *DKGRound2Output) UnmarshalJSON(data []byte) error {
	var j dkgRound2JSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	o.SecretShares = make(map[int][]byte)
	for k, v := range j.SecretShares {
		id, err := strconv.Atoi(k)
		if err != nil {
			return err
		}
		b, err := hex.DecodeString(v)
		if err != nil {
			return err
		}
		o.SecretShares[id] = b
	}
	return nil
}

// --- NonceCommitment ---

type nonceCommitmentJSON struct {
	HidingNonceCommitment  string `json:"hiding_nonce_commitment"`
	BindingNonceCommitment string `json:"binding_nonce_commitment"`
}

func (nc *NonceCommitment) MarshalJSON() ([]byte, error) {
	return json.Marshal(nonceCommitmentJSON{
		HidingNonceCommitment:  hex.EncodeToString(nc.HidingNonceCommitment),
		BindingNonceCommitment: hex.EncodeToString(nc.BindingNonceCommitment),
	})
}

func (nc *NonceCommitment) UnmarshalJSON(data []byte) error {
	var j nonceCommitmentJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	nc.HidingNonceCommitment, err = hex.DecodeString(j.HidingNonceCommitment)
	if err != nil {
		return err
	}
	nc.BindingNonceCommitment, err = hex.DecodeString(j.BindingNonceCommitment)
	return err
}

// --- SignatureShare ---

type signatureShareJSON struct {
	SignerID int    `json:"signer_id"`
	Zi       string `json:"zi"`
}

func (ss *SignatureShare) MarshalJSON() ([]byte, error) {
	return json.Marshal(signatureShareJSON{
		SignerID: ss.SignerID,
		Zi:       hex.EncodeToString(ss.Zi),
	})
}

func (ss *SignatureShare) UnmarshalJSON(data []byte) error {
	var j signatureShareJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	ss.SignerID = j.SignerID
	var err error
	ss.Zi, err = hex.DecodeString(j.Zi)
	return err
}

// --- Signature ---

type signatureJSON struct {
	R string `json:"r"`
	Z string `json:"z"`
}

func (s *Signature) MarshalJSON() ([]byte, error) {
	return json.Marshal(signatureJSON{
		R: hex.EncodeToString(s.R),
		Z: hex.EncodeToString(s.Z),
	})
}

func (s *Signature) UnmarshalJSON(data []byte) error {
	var j signatureJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	s.R, err = hex.DecodeString(j.R)
	if err != nil {
		return err
	}
	s.Z, err = hex.DecodeString(j.Z)
	return err
}

// --- RefreshRound1Output ---

type refreshRound1JSON struct {
	FeldmanCommitments  []string            `json:"feldman_commitments"`
	PairwiseCommitments map[string]string   `json:"pairwise_commitments"`
	PairwiseSalts       map[string]string   `json:"pairwise_salts"`
	SeedCommitment      string              `json:"seed_commitment"`
	SeedSalt            string              `json:"seed_salt"`
}

func (o *RefreshRound1Output) MarshalJSON() ([]byte, error) {
	j := refreshRound1JSON{
		FeldmanCommitments:  make([]string, len(o.FeldmanCommitments)),
		PairwiseCommitments: make(map[string]string),
		PairwiseSalts:       make(map[string]string),
		SeedCommitment:      hex.EncodeToString(o.SeedCommitment[:]),
		SeedSalt:            hex.EncodeToString(o.SeedSalt[:]),
	}
	for i, c := range o.FeldmanCommitments {
		j.FeldmanCommitments[i] = hex.EncodeToString(c)
	}
	for k, v := range o.PairwiseCommitments {
		j.PairwiseCommitments[strconv.Itoa(k)] = hex.EncodeToString(v[:])
	}
	for k, v := range o.PairwiseSalts {
		j.PairwiseSalts[strconv.Itoa(k)] = hex.EncodeToString(v[:])
	}
	return json.Marshal(j)
}

func (o *RefreshRound1Output) UnmarshalJSON(data []byte) error {
	var j refreshRound1JSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	o.FeldmanCommitments = make([][]byte, len(j.FeldmanCommitments))
	for i, s := range j.FeldmanCommitments {
		b, err := hex.DecodeString(s)
		if err != nil {
			return fmt.Errorf("frost: decode refresh feldman[%d]: %w", i, err)
		}
		o.FeldmanCommitments[i] = b
	}
	o.PairwiseCommitments = make(map[int][32]byte)
	for k, v := range j.PairwiseCommitments {
		id, err := strconv.Atoi(k)
		if err != nil {
			return err
		}
		b, err := hex.DecodeString(v)
		if err != nil {
			return err
		}
		var arr [32]byte
		copy(arr[:], b)
		o.PairwiseCommitments[id] = arr
	}
	o.PairwiseSalts = make(map[int][SaltLen]byte)
	for k, v := range j.PairwiseSalts {
		id, err := strconv.Atoi(k)
		if err != nil {
			return err
		}
		b, err := hex.DecodeString(v)
		if err != nil {
			return err
		}
		var arr [SaltLen]byte
		copy(arr[:], b)
		o.PairwiseSalts[id] = arr
	}
	seedComBytes, err := hex.DecodeString(j.SeedCommitment)
	if err != nil {
		return fmt.Errorf("frost: decode seed_commitment: %w", err)
	}
	copy(o.SeedCommitment[:], seedComBytes)
	seedSaltBytes, err := hex.DecodeString(j.SeedSalt)
	if err != nil {
		return fmt.Errorf("frost: decode seed_salt: %w", err)
	}
	copy(o.SeedSalt[:], seedSaltBytes)
	return nil
}

// --- RefreshRound2Output ---

type refreshRound2JSON struct {
	SecretShares map[string]string `json:"secret_shares"`
	Seed         string            `json:"seed"`
}

func (o *RefreshRound2Output) MarshalJSON() ([]byte, error) {
	j := refreshRound2JSON{
		SecretShares: make(map[string]string),
		Seed:         hex.EncodeToString(o.Seed[:]),
	}
	for k, v := range o.SecretShares {
		j.SecretShares[strconv.Itoa(k)] = hex.EncodeToString(v)
	}
	return json.Marshal(j)
}

func (o *RefreshRound2Output) UnmarshalJSON(data []byte) error {
	var j refreshRound2JSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	o.SecretShares = make(map[int][]byte)
	for k, v := range j.SecretShares {
		id, err := strconv.Atoi(k)
		if err != nil {
			return err
		}
		b, err := hex.DecodeString(v)
		if err != nil {
			return err
		}
		o.SecretShares[id] = b
	}
	seedBytes, err := hex.DecodeString(j.Seed)
	if err != nil {
		return fmt.Errorf("frost: decode seed: %w", err)
	}
	copy(o.Seed[:], seedBytes)
	return nil
}

// --- helpers ---

func intBoolMapToString(m map[int]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[strconv.Itoa(k)] = v
	}
	return out
}

func stringBoolMapToInt(m map[string]bool) (map[int]bool, error) {
	out := make(map[int]bool, len(m))
	for k, v := range m {
		id, err := strconv.Atoi(k)
		if err != nil {
			return nil, fmt.Errorf("frost: invalid blacklist key %q: %w", k, err)
		}
		out[id] = v
	}
	return out, nil
}

