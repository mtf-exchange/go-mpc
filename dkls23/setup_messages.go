package dkls23

import "encoding/json"

// Pairwise setup message types for network-based VOLE + FZero establishment.
//
// In the example code, SetupPairwiseWith passes values directly between two
// in-process Node pointers. In production, the two nodes are separate processes
// and exchange these messages over the network.
//
// The protocol for establishing one directed VOLE pair (A→B, where A is Alice
// and B is Bob) plus FZero proceeds as follows:
//
//	Step 1: B → A:  BaseOTSenderMsg      (B's 128 sender public keys)
//	Step 2: A → B:  BaseOTReceiverMsg     (A's 128 receiver responses)
//	Step 3: B → A:  OTExtCorrectionsMsg   (B's Xi/8-byte correction vectors)
//	        (both sides expand locally)
//	Step 4: A → B:  FZeroCommitMsg        (A's seed commitment)
//	        B → A:  FZeroCommitMsg        (B's seed commitment)
//	Step 5: A → B:  FZeroRevealMsg        (A's seed + salt)
//	        B → A:  FZeroRevealMsg        (B's seed + salt)
//
// For a bidirectional VOLE (required for signing), steps 1-3 run twice
// with swapped roles.  Steps 4-5 run once per pair.

// BaseOTSenderMsg is sent by the base OT sender (Bob) in step 1.
// Contains LambdaC compressed EC public keys.
type BaseOTSenderMsg struct {
	// PubKeys are the sender's LambdaC compressed secp256k1 public keys (33 bytes each).
	PubKeys [][]byte `json:"pub_keys"`
}

// BaseOTReceiverMsg is sent by the base OT receiver (Alice) in step 2.
// Contains LambdaC compressed EC point responses.
type BaseOTReceiverMsg struct {
	// Responses are the receiver's LambdaC responses (33 bytes each).
	Responses [][]byte `json:"responses"`
}

// OTExtCorrectionsMsg is sent by the OTE receiver (Bob) in step 3.
// Contains the correction vectors needed by Alice to expand her OTE values.
type OTExtCorrectionsMsg struct {
	// Corrections are LambdaC correction bit-vectors, each Xi/8 bytes.
	Corrections [][Xi / 8]byte `json:"corrections"`
}

// FZeroCommitMsg is sent by each party in step 4 of FZero setup.
type FZeroCommitMsg struct {
	// Commitment is FCom(seed): SHA-256(seed || salt).
	Commitment [32]byte `json:"commitment"`
}

// FZeroRevealMsg is sent by each party in step 5 of FZero setup.
type FZeroRevealMsg struct {
	// Seed is the 16-byte seed committed in FZeroCommitMsg.
	Seed [16]byte `json:"seed"`
	// Salt is the 32-byte FCom salt for the commitment.
	Salt [SaltLen]byte `json:"salt"`
}

// --- JSON encoding for setup messages ---

// OTExtCorrectionsMsg needs custom encoding because [][Xi/8]byte contains
// fixed-size arrays that don't serialize well as default JSON.

type otExtCorrectionsMsgJSON struct {
	Corrections []string `json:"corrections"`
}

func (m *OTExtCorrectionsMsg) MarshalJSON() ([]byte, error) {
	corrs := make([]string, len(m.Corrections))
	for i, c := range m.Corrections {
		corrs[i] = bytesToHex(c[:])
	}
	return json.Marshal(otExtCorrectionsMsgJSON{Corrections: corrs})
}

func (m *OTExtCorrectionsMsg) UnmarshalJSON(data []byte) error {
	var j otExtCorrectionsMsgJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	m.Corrections = make([][Xi / 8]byte, len(j.Corrections))
	for i, s := range j.Corrections {
		b, err := hexToBytes(s)
		if err != nil {
			return err
		}
		copy(m.Corrections[i][:], b)
	}
	return nil
}

type fzeroCommitMsgJSON struct {
	Commitment string `json:"commitment"`
}

func (m *FZeroCommitMsg) MarshalJSON() ([]byte, error) {
	return json.Marshal(fzeroCommitMsgJSON{
		Commitment: bytesToHex(m.Commitment[:]),
	})
}

func (m *FZeroCommitMsg) UnmarshalJSON(data []byte) error {
	var j fzeroCommitMsgJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	m.Commitment, err = hexToFixed32(j.Commitment)
	return err
}

type fzeroRevealMsgJSON struct {
	Seed string `json:"seed"`
	Salt string `json:"salt"`
}

func (m *FZeroRevealMsg) MarshalJSON() ([]byte, error) {
	return json.Marshal(fzeroRevealMsgJSON{
		Seed: bytesToHex(m.Seed[:]),
		Salt: bytesToHex(m.Salt[:]),
	})
}

func (m *FZeroRevealMsg) UnmarshalJSON(data []byte) error {
	var j fzeroRevealMsgJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	var err error
	m.Seed, err = hexToFixed16(j.Seed)
	if err != nil {
		return err
	}
	m.Salt, err = hexToFixed32(j.Salt)
	return err
}
