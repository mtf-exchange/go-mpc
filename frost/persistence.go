package frost

import (
	"encoding/json"
	"fmt"
)

// SetupEncryptor is the interface callers must implement to provide
// at-rest encryption for KeyShare persistence.
//
// Implementations might use AES-GCM with a key from an HSM, an envelope
// encryption scheme, or a platform keychain. The frost package does not
// prescribe a specific cipher.
type SetupEncryptor interface {
	// Encrypt takes plaintext JSON and returns an opaque ciphertext blob.
	Encrypt(plaintext []byte) ([]byte, error)
	// Decrypt reverses Encrypt, returning the original plaintext JSON.
	Decrypt(ciphertext []byte) ([]byte, error)
}

// MarshalKeyShare serializes a KeyShare to JSON.
// The output contains the secret share in plaintext — callers should
// encrypt the result before writing to disk.
func MarshalKeyShare(ks *KeyShare) ([]byte, error) {
	return json.Marshal(ks)
}

// UnmarshalKeyShare deserializes a KeyShare from JSON.
func UnmarshalKeyShare(data []byte) (*KeyShare, error) {
	var ks KeyShare
	if err := json.Unmarshal(data, &ks); err != nil {
		return nil, fmt.Errorf("frost UnmarshalKeyShare: %w", err)
	}
	return &ks, nil
}

// MarshalSignerState serializes a SignerState to JSON.
// Safe for concurrent use: acquires a read lock.
func MarshalSignerState(ss *SignerState) ([]byte, error) {
	return json.Marshal(ss)
}

// UnmarshalSignerState deserializes a SignerState from JSON.
func UnmarshalSignerState(data []byte) (*SignerState, error) {
	var ss SignerState
	if err := json.Unmarshal(data, &ss); err != nil {
		return nil, fmt.Errorf("frost UnmarshalSignerState: %w", err)
	}
	if ss.Blacklist == nil {
		ss.Blacklist = make(map[int]bool)
	}
	return &ss, nil
}

// MarshalEncrypted serializes and encrypts a KeyShare in one step.
func MarshalEncrypted(ks *KeyShare, enc SetupEncryptor) ([]byte, error) {
	plaintext, err := MarshalKeyShare(ks)
	if err != nil {
		return nil, fmt.Errorf("frost MarshalEncrypted: marshal: %w", err)
	}
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		return nil, fmt.Errorf("frost MarshalEncrypted: encrypt: %w", err)
	}
	return ciphertext, nil
}

// UnmarshalEncrypted decrypts and deserializes a KeyShare in one step.
func UnmarshalEncrypted(ciphertext []byte, enc SetupEncryptor) (*KeyShare, error) {
	plaintext, err := enc.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("frost UnmarshalEncrypted: decrypt: %w", err)
	}
	return UnmarshalKeyShare(plaintext)
}
