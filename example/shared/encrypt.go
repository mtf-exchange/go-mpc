// Package shared provides utilities used by both the dkls23 and frost examples.
package shared

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

// AESEncryptor implements both dkls23.SetupEncryptor and frost.SetupEncryptor
// using AES-256-GCM. The key must be exactly 32 bytes.
type AESEncryptor struct {
	Key [32]byte
}

func (e *AESEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.Key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (e *AESEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.Key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
}

// LoadOrCreateKey loads an AES-256 key from dir/enc.key, or generates one
// if it doesn't exist. Returns the encryptor and whether the key was loaded
// (true) or freshly created (false).
func LoadOrCreateKey(dir string) (*AESEncryptor, bool, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, false, fmt.Errorf("create dir: %w", err)
	}

	keyPath := filepath.Join(dir, "enc.key")
	data, err := os.ReadFile(keyPath)
	if err == nil && len(data) == 32 {
		var key [32]byte
		copy(key[:], data)
		return &AESEncryptor{Key: key}, true, nil
	}

	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, false, fmt.Errorf("generate key: %w", err)
	}
	if err := os.WriteFile(keyPath, key[:], 0600); err != nil {
		return nil, false, fmt.Errorf("write key: %w", err)
	}
	return &AESEncryptor{Key: key}, false, nil
}
