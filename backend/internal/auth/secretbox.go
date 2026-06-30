package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

// At-rest encryption for server-held secrets (currently the TOTP secret). The
// secret is an authentication factor, not vault data, but encrypting it under a
// stable server key means a stolen database or backup alone — without the server
// secret — cannot read enrolled TOTP secrets. AES-256-GCM with a random nonce.

// SecretBoxKey derives a 32-byte key from a stable server secret, domain-separated
// so it never collides with other uses of that secret. Derive it from a secret you
// do not rotate (the identifier pepper), since rotating it would orphan stored
// ciphertext.
func SecretBoxKey(serverSecret string) []byte {
	sum := sha256.Sum256([]byte("passwd.secretbox.v1:" + serverSecret))
	return sum[:]
}

// EncryptSecret seals plaintext with AES-256-GCM, returning "base64(nonce)|base64(ct)".
func EncryptSecret(key []byte, plaintext string) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(nonce) + "|" + base64.StdEncoding.EncodeToString(ct), nil
}

// DecryptSecret reverses EncryptSecret.
func DecryptSecret(key []byte, blob string) (string, error) {
	i := strings.IndexByte(blob, '|')
	if i < 0 {
		return "", errors.New("auth: malformed sealed secret")
	}
	nonce, err := base64.StdEncoding.DecodeString(blob[:i])
	if err != nil {
		return "", err
	}
	ct, err := base64.StdEncoding.DecodeString(blob[i+1:])
	if err != nil {
		return "", err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
