package crypto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// These assertions hold the Go reference impl to the exact same known-answer
// vectors the TS package reproduces (clients/packages/crypto/src/vectors.test.ts),
// proving client/server crypto agreement. Regenerate with
// `npm -w @passwd/crypto run gen-vectors`.

type vectorFile struct {
	Inputs struct {
		Password             string    `json:"password"`
		Identifier           string    `json:"identifier"`
		NormalizedIdentifier string    `json:"normalizedIdentifier"`
		PBKDF2               KDFParams `json:"pbkdf2"`
		Argon2id             KDFParams `json:"argon2id"`
		AESKeyHex            string    `json:"aesKeyHex"`
		AESNonceHex          string    `json:"aesNonceHex"`
		AESPlaintext         string    `json:"aesPlaintext"`
		HKDFInfoEnc          string    `json:"hkdfInfoEnc"`
		HKDFInfoMac          string    `json:"hkdfInfoMac"`
	} `json:"inputs"`
	Expected struct {
		MasterKeyPbkdf2Hex    string `json:"masterKeyPbkdf2Hex"`
		MasterKeyArgon2idHex  string `json:"masterKeyArgon2idHex"`
		StretchedEncKeyHex    string `json:"stretchedEncKeyHex"`
		StretchedMacKeyHex    string `json:"stretchedMacKeyHex"`
		MasterPasswordHashB64 string `json:"masterPasswordHashB64"`
		AESGCMCiphertextHex   string `json:"aesGcmCiphertextHex"`
		EncString             string `json:"encString"`
	} `json:"expected"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	path := filepath.Join("..", "..", "..", "docs", "test-vectors.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func TestNormalizeIdentifier(t *testing.T) {
	v := loadVectors(t)
	if got := NormalizeIdentifier(v.Inputs.Identifier); got != v.Inputs.NormalizedIdentifier {
		t.Errorf("normalize = %q want %q", got, v.Inputs.NormalizedIdentifier)
	}
	if got := NormalizeIdentifier("  Alice@EXAMPLE.com  "); got != "alice@example.com" {
		t.Errorf("normalize messy = %q", got)
	}
}

func TestKDFPbkdf2Vector(t *testing.T) {
	v := loadVectors(t)
	mk, err := DeriveMasterKey(v.Inputs.Password, v.Inputs.Identifier, v.Inputs.PBKDF2)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(mk); got != v.Expected.MasterKeyPbkdf2Hex {
		t.Errorf("pbkdf2 master key = %s want %s", got, v.Expected.MasterKeyPbkdf2Hex)
	}
}

func TestKDFArgon2idVector(t *testing.T) {
	v := loadVectors(t)
	mk, err := DeriveMasterKey(v.Inputs.Password, v.Inputs.Identifier, v.Inputs.Argon2id)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(mk); got != v.Expected.MasterKeyArgon2idHex {
		t.Errorf("argon2id master key = %s want %s", got, v.Expected.MasterKeyArgon2idHex)
	}
}

func TestHKDFExpandVector(t *testing.T) {
	v := loadVectors(t)
	mk := mustHex(t, v.Expected.MasterKeyPbkdf2Hex)
	enc, err := HKDFExpand(mk, v.Inputs.HKDFInfoEnc, 32)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := HKDFExpand(mk, v.Inputs.HKDFInfoMac, 32)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(enc); got != v.Expected.StretchedEncKeyHex {
		t.Errorf("enc key = %s want %s", got, v.Expected.StretchedEncKeyHex)
	}
	if got := hex.EncodeToString(mac); got != v.Expected.StretchedMacKeyHex {
		t.Errorf("mac key = %s want %s", got, v.Expected.StretchedMacKeyHex)
	}
}

func TestMasterPasswordHashVector(t *testing.T) {
	v := loadVectors(t)
	mk := mustHex(t, v.Expected.MasterKeyPbkdf2Hex)
	if got := DeriveMasterPasswordHash(mk, v.Inputs.Password); got != v.Expected.MasterPasswordHashB64 {
		t.Errorf("master password hash = %s want %s", got, v.Expected.MasterPasswordHashB64)
	}
}

func TestAESGCMAndEncStringVector(t *testing.T) {
	v := loadVectors(t)
	key := mustHex(t, v.Inputs.AESKeyHex)
	nonce := mustHex(t, v.Inputs.AESNonceHex)
	ct, err := AESGCMEncrypt(key, nonce, []byte(v.Inputs.AESPlaintext))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(ct); got != v.Expected.AESGCMCiphertextHex {
		t.Errorf("aes-gcm ciphertext = %s want %s", got, v.Expected.AESGCMCiphertextHex)
	}
	if got := SerializeEncString(1, nonce, ct); got != v.Expected.EncString {
		t.Errorf("enc string = %s want %s", got, v.Expected.EncString)
	}
}
