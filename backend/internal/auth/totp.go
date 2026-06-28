package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// TOTP (RFC 6238): HMAC-SHA1, 6 digits, 30-second step — the parameters every
// authenticator app defaults to. Implemented with the std lib (no dependency).
//
// 2FA requires the server to verify codes, so the secret is stored server-side
// (see storage.User.TOTPSecret). The provisioning URI is built client-side so the
// plaintext identifier never reaches the server.

const totpDigits = 6
const totpPeriod = 30 * time.Second

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a new random base32 secret (160 bits).
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32NoPad.EncodeToString(b), nil
}

// CurrentTOTP returns the code for the secret at the current time. Useful for
// tooling and tests; production verifies with VerifyTOTP.
func CurrentTOTP(secret string) (string, error) {
	return totpAt(secret, time.Now())
}

// VerifyTOTP checks a code against the secret, allowing ±1 step for clock skew.
func VerifyTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	now := time.Now()
	for _, skew := range []time.Duration{0, -totpPeriod, totpPeriod} {
		want, err := totpAt(secret, now.Add(skew))
		if err != nil {
			return false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func totpAt(secret string, t time.Time) (string, error) {
	key, err := base32NoPad.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	counter := uint64(t.Unix()) / uint64(totpPeriod.Seconds())
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset]&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])) % 1_000_000
	return fmt.Sprintf("%06d", value), nil
}
