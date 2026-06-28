package auth

import (
	"testing"
	"time"
)

// RFC 6238 Appendix B known-answer vector: the ASCII seed "12345678901234567890"
// at T=59s yields 8-digit 94287082, i.e. 6-digit 287082 (SHA-1).
func TestTOTPRFC6238Vector(t *testing.T) {
	secret := base32NoPad.EncodeToString([]byte("12345678901234567890"))
	got, err := totpAt(secret, time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got != "287082" {
		t.Fatalf("totp = %s want 287082", got)
	}
}

func TestTOTPVerify(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	code, err := CurrentTOTP(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyTOTP(secret, code) {
		t.Fatal("valid code rejected")
	}
	// A code from 10 minutes ago is well outside the ±1 step window.
	stale, _ := totpAt(secret, time.Now().Add(-10*time.Minute))
	if VerifyTOTP(secret, stale) {
		t.Fatal("stale code accepted")
	}
	if VerifyTOTP(secret, "abc") {
		t.Fatal("malformed code accepted")
	}
}
