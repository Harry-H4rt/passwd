package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Access tokens are stateless HS256 JWTs (implemented with the std lib — no JWT
// dependency). Refresh tokens are opaque random strings; only their SHA-256 is
// stored, and they are rotated on every use.

const (
	AccessTokenTTL  = 15 * time.Minute
	RefreshTokenTTL = 30 * 24 * time.Hour
)

var (
	ErrInvalidToken = errors.New("auth: invalid token")
	jwtB64          = base64.RawURLEncoding
)

type accessClaims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// IssueAccessToken returns a signed HS256 JWT for the given user.
func IssueAccessToken(userID, secret string, ttl time.Duration) (string, error) {
	header := jwtB64.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now()
	cb, err := json.Marshal(accessClaims{Sub: userID, Iat: now.Unix(), Exp: now.Add(ttl).Unix()})
	if err != nil {
		return "", err
	}
	signing := header + "." + jwtB64.EncodeToString(cb)
	return signing + "." + signJWT(signing, secret), nil
}

// ParseAccessToken validates the signature and expiry and returns the user ID.
func ParseAccessToken(token, secret string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ErrInvalidToken
	}
	signing := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(signJWT(signing, secret)), []byte(parts[2])) {
		return "", ErrInvalidToken
	}
	cb, err := jwtB64.DecodeString(parts[1])
	if err != nil {
		return "", ErrInvalidToken
	}
	var claims accessClaims
	if err := json.Unmarshal(cb, &claims); err != nil {
		return "", ErrInvalidToken
	}
	if claims.Sub == "" || time.Now().Unix() >= claims.Exp {
		return "", ErrInvalidToken
	}
	return claims.Sub, nil
}

func signJWT(msg, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	return jwtB64.EncodeToString(mac.Sum(nil))
}

// GenerateRefreshToken returns an opaque token (given to the client) and its hash
// (stored server-side).
func GenerateRefreshToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	token = jwtB64.EncodeToString(b)
	return token, HashRefreshToken(token), nil
}

// HashRefreshToken is the SHA-256 (hex) of an opaque refresh token.
func HashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
