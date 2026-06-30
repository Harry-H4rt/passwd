module github.com/passwd-app/server

go 1.22

// Deps are pinned to versions compatible with Go 1.22 (latest x/crypto needs Go
// >=1.25). JWT is implemented with the std lib (no JWT dependency). See
// docs/ROADMAP.md. x/crypto provides argon2id/pbkdf2/hkdf for the reference impl
// and the server-side password verifier.
//
// go-webauthn is pinned to v0.11.1, the newest release whose go directive is still
// 1.22 (v0.12+ require Go >=1.23, v0.17+ require >=1.25). Bump only alongside the
// project's Go version. It is pure Go (no cgo), matching modernc.org/sqlite.

require (
	github.com/go-webauthn/webauthn v0.11.1
	github.com/lib/pq v1.12.3
	golang.org/x/crypto v0.31.0
	modernc.org/sqlite v1.34.4
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/go-webauthn/x v0.1.12 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/google/go-tpm v0.9.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sys v0.28.0 // indirect
	modernc.org/gc/v3 v3.0.0-20240107210532-573471604cb6 // indirect
	modernc.org/libc v1.55.3 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
	modernc.org/strutil v1.2.0 // indirect
	modernc.org/token v1.1.0 // indirect
)
