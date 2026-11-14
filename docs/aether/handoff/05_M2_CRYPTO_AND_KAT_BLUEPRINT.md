# Handoff Report — `explorer_m2_1` (`protocol/aether/crypto.go` & `crypto_test.go` Blueprint)

**Core Summary**: Complete read-only symbol-collision audit, Go `1.25.5`/`1.27.3` + `golang.org/x/crypto v0.54.0` + `golang.org/x/sys v0.47.0` API analysis, byte-exact implementation blueprint for `protocol/aether/crypto.go` and `protocol/aether/crypto_test.go`, and **29 precomputed independent reference KAT vectors** (computed via PHC `libargon2.so.1`, `libsodium.so.23`, OpenSSL `libcrypto.so.3`, and Python RFC 5869/7748, cross-verified 100% against Go, with all `/tmp` scripts removed and repo clean).

---

## 1. Observation

### 1.1 Existing Package-Level Symbols in `package aether` (`protocol/aether/*.go`)

All 8 files currently in `protocol/aether/` belong to `package aether`. Because `cipher.go`, `frame.go`, `noise.go`, and `probe_guard.go` remain in `protocol/aether/` until Milestone M4 deletes them (and `conn.go` remains until M3 rewrites it, while `inbound.go`/`outbound.go` remain on M1 shims until M4), `crypto.go` **must coexist** with every symbol below without redeclaration AND **must not reference** any symbol from `{cipher,frame,noise,probe_guard}.go` so M4 can delete those files with zero edits to `crypto.go`:

| File | Existing Package-Level Declarations (Line Numbers Verified via `view_file`) | Lifecycle |
|---|---|---|
| `protocol/aether/cipher.go` | **Consts**: `SaltSize = 32` (`:16`), `KeySize = 32` (`:17`), `TagSize = chacha20poly1305.Overhead` (`:18`), `NonceSize = chacha20poly1305.NonceSize` (`:19`), `HKDFInfoString = "AetherFlow-v1-Session-Subkey"` (`:20`)<br>**Vars**: `ErrInvalidTag` (`:24`), `ErrShortBuffer` (`:25`), `ErrReplayDetected` (`:26`), `ErrInvalidHeader` (`:27`)<br>**Types**: `CipherSession` (`:30`)<br>**Funcs**: `GenerateSalt()` (`:42`), `KeyFromPassword(password string)` (`:48`), `NewCipherSession(...)` (`:52`), **unexported** `encodeNonce(seq uint64, dst []byte)` (`:117`) | Deleted in M4 |
| `protocol/aether/conn.go` | **Consts**: `MaxChunkSize` (`:14`), `FrameData` (`:16`), `FramePing` (`:17`), `FramePong` (`:18`)<br>**Types**: `Conn` (`:21`)<br>**Funcs**: `NewClientConn` (`:99`), `NewServerConn` (`:156`) | Rewritten in M3 |
| `protocol/aether/frame.go` | **Consts**: `AtypIPv4` (`:12`), `AtypDomain` (`:13`), `AtypIPv6` (`:14`)<br>**Types**: `Header` (`:17`)<br>**Funcs**: `EncodeAddress` (`:26`), `DecodeAddress` (`:63`), `PackHeader` (`:104`), `UnpackHeader` (`:130`) | Deleted in M4 |
| `protocol/aether/noise.go` | **Consts**: `MinNoisePadding` (`:9`), `MaxNoisePadding` (`:10`)<br>**Funcs**: `GenerateRandomNoise` (`:13`), `MaskLength` (`:34`), `UnmaskLength` (`:41`) | Deleted in M4 |
| `protocol/aether/probe_guard.go` | **Funcs**: `HandleProbe` (`:8`) | Deleted in M4 |
| `protocol/aether/replay.go` | **Consts**: `MaxTimeDiffMs` (`:9`), `LRUWindowSize` (`:10`)<br>**Types**: `ReplayFilter` (`:13`)<br>**Funcs**: `NewReplayFilter` (`:20`)<br>*(Note: `inbound.go:34,55,70` and `conn.go:156` still reference `ReplayFilter`, `NewReplayFilter`, and `MaxTimeDiffMs` until M3/M4!)* | Rewritten in M2 (keep v1 shim types until M4) |
| `protocol/aether/inbound.go` | **Funcs**: `RegisterInbound` (`:22`), `NewInbound` (`:38`, calls `option.ResolveSecret` at `:39,:44` and `KeyFromPassword` at `:52`)<br>**Types**: `Inbound` (`:28`) | Shimmed in M1 -> Rewritten in M4 |
| `protocol/aether/outbound.go` | **Funcs**: `RegisterOutbound` (`:23`), `NewOutbound` (`:56`, calls `option.ResolveSecret` at `:57`, checks `"unsupported aether cipher: "` at `:64`, calls `KeyFromPassword` at `:76`)<br>**Types**: `Outbound` (`:35`), `aetherDialer` (`:46`) | Shimmed in M1 -> Rewritten in M4 |

### 1.2 M1 Options & CLI Contracts Already Committed on `dev/aether-v2`
- `option/aether.go:8-49`:
  - `option.AetherUser` (`Name`, `Password`, `Key`)
  - `option.ResolveSecret(password, key string) (string, error)` (`:41-49`): returns `E.New("conflicting password and key")` when `password != "" && key != "" && password != key`; returns `""` when both are empty.
- `cmd/sing-box/cmd_generate_aether_test.go:199-201`:
  - Asserts `require.ErrorContains(t, err, "unsupported aether cipher")` for invalid `cipher` values (e.g. `"aes-128-gcm"`). `SelectCipherSuite` in `crypto.go` MUST preserve the `"unsupported aether cipher"` error substring so M4 can replace `outbound.go:61-65`'s inline switch directly with `SelectCipherSuite(options.Cipher)`.

### 1.3 Workspace Go Toolchain & Crypto/CPU API Inspection (`go.mod` & `/usr/local/go/src/...`)
- **Module & Toolchain** (`go.mod:3,71,76`, `go env`):
  - `go 1.25.5` in `go.mod` (VM compiler: `go1.27.3 linux/amd64`).
  - `golang.org/x/crypto v0.54.0`, `golang.org/x/sys v0.47.0`, `github.com/stretchr/testify v1.12.0`, `github.com/sagernet/sing v0.9.7-0.20261023115459-5dc452e537bf` (`E "github.com/sagernet/sing/common/exceptions"`).
- **`crypto/hkdf` (Go stdlib) vs `golang.org/x/crypto/hkdf`** (`/usr/local/go/src/crypto/hkdf/hkdf.go:25-70`):
  - Stdlib `crypto/hkdf` provides:
    - `hkdf.Key(sha256.New, secret, salt []byte, info string, keyLength int) ([]byte, error)` — full RFC 5869 `HKDF-Extract(salt, secret)` + `HKDF-Expand(prk, info, keyLength)`, accepting `info` directly as `string` (zero `[]byte(info)` allocation).
    - `hkdf.Expand(sha256.New, pseudorandomKey []byte, info string, keyLength int) ([]byte, error)` — pure RFC 5869 § 3.3 `HKDF-Expand` (skips `Extract`).
  - Empirically verified identical output to `golang.org/x/crypto/hkdf` and Python RFC 5869.
- **`crypto/ecdh` Subtleties in Go 1.26+** (`/usr/local/go/src/crypto/ecdh/x25519.go:37-91`):
  1. `ecdh.X25519().GenerateKey(rand io.Reader)` ignores custom `io.Reader` in Go 1.26+ (`rand.CustomReader(r)` uses OS CSPRNG unless `GODEBUG=cryptocustomrand=1` or `cryptotest.SetGlobalRandom`). Separating pure `MaskEPK(uPSK, salt, rawEPK [32]byte) [32]byte` from `GenerateMaskedEPK(uPSK, salt [32]byte)` allows deterministic KAT testing with `ecdh.X25519().NewPrivateKey(seed)`.
  2. `ecdh.X25519().NewPrivateKey(key)` and `ecdh.X25519().NewPublicKey(key)` check **only** `len(key) == 32` (`x25519.go:53,71`); they do **not** reject `[32]byte{}` or non-zero low-order Curve25519 points (`ecdh` only checks `isZero(out)` inside `local.ECDH(remote)` at `x25519.go:86`).
- **`encoding/base64` Subtleties** (`/usr/local/go/src/encoding/base64/base64.go:107-128, 421-428`):
  1. Non-strict `base64.*Encoding.DecodeString` ignores non-zero trailing padding bits in the 43rd character of a 32-byte Base64 string (e.g. `"Q="` and `"R="` decode to identical 32 bytes!), creating a key-mutation collision hazard.
  2. Even `.Strict()` ignores embedded `\r` and `\n` (`base64.go:111-112`).
  3. Enforcing `(len(s) == 43 || len(s) == 44) && !strings.ContainsAny(s, "\r\n")` with `.Strict()` across `StdEncoding`, `RawStdEncoding`, `URLEncoding`, and `RawURLEncoding` accepts **100% of canonical 32B Base64 strings** while rejecting all malleable mutations.
- **`golang.org/x/sys/cpu` & Go Stdlib AES-GCM Assembly Support** (`/usr/local/go/src/crypto/tls/cipher_suites.go:361-369` & `/usr/local/go/src/crypto/internal/fips140/aes/gcm/gcm_asm.go:5,34-43`):
  - Go's hardware-accelerated `aes/gcm` assembly is built **only** on `amd64`, `arm64`, `s390x`, and `ppc64`/`ppc64le` (`!purego`). On `GOARCH=386` running on an x86_64 CPU, `cpu.X86.HasAES` can be true even though Go's 32-bit `386` binary uses software AES-GCM! Switching on `runtime.GOARCH` matches `crypto/tls.hasAESGCMHardwareSupport` exactly:
    - `"amd64"`: `cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ && cpu.X86.HasSSE41 && cpu.X86.HasSSSE3`
    - `"arm64"`: `cpu.ARM64.HasAES && cpu.ARM64.HasPMULL`
    - `"s390x"`: `cpu.S390X.HasAES && cpu.S390X.HasAESCTR && (cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)`
    - `"ppc64", "ppc64le"`: `true`
    - `default`: `false`
- **`golang.org/x/crypto/argon2` & `chacha20` & `chacha20poly1305`**:
  - `argon2.IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte` (`time=3, memory=64*1024, threads=4, keyLen=32`).
  - `chacha20.NewUnauthenticatedCipher(key32, nonce12)` initializes RFC 8439 ChaCha20 with initial 32-bit block counter `0`.
  - `chacha20poly1305.New(key32)` (`12B` nonce, `16B` Poly1305 tag).

---

## 2. Logic Chain

1. **Zero Symbol Collisions + Zero M4 Deletion Coupling** (from Observation § 1.1):
   - Because `cipher.go` already defines `SaltSize`, `KeySize`, `TagSize`, `NonceSize`, `HKDFInfoString`, `ErrInvalidTag`, `ErrShortBuffer`, `ErrReplayDetected`, `ErrInvalidHeader`, `CipherSession`, `GenerateSalt`, `KeyFromPassword`, `NewCipherSession`, and lowercase `encodeNonce`, `crypto.go` defines distinct v2 constants (`PSKSize`, `HandshakeSaltSize`, `EPKSize`, `EIHSize`, `UserIDSize`, `AEADNonceSize`, `AEADTagSize`, `EPKMaskMaterialSize`, `CipherAES256GCM`, `CipherChaCha20Poly1305`), distinct sentinel errors (`ErrEmptySecret`, `ErrAllZeroKey`, `ErrWeakPassword`, `ErrInvalidX25519Key`, `ErrUnsupportedCipherSuite`, `ErrEmptyUserTable`, `ErrDuplicateUserName`, `ErrDuplicateUserKey`), `GenerateRandomSalt()`, and exported `EncodeNonce(seq uint64, dst *[12]byte)`.
   - Thus `crypto.go` compiles alongside `cipher.go` in M2/M3 and requires zero edits when `cipher.go` is deleted in M4.

2. **Non-Malleable Base64 Fast-Path & Unambiguous Colon Credential Splitting** (from Observation § 1.3 & `PROJECT.md` § 3):
   - Any canonical Base64 encoding of 32 bytes in `{Std, RawStd, URL, RawURL}` has length `44` (padded) or `43` (unpadded), zero `\r`/`\n`, and zero trailing padding bits (`(byte[31] & 0x0f) << 2` always ends in `00`). Using `.Strict()` + length/newline guards in `decodeBase64Key32` guarantees every valid 32B Base64 key hits the `<1 µs` fast-path (and rejects `[32]byte{}` immediately with `ErrAllZeroKey`), while any mutated 43/44-char string is never silently aliased to the original key.
   - In `ParseOutboundCredentials(secret)`:
     - Splitting on first `:` via `strings.Cut(secret, ":")`:
       1. If either half is a canonical 32B Base64 string (`decodeBase64Key32` returns `true`, including all-zero 32B Base64), the operator unambiguously intended `<server_secret>:<user_secret>`: derive both via `DerivePSK` and propagate any error (such as `<valid_b64>:short` -> `ErrWeakPassword` or `<valid_b64>:<all_zero_b64>` -> `ErrAllZeroKey`) instead of silently treating a malformed EIH config as a single 50+-char passphrase.
       2. Else if `len(left) >= 16 && len(right) >= 16`: both halves are valid passphrases -> derive `iPSK` and `uPSK` via `DerivePSK`.
       3. Otherwise (e.g. `"my:passphrase-with-colon-123"` where `len("my") < 16`, or `"short:short"`): treat `secret` as a single credential and pass to `DerivePSK(secret)`.

3. **Startup Rejection of All Curve25519 Low-Order Public Keys** (from Observation § 1.3):
   - On Curve25519 (`#E = 8*l`, `#E' = 4*l'` with primes `l, l' > 2^252`), every clamped X25519 scalar `s = 8*m` (`2^251 <= m < 2^252`) satisfies `gcd(m, l) = gcd(m, l') = 1`. Therefore `[s]P == 0` for one clamped scalar `s` **if and only if** `P` is a low-order point (`[8]P = O`), which holds for **all** clamped scalars. Performing a single `probePriv.ECDH(pub)` inside `ParseX25519PublicKey` rejects all 12 canonical/non-canonical low-order points at node startup (`NewOutbound`), while `ComputeECDH` rejects low-order peer ephemeral keys at connection time.

4. **Single-Scalar-Mult 0-RTT PFS & Exact `HKDF-Key` vs `HKDF-Expand` Key Schedule** (from `PROJECT.md` § 3 lines 187–205):
   - Computing `ssStatic, err := ComputeECDH(...)` once and passing `ssStatic[:]` (`nil` when no static key is configured) into both `DeriveClientInitAEAD` and `DeriveSessionKeys` cuts server/client static ECDH CPU cost in half.
   - `masterSecret` uses `hkdf.Key(sha256.New, ikmSession, dualSalt[:], "AetherFlow-v2-Session", 32)` (Extract + Expand), whereas the 5 subkeys (`Resp`, `C2S-Header`, `C2S-Payload`, `S2C-Header`, `S2C-Payload`) use `hkdf.Expand(sha256.New, masterSecret[:], label, 32)` (Expand-only, taking `PRK = masterSecret`), matching `PROJECT.md:199-205` byte-for-byte.

---

## 3. Caveats

1. **Sibling M2 File `protocol/aether/replay.go` Coexistence Note**:
   - While not part of `crypto.go`, the M2 Worker implementing `replay.go` alongside `crypto.go` MUST retain the legacy `ReplayFilter`, `NewReplayFilter`, and `MaxTimeDiffMs` symbols (or thin shims) in `replay.go` during M2 because `protocol/aether/inbound.go:34,55,70` and `protocol/aether/conn.go:156` still reference them until M3/M4.
2. **Inbound Credential Validation Helper**:
   - In `inbound.go` (M4), Inbound supports 3 modes (`PROJECT.md:176-186`): (a) Single-user (`len(Users) == 0`, `Password`/`Key` non-empty), (b) Multi-user EIH (`len(Users) > 0`, `Password`/`Key` non-empty -> `iPSK` + `UserTable`), and (c) Multi-user `Users`-only (`len(Users) > 0`, `Password`/`Key` empty -> `UserTable` only). `NewUserTable` in `crypto.go` supports both (b) and (c) via `O(1)` `Lookup(userID)` / `LookupEIH(...)` and deterministic slice `Users()`.

---

## 4. Conclusion — Complete Blueprint for `protocol/aether/crypto.go` & `protocol/aether/crypto_test.go`

### 4.1 Complete Proposed Implementation Blueprint: `protocol/aether/crypto.go`

```go
package aether

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/cpu"
)

const (
	PSKSize             = 32
	HandshakeSaltSize   = 32
	EPKSize             = 32
	EIHSize             = 16
	UserIDSize          = 16
	AEADNonceSize       = 12
	AEADTagSize         = 16
	EPKMaskMaterialSize = 44

	MinPassphraseLength = 16

	Argon2Time      uint32 = 3
	Argon2MemoryKiB uint32 = 64 * 1024
	Argon2Threads   uint8  = 4

	CipherAES256GCM        uint8 = 0x01
	CipherChaCha20Poly1305 uint8 = 0x02

	CipherNameAuto             = "auto"
	CipherNameAES256GCM        = "aes-256-gcm"
	CipherNameChaCha20Poly1305 = "chacha20-poly1305"

	KDFSaltArgon2id    = "AetherFlow-v2-KDF"
	HKDFInfoEPKMask    = "AetherFlow-v2-EPK-Mask"
	UserIDDomainPrefix = "AetherFlow-v2-UID"
	HKDFInfoEIH        = "AetherFlow-v2-EIH"
	HKDFInfoClientInit = "AetherFlow-v2-Client-Init"
	HKDFInfoSession    = "AetherFlow-v2-Session"
	HKDFInfoResp       = "AetherFlow-v2-Resp"
	HKDFInfoC2SHeader  = "AetherFlow-v2-C2S-Header"
	HKDFInfoC2SPayload = "AetherFlow-v2-C2S-Payload"
	HKDFInfoS2CHeader  = "AetherFlow-v2-S2C-Header"
	HKDFInfoS2CPayload = "AetherFlow-v2-S2C-Payload"
)

var (
	ErrEmptySecret            = errors.New("aether: empty password/key")
	ErrAllZeroKey             = errors.New("aether: all-zero key rejected")
	ErrWeakPassword           = errors.New("aether: weak password: must be a 32-byte Base64 key or passphrase >= 16 characters")
	ErrInvalidX25519Key       = errors.New("aether: invalid X25519 key")
	ErrInvalidSharedSecret    = errors.New("aether: invalid ECDH shared secret")
	ErrUnsupportedCipherSuite = errors.New("unsupported aether cipher")
	ErrEmptyUserTable         = errors.New("aether: empty users list")
	ErrDuplicateUserName      = errors.New("aether: duplicate user name")
	ErrDuplicateUserKey       = errors.New("aether: duplicate user password/key")
)

var (
	strictStdBase64    = base64.StdEncoding.Strict()
	strictRawStdBase64 = base64.RawStdEncoding.Strict()
	strictURLBase64    = base64.URLEncoding.Strict()
	strictRawURLBase64 = base64.RawURLEncoding.Strict()

	x25519LowOrderProbeKey = mustNewProbePrivateKey()
)

func mustNewProbePrivateKey() *ecdh.PrivateKey {
	var scalar [32]byte
	scalar[0] = 1
	priv, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		panic(err)
	}
	return priv
}

func isAllZero32(b [32]byte) bool {
	var zero [32]byte
	return subtle.ConstantTimeCompare(b[:], zero[:]) == 1
}

// decodeBase64Key32 attempts strict 32-byte Base64 decoding across StdEncoding,
// RawStdEncoding, URLEncoding, and RawURLEncoding without CR/LF malleability.
func decodeBase64Key32(s string) ([32]byte, bool) {
	var out [32]byte
	if (len(s) != 43 && len(s) != 44) || strings.ContainsAny(s, "\r\n") {
		return out, false
	}
	var encodings []*base64.Encoding
	if len(s) == 44 {
		encodings = []*base64.Encoding{strictStdBase64, strictURLBase64}
	} else {
		encodings = []*base64.Encoding{strictRawStdBase64, strictRawURLBase64}
	}
	for _, enc := range encodings {
		decoded, err := enc.DecodeString(s)
		if err == nil && len(decoded) == 32 {
			copy(out[:], decoded)
			return out, true
		}
	}
	return out, false
}

// GenerateRandomSalt reads 32 cryptographically random bytes from crypto/rand.
func GenerateRandomSalt() ([HandshakeSaltSize]byte, error) {
	var salt [HandshakeSaltSize]byte
	_, err := io.ReadFull(rand.Reader, salt[:])
	return salt, err
}

// DerivePSK derives a 32-byte pre-shared key via the 32-byte Base64 fast-path
// or Argon2id(password, "AetherFlow-v2-KDF", t=3, m=64MiB, p=4, keyLen=32).
func DerivePSK(secret string) ([PSKSize]byte, error) {
	var zero [PSKSize]byte
	if len(secret) == 0 {
		return zero, ErrEmptySecret
	}
	if decoded, ok := decodeBase64Key32(secret); ok {
		if isAllZero32(decoded) {
			return zero, ErrAllZeroKey
		}
		return decoded, nil
	}
	if len(secret) < MinPassphraseLength {
		return zero, ErrWeakPassword
	}
	derived := argon2.IDKey(
		[]byte(secret),
		[]byte(KDFSaltArgon2id),
		Argon2Time,
		Argon2MemoryKiB,
		Argon2Threads,
		PSKSize,
	)
	var out [PSKSize]byte
	copy(out[:], derived)
	if isAllZero32(out) {
		return zero, ErrAllZeroKey
	}
	return out, nil
}

// ParseOutboundCredentials parses an outbound secret supporting either single-secret
// "<user_secret>" or EIH multi-user "<server_secret>:<user_secret>" when both sides
// are valid secrets (or when either side is a canonical 32-byte Base64 key).
func ParseOutboundCredentials(secret string) (hasServerPSK bool, iPSK [PSKSize]byte, uPSK [PSKSize]byte, err error) {
	if len(secret) == 0 {
		return false, iPSK, uPSK, ErrEmptySecret
	}
	if left, right, hasColon := strings.Cut(secret, ":"); hasColon {
		_, leftIsB64 := decodeBase64Key32(left)
		_, rightIsB64 := decodeBase64Key32(right)
		if leftIsB64 || rightIsB64 || (len(left) >= MinPassphraseLength && len(right) >= MinPassphraseLength) {
			iPSK, err = DerivePSK(left)
			if err != nil {
				return false, [PSKSize]byte{}, [PSKSize]byte{}, fmt.Errorf("server credential: %w", err)
			}
			uPSK, err = DerivePSK(right)
			if err != nil {
				return false, [PSKSize]byte{}, [PSKSize]byte{}, fmt.Errorf("user credential: %w", err)
			}
			return true, iPSK, uPSK, nil
		}
	}
	uPSK, err = DerivePSK(secret)
	if err != nil {
		return false, [PSKSize]byte{}, [PSKSize]byte{}, err
	}
	return false, [PSKSize]byte{}, uPSK, nil
}

// DeriveUserID computes SHA256("AetherFlow-v2-UID" || uPSK[:])[0:16].
func DeriveUserID(uPSK [PSKSize]byte) [UserIDSize]byte {
	var buf [len(UserIDDomainPrefix) + PSKSize]byte
	copy(buf[0:len(UserIDDomainPrefix)], UserIDDomainPrefix)
	copy(buf[len(UserIDDomainPrefix):], uPSK[:])
	sum := sha256.Sum256(buf[:])
	var uid [UserIDSize]byte
	copy(uid[:], sum[:UserIDSize])
	return uid
}

func deriveEIHMask(iPSK, clientSalt [PSKSize]byte) [EIHSize]byte {
	maskSlice, err := hkdf.Key(sha256.New, iPSK[:], clientSalt[:], HKDFInfoEIH, EIHSize)
	if err != nil {
		panic(err) // unreachable for SHA-256 with 32B IKM and 16B output
	}
	var mask [EIHSize]byte
	copy(mask[:], maskSlice)
	return mask
}

// MaskEIH masks userID with HKDF-SHA256(iPSK, clientSalt, "AetherFlow-v2-EIH", 16).
func MaskEIH(iPSK, clientSalt [PSKSize]byte, userID [UserIDSize]byte) [EIHSize]byte {
	mask := deriveEIHMask(iPSK, clientSalt)
	var eih [EIHSize]byte
	for i := range EIHSize {
		eih[i] = userID[i] ^ mask[i]
	}
	return eih
}

// UnmaskEIH recovers userID from EIH using iPSK and clientSalt.
func UnmaskEIH(iPSK, clientSalt [PSKSize]byte, eih [EIHSize]byte) [UserIDSize]byte {
	return MaskEIH(iPSK, clientSalt, eih)
}

// UserRecord holds a validated multi-user entry and its precomputed 16-byte UserID.
type UserRecord struct {
	Name   string
	UPSK   [PSKSize]byte
	UserID [UserIDSize]byte
}

// UserTable provides O(1) UserID/EIH lookup via map[[16]byte]*UserRecord as well as
// deterministic slice iteration for Users-Only mode (when inbound iPSK is empty).
type UserTable struct {
	byID  map[[UserIDSize]byte]*UserRecord
	users []*UserRecord
}

// NewUserTable validates configured users, rejecting empty lists, conflicting
// password/key pairs, weak/all-zero keys, duplicate user names, and duplicate uPSKs/UserIDs.
func NewUserTable(cfgUsers []option.AetherUser) (*UserTable, error) {
	if len(cfgUsers) == 0 {
		return nil, ErrEmptyUserTable
	}
	byID := make(map[[UserIDSize]byte]*UserRecord, len(cfgUsers))
	users := make([]*UserRecord, 0, len(cfgUsers))
	seenNames := make(map[string]struct{}, len(cfgUsers))
	seenUPSK := make(map[[PSKSize]byte]struct{}, len(cfgUsers))

	for i, u := range cfgUsers {
		if _, dupName := seenNames[u.Name]; dupName {
			return nil, fmt.Errorf("%w: %q (index %d)", ErrDuplicateUserName, u.Name, i)
		}
		seenNames[u.Name] = struct{}{}

		secret, err := option.ResolveSecret(u.Password, u.Key)
		if err != nil {
			return nil, fmt.Errorf("user %q (index %d): %w", u.Name, i, err)
		}
		uPSK, err := DerivePSK(secret)
		if err != nil {
			return nil, fmt.Errorf("user %q (index %d): %w", u.Name, i, err)
		}
		if _, dupPSK := seenUPSK[uPSK]; dupPSK {
			return nil, fmt.Errorf("%w: user %q (index %d)", ErrDuplicateUserKey, u.Name, i)
		}
		seenUPSK[uPSK] = struct{}{}

		uid := DeriveUserID(uPSK)
		if _, dupUID := byID[uid]; dupUID {
			return nil, fmt.Errorf("%w: duplicate userID for %q (index %d)", ErrDuplicateUserKey, u.Name, i)
		}
		rec := &UserRecord{
			Name:   u.Name,
			UPSK:   uPSK,
			UserID: uid,
		}
		byID[uid] = rec
		users = append(users, rec)
	}
	return &UserTable{
		byID:  byID,
		users: users,
	}, nil
}

func (t *UserTable) Len() int {
	if t == nil {
		return 0
	}
	return len(t.users)
}

func (t *UserTable) Lookup(userID [UserIDSize]byte) (*UserRecord, bool) {
	if t == nil {
		return nil, false
	}
	rec, ok := t.byID[userID]
	return rec, ok
}

func (t *UserTable) LookupEIH(iPSK, clientSalt [PSKSize]byte, eih [EIHSize]byte) (*UserRecord, bool) {
	if t == nil {
		return nil, false
	}
	uid := UnmaskEIH(iPSK, clientSalt, eih)
	return t.Lookup(uid)
}

func (t *UserTable) Users() []*UserRecord {
	if t == nil {
		return nil
	}
	return t.users
}

// ParseX25519PrivateKey parses a 32-byte Base64 static X25519 private key across all 4 Base64 variants.
func ParseX25519PrivateKey(encoded string) (*ecdh.PrivateKey, error) {
	raw, ok := decodeBase64Key32(encoded)
	if !ok {
		return nil, fmt.Errorf("%w: must be 32-byte Base64", ErrInvalidX25519Key)
	}
	if isAllZero32(raw) {
		return nil, fmt.Errorf("%w: all-zero key rejected", ErrInvalidX25519Key)
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidX25519Key, err)
	}
	return priv, nil
}

// ParseX25519PublicKey parses a 32-byte Base64 static X25519 public key across all 4 Base64 variants,
// rejecting all-zero and all Curve25519 small-order points at startup.
func ParseX25519PublicKey(encoded string) (*ecdh.PublicKey, error) {
	raw, ok := decodeBase64Key32(encoded)
	if !ok {
		return nil, fmt.Errorf("%w: must be 32-byte Base64", ErrInvalidX25519Key)
	}
	if isAllZero32(raw) {
		return nil, fmt.Errorf("%w: all-zero key rejected", ErrInvalidX25519Key)
	}
	pub, err := ecdh.X25519().NewPublicKey(raw[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidX25519Key, err)
	}
	if _, err := x25519LowOrderProbeKey.ECDH(pub); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidX25519Key, err)
	}
	return pub, nil
}

// ComputeECDH performs X25519 scalar multiplication, rejecting nil keys and low-order points.
func ComputeECDH(localPriv *ecdh.PrivateKey, remotePub *ecdh.PublicKey) ([32]byte, error) {
	var out [32]byte
	if localPriv == nil || remotePub == nil {
		return out, ErrInvalidX25519Key
	}
	ss, err := localPriv.ECDH(remotePub)
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrInvalidSharedSecret, err)
	}
	copy(out[:], ss)
	if isAllZero32(out) {
		return [32]byte{}, ErrInvalidSharedSecret
	}
	return out, nil
}

// MaskEPK XOR-masks a 32-byte X25519 public key with a ChaCha20 stream derived from
// HKDF-SHA256(uPSK, salt, "AetherFlow-v2-EPK-Mask", 44).
func MaskEPK(uPSK, salt, rawEPK [32]byte) [EPKSize]byte {
	hkdfOut, err := hkdf.Key(sha256.New, uPSK[:], salt[:], HKDFInfoEPKMask, EPKMaskMaterialSize)
	if err != nil {
		panic(err)
	}
	stream, err := chacha20.NewUnauthenticatedCipher(hkdfOut[0:32], hkdfOut[32:44])
	if err != nil {
		panic(err)
	}
	var dst [EPKSize]byte
	stream.XORKeyStream(dst[:], rawEPK[:])
	return dst
}

// GenerateMaskedEPK generates a fresh ephemeral X25519 keypair and returns its private key
// and ChaCha20 stream-masked 32-byte public key.
func GenerateMaskedEPK(uPSK, salt [32]byte) (*ecdh.PrivateKey, [EPKSize]byte, error) {
	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, [EPKSize]byte{}, err
	}
	var rawEPK [EPKSize]byte
	copy(rawEPK[:], ephPriv.PublicKey().Bytes())
	return ephPriv, MaskEPK(uPSK, salt, rawEPK), nil
}

// UnmaskEPK unmasks a 32-byte ChaCha20-masked X25519 public key and parses it into *ecdh.PublicKey.
func UnmaskEPK(uPSK, salt, maskedEPK [32]byte) (*ecdh.PublicKey, error) {
	rawEPK := MaskEPK(uPSK, salt, maskedEPK)
	if isAllZero32(rawEPK) {
		return nil, fmt.Errorf("%w: all-zero ephemeral public key", ErrInvalidX25519Key)
	}
	pub, err := ecdh.X25519().NewPublicKey(rawEPK[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidX25519Key, err)
	}
	return pub, nil
}

// DeriveClientInitKey derives the 32-byte handshake initKey via HKDF-SHA256("AetherFlow-v2-Client-Init").
// staticSharedSecret must be empty/nil (no static key) or 32 non-zero bytes (0-RTT PFS mode).
func DeriveClientInitKey(uPSK, clientSalt [32]byte, staticSharedSecret []byte) ([32]byte, error) {
	var out [32]byte
	var ikmBuf [64]byte
	copy(ikmBuf[0:32], uPSK[:])
	ikm := ikmBuf[0:32]
	if len(staticSharedSecret) > 0 {
		if len(staticSharedSecret) != 32 {
			return out, ErrInvalidSharedSecret
		}
		var ssArr [32]byte
		copy(ssArr[:], staticSharedSecret)
		if isAllZero32(ssArr) {
			return out, ErrInvalidSharedSecret
		}
		copy(ikmBuf[32:64], staticSharedSecret)
		ikm = ikmBuf[0:64]
	}
	derived, err := hkdf.Key(sha256.New, ikm, clientSalt[:], HKDFInfoClientInit, 32)
	if err != nil {
		return out, err
	}
	copy(out[:], derived)
	return out, nil
}

// DeriveClientInitAEAD derives initKey and initializes its ChaCha20-Poly1305 AEAD.
func DeriveClientInitAEAD(uPSK, clientSalt [32]byte, staticSharedSecret []byte) (cipher.AEAD, error) {
	initKey, err := DeriveClientInitKey(uPSK, clientSalt, staticSharedSecret)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.New(initKey[:])
}

// SessionKeys holds the dual-salt ratcheted masterSecret and all 5 domain-separated 32B subkeys.
type SessionKeys struct {
	MasterSecret  [32]byte
	RespKey       [32]byte
	C2SHeaderKey  [32]byte
	C2SPayloadKey [32]byte
	S2CHeaderKey  [32]byte
	S2CPayloadKey [32]byte
}

func expandSubkey32(prk [32]byte, label string) [32]byte {
	sub, err := hkdf.Expand(sha256.New, prk[:], label, 32)
	if err != nil {
		panic(err)
	}
	var out [32]byte
	copy(out[:], sub)
	return out
}

// DeriveSessionKeys ratchets uPSK + ephSharedSecret [+ staticSharedSecret] with
// dualSalt = clientSalt || serverSalt via HKDF-SHA256("AetherFlow-v2-Session") and expands
// the 5 directional/response 32-byte subkeys via HKDF-Expand-SHA256.
func DeriveSessionKeys(
	uPSK [32]byte,
	ephSharedSecret [32]byte,
	staticSharedSecret []byte,
	clientSalt, serverSalt [32]byte,
) (SessionKeys, error) {
	var keys SessionKeys
	if isAllZero32(ephSharedSecret) {
		return keys, ErrInvalidSharedSecret
	}
	var ikmBuf [96]byte
	copy(ikmBuf[0:32], uPSK[:])
	copy(ikmBuf[32:64], ephSharedSecret[:])
	ikm := ikmBuf[0:64]
	if len(staticSharedSecret) > 0 {
		if len(staticSharedSecret) != 32 {
			return keys, ErrInvalidSharedSecret
		}
		var ssArr [32]byte
		copy(ssArr[:], staticSharedSecret)
		if isAllZero32(ssArr) {
			return keys, ErrInvalidSharedSecret
		}
		copy(ikmBuf[64:96], staticSharedSecret)
		ikm = ikmBuf[0:96]
	}

	var dualSalt [64]byte
	copy(dualSalt[0:32], clientSalt[:])
	copy(dualSalt[32:64], serverSalt[:])

	ms, err := hkdf.Key(sha256.New, ikm, dualSalt[:], HKDFInfoSession, 32)
	if err != nil {
		return keys, err
	}
	copy(keys.MasterSecret[:], ms)
	keys.RespKey = expandSubkey32(keys.MasterSecret, HKDFInfoResp)
	keys.C2SHeaderKey = expandSubkey32(keys.MasterSecret, HKDFInfoC2SHeader)
	keys.C2SPayloadKey = expandSubkey32(keys.MasterSecret, HKDFInfoC2SPayload)
	keys.S2CHeaderKey = expandSubkey32(keys.MasterSecret, HKDFInfoS2CHeader)
	keys.S2CPayloadKey = expandSubkey32(keys.MasterSecret, HKDFInfoS2CPayload)
	return keys, nil
}

// NewRespAEAD constructs the ChaCha20-Poly1305 AEAD for EncryptedRespHeader.
func NewRespAEAD(respKey [32]byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(respKey[:])
}

// EncodeNonce encodes seq as a 96-bit TLS 1.3-style Big-Endian nonce:
// dst[0..3] = 0, binary.BigEndian.PutUint64(dst[4:12], seq).
func EncodeNonce(seq uint64, dst *[AEADNonceSize]byte) {
	dst[0] = 0
	dst[1] = 0
	dst[2] = 0
	dst[3] = 0
	binary.BigEndian.PutUint64(dst[4:12], seq)
}

// HasAESGCMHardware reports whether the current CPU and GOARCH have hardware-accelerated AES-GCM.
func HasAESGCMHardware() bool {
	switch runtime.GOARCH {
	case "amd64":
		return cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ && cpu.X86.HasSSE41 && cpu.X86.HasSSSE3
	case "arm64":
		return cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
	case "s390x":
		return cpu.S390X.HasAES && cpu.S390X.HasAESCTR && (cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)
	case "ppc64", "ppc64le":
		return true
	default:
		return false
	}
}

func selectCipherSuiteWithHardware(cipherOpt string, hasAESGCM bool) (uint8, error) {
	switch cipherOpt {
	case "", CipherNameAuto:
		if hasAESGCM {
			return CipherAES256GCM, nil
		}
		return CipherChaCha20Poly1305, nil
	case CipherNameAES256GCM:
		return CipherAES256GCM, nil
	case CipherNameChaCha20Poly1305:
		return CipherChaCha20Poly1305, nil
	default:
		return 0, E.New("unsupported aether cipher: ", cipherOpt)
	}
}

// SelectCipherSuite resolves outbound cipher option ("", "auto", "aes-256-gcm", "chacha20-poly1305").
func SelectCipherSuite(cipherOpt string) (uint8, error) {
	return selectCipherSuiteWithHardware(cipherOpt, HasAESGCMHardware())
}

// IsValidCipherSuite reports whether suite is a supported wire CipherSuite byte.
func IsValidCipherSuite(suite uint8) bool {
	return suite == CipherAES256GCM || suite == CipherChaCha20Poly1305
}

// NewDataAEAD constructs the negotiated data-plane AEAD (AES-256-GCM 0x01 or ChaCha20-Poly1305 0x02).
func NewDataAEAD(suite uint8, key [32]byte) (cipher.AEAD, error) {
	switch suite {
	case CipherAES256GCM:
		block, err := aes.NewCipher(key[:])
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case CipherChaCha20Poly1305:
		return chacha20poly1305.New(key[:])
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedCipherSuite, suite)
	}
}
```

### 4.2 Precomputed Independent Reference KAT Vectors (29 Vectors — Dual-Verified)

All 29 vectors below were independently computed via PHC `libargon2.so.1`, `libsodium.so.23`, OpenSSL `libcrypto.so.3`, and Python 3.11 RFC 5869/7748, and verified byte-for-byte against Go `1.27.3`:

| # | Primitive / Step | Inputs | Expected Exact Hex / Base64 Output |
|---|---|---|---|
| 1 | `DerivePSK` Argon2id (`16`-char boundary) | `secret = "AetherV2-TestKey"` (`t=3, m=65536, p=4`, salt `"AetherFlow-v2-KDF"`) | `eeb853fabf4168e7bf4c37b42c9f0e95b7b3abe6a3174f1ed9993af8739d476f` |
| 2 | `DerivePSK` Argon2id (`24`-char passphrase) | `secret = "DedicatedLine-Secret-001"` | `053d012dd9c7d2b906cf72d5e6649af6daede7c0d82fe616a38f4a7d99253d4c` |
| 3 | `DerivePSK` Base64 `StdEncoding` (`+`, `/`, `=`) | `"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd+/8="` | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1dfbff` |
| 4 | `DerivePSK` Base64 `RawStdEncoding` (43 chars) | `"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd+/8"` | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1dfbff` |
| 5 | `DerivePSK` Base64 `URLEncoding` (`-`, `_`, `=`) | `"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd-_8="` | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1dfbff` |
| 6 | `DerivePSK` Base64 `RawURLEncoding` (43 chars) | `"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd-_8"` | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1dfbff` |
| 7 | `iPSK` (`StdEncoding`) | `"EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8="` | `101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f` |
| 8 | `DeriveUserID(uPSK)` | `uPSK = 0001..fbff`, prefix `"AetherFlow-v2-UID"` | `998a38f4e1515394497d30bc75249448` |
| 9 | `deriveEIHMask(iPSK, clientSalt)` | `iPSK = 1011..2e2f`, `clientSalt = a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf` | `6e288f81aa5d91ce92d56ef029fbf6b4` |
| 10 | `MaskEIH(iPSK, clientSalt, userID)` | `userID XOR eihMask` | `f7a2b7754b0cc25adba85e4c5cdf62fc` |
| 11 | Client Ephemeral X25519 `epk_c` | `ek_c = 303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f` | `34e42d4af5ef94a07a3a84201b889d4cd1a743cb27b11b6a10438a8feb8e5847` |
| 12 | `MaskEPK(uPSK, clientSalt, epk_c)` | `"AetherFlow-v2-EPK-Mask"` (44B) + ChaCha20(ic=0) *(note byte 31 = `0xdd`, MSB=1!)* | `e6208fb969ed169629dfb561c13f3c71239d49176a3a1f9008dc0147862189dd` |
| 13 | Server Ephemeral X25519 `epk_s` | `ek_s = 505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f` | `392d174a38b3b1beafaf1fe824870841c5fa531bc6eafdb6402c124664488c1c` |
| 14 | `MaskEPK(uPSK, serverSalt, epk_s)` | `serverSalt = c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf` | `8020e59ea04bc2e69b3337ecca8157743500a65f2b699f792811b1b91d856c4f` |
| 15 | Server Static X25519 Keypair (`sk_s`, `spk_s`) | `sk_s = 7071..8e8f` (`"cHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo8="`) | `spk_s` = `23b7bb8c91ae008711fb12846780bcdf1e065f821bdfec49f57e7c7dcd4c4823` (`"I7e7jJGuAIcR+xKEZ4C83x4GX4Ib3+xJ9X58fc1MSCM="`) |
| 16 | Ephemeral Shared Secret `ss_eph` | `ECDH(ek_c, epk_s) == ECDH(ek_s, epk_c)` | `d800703cfb0fc9422762b8cf9b29c7211cb2ef6abac6a29d2df1de283c1a5a50` |
| 17 | Static 0-RTT Shared Secret `ss_static` | `ECDH(ek_c, spk_s) == ECDH(sk_s, epk_c)` | `436be988cf0004b93d7b4c35403a45d6004b6def411a14c3633af43f27a8263e` |
| 18 | `DeriveClientInitKey` (No Static Key) | `uPSK`, `clientSalt`, `nil` (`"AetherFlow-v2-Client-Init"`) | `5b33be524b9fe4faaddc1ecb4e7f0e1115d58695f065b89e2d2546483ff8ce4d` |
| 19 | `initAEAD` Fixed & Var Header (No Static, 64B AAD) | `FixedPT = 02010100000000006735398000200040` (`n=0`, `AAD = clientSalt\|\|maskedEPK_c`); `VarPT = 0001..0e0f` (`n=1`, `AAD = FixedPT`) | FixedCT: `092e24e7e20a13b2b659db54f390d746922d2cfab66446c3be97eeebbd321bc0`<br>VarCT: `f315719703210366b2520ed62b8e4e7fb29a983b6718604e417a9b8e7a34ec0b` |
| 20 | `DeriveClientInitKey` (With Static `ss_static`) | `uPSK \|\| ss_static`, `clientSalt` | `7726f62a03009bf8ded213d1a33d883c6379dbaa2cd0706fbef18321d378dfa9` |
| 21 | `initAEAD` Fixed & Var Header (With Static + EIH 80B AAD) | `FixedPT` (`n=0`, `AAD = clientSalt\|\|maskedEPK_c\|\|eih`); `VarPT` (`n=1`, `AAD = FixedPT`) | FixedCT: `f068e6150e6940aebc05f8dedbb3b1badf67b13261ec4fa7dc4c1e291c7e25c9`<br>VarCT: `43194279f1b28055e482dd5fa1525b71dce4fdc0cc494dbb3cca7151cabda063` |
| 22 | `DeriveSessionKeys` — Mode A (`static = nil`) | `ikm = uPSK \|\| ss_eph`, `dualSalt = clientSalt \|\| serverSalt` | `MasterSecret`: `53a7cb25b894ffd419534566ef25690b0e805de3584044933d1e1a10c57f047f`<br>`RespKey`: `8fe832c3e4bfc413e045fb63728274d09c4be7c74fe35f8dea634dadb6bcbd2a`<br>`C2SHeaderKey`: `26daf3f0067dba1ccfdc08c0ccfefa93ca2bc66f120b47231e36da28d01d4a2c`<br>`C2SPayloadKey`: `e983abacfcc4ca33b2d4653960272b55bb726d92e3a04380007144c131c50e9a`<br>`S2CHeaderKey`: `8a165fa7db2673adc4f9f347250df2d00555fdf471a3a984c3ac1d8ccd67017c`<br>`S2CPayloadKey`: `0648cd952b50062de4a33c38c3463d4c87b41a2c23d8efe1dca4f5a289b5b4d0` |
| 23 | `DeriveSessionKeys` — Mode B (`static = ss_static`) | `ikm = uPSK \|\| ss_eph \|\| ss_static`, `dualSalt = clientSalt \|\| serverSalt` | `MasterSecret`: `c9f1be6a318b408127f55c097b1ea3e2be3bbe78476a19ddf38654309d4b1da3`<br>`RespKey`: `211d02251c455824e343957d7c22e0f83e116ef20f1a72867af21476c5c7420f`<br>`C2SHeaderKey`: `34882c16081a2f4eeccb3cfe8529a711ab319dddce31677ddb191388a5faf65c`<br>`C2SPayloadKey`: `5a4de848efc45576d045d387dd7a35fede4f43ef96712f214cb55bf3cca25547`<br>`S2CHeaderKey`: `58dd5de42209042a1bbc3d4780216072c8fb57d78fd0b683bc28244f14a332e2`<br>`S2CPayloadKey`: `c6f454f144cd0ad6b898151ca0fb5cfabcd1d226f3e9946a278b24e2d943725d` |
| 24 | `NewRespAEAD` EncryptedRespHeader (`20B`) | `key = RespKey (Mode A)`, `n = 0`, `pt = 02000100`, `AAD = clientSalt\|\|serverSalt\|\|maskedEPK_s` (`96B`) | `4882aaf223bc8333c5a0c6184ca6cd5ec7658a1a` |
| 25 | `EncodeNonce(5, &n)` | `seq = 5` | `000000000000000000000005` |
| 26 | `NewDataAEAD(CipherAES256GCM, C2SHeaderKey_A)` | `nonce = EncodeNonce(5)`, `pt = 0042` (`18B` encrypted length header), `aad = nil` | `c00985665d956f030e74ad4d72804f65923b` |
| 27 | `NewDataAEAD(CipherChaCha20Poly1305, C2SHeaderKey_A)` | `nonce = EncodeNonce(5)`, `pt = 0042` (`18B` encrypted length header), `aad = nil` | `7212bfbad161bce2c38e4d335b5cd7c654aa` |

### 4.3 Complete Test Matrix Blueprint for `protocol/aether/crypto_test.go`

`crypto_test.go` (`package aether`) MUST include the following deterministic, `-race`-clean unit tests (`t.Parallel()`):

1. **`TestKAT_AllPrimitivesReferenceVectors`**:
   - Verifies all 29 reference KAT vectors in Table § 4.2 byte-for-byte (`DerivePSK` Argon2id & 4 Base64 encodings, `DeriveUserID`, `MaskEIH`/`UnmaskEIH`, `MaskEPK`/`UnmaskEPK`, `ParseX25519PrivateKey`/`ParseX25519PublicKey`, `ComputeECDH`, `DeriveClientInitKey`/`DeriveClientInitAEAD` with & without static key, `DeriveSessionKeys` Mode A & Mode B, `NewRespAEAD`, `EncodeNonce`, `NewDataAEAD` AES-256-GCM & ChaCha20-Poly1305 Seal+Open).
2. **`TestDerivePSK_BoundariesAndRejections`**:
   - Empty `""` -> `ErrEmptySecret`.
   - Lengths `1..15` (including `15`-char `"123456789012345"`) -> `ErrWeakPassword`.
   - Exact `16`-char `"AetherV2-TestKey"` -> succeeds via Argon2id.
   - All-zero 32B Base64 in all 4 variants (`"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`, `"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`) -> `ErrAllZeroKey` (does NOT fall through to Argon2id).
   - Non-canonical Base64 padding bit mutation (`"...+/9="` vs `"...+/8="`) -> NOT silently decoded to the same 32B key; embedded `\n` rejected by Base64 fast-path.
   - Base64 fast-path latency check (`< 5ms` for 1,000 calls, proving Argon2id is bypassed).
3. **`TestParseOutboundCredentials_SplittingAndEdgeCases`**:
   - Single Base64 key, single `>=16` passphrase, single passphrase containing colon (`"ab:cdefghijklmnopqrs"` -> `hasServerPSK=false`).
   - `<b64_iPSK>:<b64_uPSK>`, `<b64_iPSK>:<16+_passphrase>`, `<16+_pass_1>:<16+_pass_2>` -> `hasServerPSK=true`.
   - Negative boundaries: `""`, `"short:short"`, `"<valid_b64>:short"`, `"short:<valid_b64>"`, `"<valid_b64>:"`, `"<valid_b64>:<all_zero_b64>"` -> all return errors!
4. **`TestUserTable_LookupAndDuplicateRejection`**:
   - Valid multi-user table (`Password` and `Key` alias resolution), `O(1)` `Lookup` & `LookupEIH` hit/miss, `Users()` deterministic slice order, `nil` `*UserTable` safety.
   - Rejects empty `cfgUsers`, conflicting `Password`+`Key`, weak user password, duplicate `Name` (both named and multiple unnamed `""`), and duplicate `UPSK`/`UserID` (even if one user specifies `StdEncoding` and another specifies `RawURLEncoding` of the same 32B key!).
5. **`TestX25519StaticKeys_FourEncodingsAndLowOrderRejection`**:
   - Accepts `StdEncoding`, `RawStdEncoding`, `URLEncoding`, `RawURLEncoding` for both `ParseX25519PrivateKey` and `ParseX25519PublicKey`.
   - Rejects empty, wrong-length (31B/33B), invalid Base64, trailing-bit-mutated Base64, all-zero `[32]byte{}`, and all 7 RFC 7748 § 6.1 canonical/non-canonical low-order points (`0`, `1`, `e0eb7a...`, `5f9c95...`, `p-1`, `p`, `p+1`) in BOTH `ParseX25519PublicKey` and `ComputeECDH`!
6. **`TestGenerateMaskedEPK_RoundTripAndStatisticalUniformity`**:
   - Generates `2,048` ephemeral keypairs via `GenerateMaskedEPK`; verifies `UnmaskEPK` recovers the exact `PublicKey` every time, verifies raw `epk[31] & 0x80 == 0` for all `2,048` keys while `maskedEPK[31] & 0x80 != 0` count lies within `[880, 1168]` (`50% ± 6σ`), and overall bit-1 density across `524,288` bits lies within `[0.49, 0.51]`.
7. **`TestHandshakeAndSessionRatchet_EndToEndClientServerSymmetry`**:
   - Simulates full client <-> server key exchange across both PSK-only and 0-RTT Static PFS modes, verifying all 5 subkeys match, all 5 subkeys are pairwise distinct, flipping 1 bit of `ClientSalt`, `ServerSalt`, `MaskedClientEPK`, `EIH`, or `MaskedServerEPK` fails AEAD tag verification (`S-1`, `S-3`, `S-6`).
8. **`TestEncodeNonce_AndCipherSuiteSelection`**:
   - Verifies `EncodeNonce` for `0`, `1`, `0x0102030405060708`, and `math.MaxUint64` (ensuring `dst[0:4]` is zeroed even when `dst` previously held `0xff` bytes!).
   - Tests `selectCipherSuiteWithHardware` for both `hasAESGCM=true` and `hasAESGCM=false`, `SelectCipherSuite` error containing `"unsupported aether cipher"`, and `NewDataAEAD` round-trip + tamper rejection for `0x01`, `0x02`, and invalid `0x00`/`0xff`.

---

## 5. Verification Method

Once the M2 Worker writes `protocol/aether/crypto.go` and `protocol/aether/crypto_test.go` (and `replay.go` / `replay_test.go`):

1. **Unit, KAT & Race Detector Verification**:
   ```bash
   GOPROXY=direct GOSUMDB=off go test -v -race -count=1 ./protocol/aether/...
   ```
2. **Full `sing-box` Multi-Tag Binary Compilation Verification** (proving zero duplicate symbols with `cipher.go` and zero regressions in `cmd/sing-box`):
   ```bash
   GOPROXY=direct GOSUMDB=off CGO_ENABLED=0 go build -trimpath \
     -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,badlinkname,tfogo_checklinkname0" \
     -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=1.14.4-Custom-Aether' $(cat release/LDFLAGS) -s -w -buildid=" \
     -o /tmp/sing-box-m2-check ./cmd/sing-box && rm -f /tmp/sing-box-m2-check
   ```
3. **Invalidation Conditions**:
   - Any change to KDF salt/info strings in `PROJECT.md § Interface Contracts § 3` (`"AetherFlow-v2-KDF"`, `"AetherFlow-v2-EPK-Mask"`, `"AetherFlow-v2-UID"`, `"AetherFlow-v2-EIH"`, `"AetherFlow-v2-Client-Init"`, `"AetherFlow-v2-Session"`, `"AetherFlow-v2-Resp"`, `"AetherFlow-v2-C2S-Header"`, `"AetherFlow-v2-C2S-Payload"`, `"AetherFlow-v2-S2C-Header"`, `"AetherFlow-v2-S2C-Payload"`) or Argon2id cost parameters (`t=3, m=64*1024, p=4`) would invalidate the KAT vectors in § 4.2.
