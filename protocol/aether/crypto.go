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
	"math"
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
	ProtocolVersion uint8 = 0x02

	PSKSize             = 32
	HandshakeSaltSize   = 32
	EPKSize             = 32
	EIHSize             = 16
	UserIDSize          = 16
	AEADNonceSize       = 12
	AEADTagSize         = 16
	EPKMaskMaterialSize = 44

	FixedHeaderPlainSize  = 16
	EncryptedFixedHdrSize = FixedHeaderPlainSize + AEADTagSize                            // 32
	ClientPrefixNoEIHSize = HandshakeSaltSize + EPKSize + EncryptedFixedHdrSize           // 96
	ClientPrefixEIHSize   = HandshakeSaltSize + EPKSize + EIHSize + EncryptedFixedHdrSize // 112
	RespHeaderPlainSize   = 4
	EncryptedRespHdrSize  = RespHeaderPlainSize + AEADTagSize                  // 20
	ServerRespPrefixSize  = HandshakeSaltSize + EPKSize + EncryptedRespHdrSize // 84
	LengthHeaderPlainSize = 2
	EncryptedLengthSize   = LengthHeaderPlainSize + AEADTagSize // 18

	MinFramePlainSize = 2
	MaxFrameDataSize  = 16384
	MaxFramePadSize   = 255
	MaxFramePlainSize = MinFramePlainSize + MaxFramePadSize + MaxFrameDataSize // 16641

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
	ErrAmbiguousCredentials   = errors.New("aether: ambiguous colon-delimited credentials; use 32-byte Base64 keys")
	ErrInvalidX25519Key       = errors.New("aether: invalid X25519 key")
	ErrLowOrderX25519Point    = errors.New("aether: low-order X25519 point rejected")
	ErrInvalidSharedSecret    = errors.New("aether: invalid ECDH shared secret")
	ErrUnsupportedCipherSuite = errors.New("unsupported aether cipher")
	ErrEmptyUserTable         = errors.New("aether: empty users list")
	ErrDuplicateUserName      = errors.New("aether: duplicate user name")
	ErrDuplicateUserKey       = errors.New("aether: duplicate user password/key")
	ErrMissingInboundSecret   = errors.New("aether: inbound requires password/key or users")
	ErrAuthenticationFailed   = errors.New("aether: handshake authentication failed")
	ErrInvalidRespHeader      = errors.New("aether: invalid server response header")
	ErrInvalidFrameLength     = errors.New("aether: invalid frame length")
	ErrNonceExhausted         = errors.New("aether: directional AEAD nonce sequence exhausted")
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
	scalar[0] = 8
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

// hasZeroX25519VariableBits reports whether all 251 variable scalar bits of a
// 32-byte X25519 private key are zero (which would clamp to deterministic 2^254).
func hasZeroX25519VariableBits(raw [32]byte) bool {
	var acc byte
	acc |= raw[0] & 0xf8
	for i := 1; i < 31; i++ {
		acc |= raw[i]
	}
	acc |= raw[31] & 0x3f
	return subtle.ConstantTimeByteEq(acc, 0) == 1
}

// decodeBase64Key32 attempts strict canonical 32-byte Base64 decoding across
// StdEncoding, RawStdEncoding, URLEncoding, and RawURLEncoding without CR/LF malleability.
func decodeBase64Key32(s string) ([32]byte, bool) {
	var out [32]byte
	if strings.ContainsAny(s, "\r\n") {
		return out, false
	}
	var encodings []*base64.Encoding
	switch len(s) {
	case 44:
		if s[43] != '=' || s[42] == '=' {
			return out, false
		}
		encodings = []*base64.Encoding{strictStdBase64, strictURLBase64}
	case 43:
		encodings = []*base64.Encoding{strictRawStdBase64, strictRawURLBase64}
	default:
		return out, false
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

func generateNonZeroRandom32() ([32]byte, error) {
	var out [32]byte
	for {
		if _, err := io.ReadFull(rand.Reader, out[:]); err != nil {
			return [32]byte{}, err
		}
		if !isAllZero32(out) {
			return out, nil
		}
	}
}

// DerivePSK derives a 32-byte pre-shared key via the strict 32-byte Base64 fast-path
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

// ClientCredentials holds parsed outbound credentials for either single-secret mode
// or EIH multi-user mode ("<server_secret>:<user_secret>").
type ClientCredentials struct {
	HasServerPSK bool
	IPSK         [PSKSize]byte
	UPSK         [PSKSize]byte
	UserID       [UserIDSize]byte
}

func buildDualCredentials(left, right string) (ClientCredentials, error) {
	iPSK, err := DerivePSK(left)
	if err != nil {
		return ClientCredentials{}, fmt.Errorf("server credential: %w", err)
	}
	uPSK, err := DerivePSK(right)
	if err != nil {
		return ClientCredentials{}, fmt.Errorf("user credential: %w", err)
	}
	return ClientCredentials{
		HasServerPSK: true,
		IPSK:         iPSK,
		UPSK:         uPSK,
		UserID:       DeriveUserID(uPSK),
	}, nil
}

// ParseOutboundCredentials parses an outbound secret supporting either single-secret
// "<user_secret>" or EIH multi-user "<server_secret>:<user_secret>".
func ParseOutboundCredentials(secret string) (ClientCredentials, error) {
	if len(secret) == 0 {
		return ClientCredentials{}, ErrEmptySecret
	}
	idxFirst := strings.IndexByte(secret, ':')
	if idxFirst >= 0 {
		idxLast := strings.LastIndexByte(secret, ':')
		if idxFirst == idxLast {
			left := secret[:idxFirst]
			right := secret[idxFirst+1:]
			_, leftIsB64 := decodeBase64Key32(left)
			_, rightIsB64 := decodeBase64Key32(right)
			if leftIsB64 || rightIsB64 || (len(left) >= MinPassphraseLength && len(right) >= MinPassphraseLength) {
				return buildDualCredentials(left, right)
			}
		} else {
			if _, firstLeftIsB64 := decodeBase64Key32(secret[:idxFirst]); firstLeftIsB64 {
				return buildDualCredentials(secret[:idxFirst], secret[idxFirst+1:])
			}
			if _, lastRightIsB64 := decodeBase64Key32(secret[idxLast+1:]); lastRightIsB64 {
				return buildDualCredentials(secret[:idxLast], secret[idxLast+1:])
			}
			validSplitIdx := -1
			validSplitCount := 0
			for i := range len(secret) {
				if secret[i] != ':' {
					continue
				}
				left := secret[:i]
				right := secret[i+1:]
				_, leftIsB64 := decodeBase64Key32(left)
				_, rightIsB64 := decodeBase64Key32(right)
				if leftIsB64 || rightIsB64 {
					return buildDualCredentials(left, right)
				}
				if len(left) >= MinPassphraseLength && len(right) >= MinPassphraseLength {
					validSplitIdx = i
					validSplitCount++
				}
			}
			if validSplitCount >= 2 {
				return ClientCredentials{}, ErrAmbiguousCredentials
			}
			if validSplitCount == 1 {
				return buildDualCredentials(secret[:validSplitIdx], secret[validSplitIdx+1:])
			}
		}
	}

	uPSK, err := DerivePSK(secret)
	if err != nil {
		return ClientCredentials{}, err
	}
	return ClientCredentials{
		HasServerPSK: false,
		UPSK:         uPSK,
		UserID:       DeriveUserID(uPSK),
	}, nil
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
		panic(err)
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

// UserRecord holds a validated multi-user entry, its index, and its precomputed 16-byte UserID.
type UserRecord struct {
	Name   string
	Index  int
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
			Index:  i,
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

// ParseX25519PrivateKey parses a strict 32-byte Base64 static X25519 private key across
// all 4 Base64 variants, rejecting all-zero and clamped-zero variable-bit scalars.
func ParseX25519PrivateKey(encoded string) (*ecdh.PrivateKey, error) {
	raw, ok := decodeBase64Key32(encoded)
	if !ok {
		return nil, fmt.Errorf("%w: must be canonical 32-byte Base64", ErrInvalidX25519Key)
	}
	if hasZeroX25519VariableBits(raw) {
		return nil, fmt.Errorf("%w: %w", ErrInvalidX25519Key, ErrAllZeroKey)
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidX25519Key, err)
	}
	return priv, nil
}

// ParseX25519PublicKey parses a strict 32-byte Base64 static X25519 public key across
// all 4 Base64 variants, running a startup ECDH probe to reject all 14 Curve25519 low-order points.
func ParseX25519PublicKey(encoded string) (*ecdh.PublicKey, error) {
	raw, ok := decodeBase64Key32(encoded)
	if !ok {
		return nil, fmt.Errorf("%w: must be canonical 32-byte Base64", ErrInvalidX25519Key)
	}
	if isAllZero32(raw) {
		return nil, fmt.Errorf("%w: %w: %w", ErrInvalidX25519Key, ErrAllZeroKey, ErrLowOrderX25519Point)
	}
	pub, err := ecdh.X25519().NewPublicKey(raw[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidX25519Key, err)
	}
	if _, err := x25519LowOrderProbeKey.ECDH(pub); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidX25519Key, ErrLowOrderX25519Point)
	}
	return pub, nil
}

// ComputeECDH performs X25519 scalar multiplication, rejecting nil keys and all low-order points.
func ComputeECDH(localPriv *ecdh.PrivateKey, remotePub *ecdh.PublicKey) ([32]byte, error) {
	var out [32]byte
	if localPriv == nil || remotePub == nil {
		return out, ErrInvalidX25519Key
	}
	ss, err := localPriv.ECDH(remotePub)
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrInvalidSharedSecret, ErrLowOrderX25519Point)
	}
	copy(out[:], ss)
	if isAllZero32(out) {
		return [32]byte{}, fmt.Errorf("%w: %w", ErrInvalidSharedSecret, ErrLowOrderX25519Point)
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

// UnmaskEPK unmasks a 32-byte ChaCha20-masked X25519 public key and parses it into *ecdh.PublicKey,
// rejecting all-zero raw keys. Peer low-order points are rejected when ComputeECDH runs.
func UnmaskEPK(uPSK, salt, maskedEPK [32]byte) (*ecdh.PublicKey, error) {
	rawEPK := MaskEPK(uPSK, salt, maskedEPK)
	if isAllZero32(rawEPK) {
		return nil, fmt.Errorf("%w: %w", ErrInvalidX25519Key, ErrLowOrderX25519Point)
	}
	pub, err := ecdh.X25519().NewPublicKey(rawEPK[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidX25519Key, err)
	}
	return pub, nil
}

// UnmaskAndECDH unmasks maskedPeerEPK and computes X25519(localPriv, peerPub), rejecting all 14 low-order points.
func UnmaskAndECDH(localPriv *ecdh.PrivateKey, uPSK, salt, maskedPeerEPK [32]byte) ([32]byte, error) {
	if localPriv == nil {
		return [32]byte{}, ErrInvalidX25519Key
	}
	peerPub, err := UnmaskEPK(uPSK, salt, maskedPeerEPK)
	if err != nil {
		return [32]byte{}, err
	}
	return ComputeECDH(localPriv, peerPub)
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

// DirectionalCipher provides zero-allocation two-block independent-key AEAD frame
// encryption/decryption (18B encrypted length header + encrypted payload body) for a
// single direction (either under writeMu or under readMu).
type DirectionalCipher struct {
	headerAEAD   cipher.AEAD
	payloadAEAD  cipher.AEAD
	seq          uint64
	suite        uint8
	nonceScratch [AEADNonceSize]byte
	lenPlain     [LengthHeaderPlainSize]byte
	lenOpenBuf   [LengthHeaderPlainSize]byte
}

// NewDirectionalCipher constructs a DirectionalCipher for the negotiated suite and directional subkeys.
func NewDirectionalCipher(suite uint8, headerKey, payloadKey [32]byte) (*DirectionalCipher, error) {
	headerAEAD, err := NewDataAEAD(suite, headerKey)
	if err != nil {
		return nil, err
	}
	payloadAEAD, err := NewDataAEAD(suite, payloadKey)
	if err != nil {
		return nil, err
	}
	return &DirectionalCipher{
		headerAEAD:  headerAEAD,
		payloadAEAD: payloadAEAD,
		suite:       suite,
	}, nil
}

func (dc *DirectionalCipher) Suite() uint8 {
	return dc.suite
}

func (dc *DirectionalCipher) Seq() uint64 {
	return dc.seq
}

// SealFrame appends the 18-byte AEAD-sealed length header followed by the AEAD-sealed
// bodyPlain (2..16641 bytes -> +16B tag) to dst and advances the directional sequence number.
// Achieves 0 allocs/op when dst has sufficient remaining capacity.
func (dc *DirectionalCipher) SealFrame(dst, bodyPlain []byte) ([]byte, error) {
	bodyLen := len(bodyPlain)
	if bodyLen < MinFramePlainSize || bodyLen > MaxFramePlainSize {
		return nil, ErrInvalidFrameLength
	}
	if dc.seq == math.MaxUint64 {
		return nil, ErrNonceExhausted
	}
	EncodeNonce(dc.seq, &dc.nonceScratch)
	binary.BigEndian.PutUint16(dc.lenPlain[:], uint16(bodyLen))

	needed := EncryptedLengthSize + bodyLen + AEADTagSize
	if cap(dst)-len(dst) < needed {
		grown := make([]byte, len(dst), len(dst)+needed)
		copy(grown, dst)
		dst = grown
	}
	out := dc.headerAEAD.Seal(dst, dc.nonceScratch[:], dc.lenPlain[:], nil)
	out = dc.payloadAEAD.Seal(out, dc.nonceScratch[:], bodyPlain, nil)
	dc.seq++
	return out, nil
}

// OpenLengthHeader decrypts an 18-byte encrypted length header at the current directional
// sequence number without advancing seq until OpenPayloadBody succeeds.
func (dc *DirectionalCipher) OpenLengthHeader(encHeader []byte) (uint16, error) {
	if len(encHeader) != EncryptedLengthSize {
		return 0, ErrInvalidFrameLength
	}
	if dc.seq == math.MaxUint64 {
		return 0, ErrNonceExhausted
	}
	EncodeNonce(dc.seq, &dc.nonceScratch)
	plain, err := dc.headerAEAD.Open(dc.lenOpenBuf[:0], dc.nonceScratch[:], encHeader, nil)
	if err != nil {
		return 0, err
	}
	plainLen := binary.BigEndian.Uint16(plain)
	if plainLen < MinFramePlainSize || plainLen > MaxFramePlainSize {
		return 0, ErrInvalidFrameLength
	}
	return plainLen, nil
}

// OpenPayloadBody decrypts an encrypted frame body (PlainFrameLen + 16B tag) at the current
// directional sequence number and advances seq on success. Achieves 0 allocs/op when dst has capacity.
func (dc *DirectionalCipher) OpenPayloadBody(dst, encBody []byte) ([]byte, error) {
	if len(encBody) < MinFramePlainSize+AEADTagSize || len(encBody) > MaxFramePlainSize+AEADTagSize {
		return nil, ErrInvalidFrameLength
	}
	if dc.seq == math.MaxUint64 {
		return nil, ErrNonceExhausted
	}
	EncodeNonce(dc.seq, &dc.nonceScratch)
	plain, err := dc.payloadAEAD.Open(dst, dc.nonceScratch[:], encBody, nil)
	if err != nil {
		return nil, err
	}
	dc.seq++
	return plain, nil
}

// AuthMode identifies the server inbound authentication wire mode.
type AuthMode uint8

const (
	AuthModeSingleUser AuthMode = iota + 1
	AuthModeMultiUserEIH
	AuthModeMultiUserDirect
)

// ServerAuthenticator is an immutable, goroutine-safe inbound handshake authenticator
// supporting SingleUser (96B), MultiUserEIH (112B with constant-time dummy fallback),
// and MultiUserDirect (96B with non-breaking scan and deferred UnmaskEPK).
type ServerAuthenticator struct {
	mode          AuthMode
	singleUPSK    [PSKSize]byte
	iPSK          [PSKSize]byte
	users         *UserTable
	staticPriv    *ecdh.PrivateKey
	dummyUPSK     [PSKSize]byte
	dummyStaticSS [32]byte
}

// NewServerAuthenticator constructs an immutable ServerAuthenticator from resolved inbound config.
func NewServerAuthenticator(
	serverSecret string,
	cfgUsers []option.AetherUser,
	serverPrivateKeyB64 string,
) (*ServerAuthenticator, error) {
	var staticPriv *ecdh.PrivateKey
	if serverPrivateKeyB64 != "" {
		var err error
		staticPriv, err = ParseX25519PrivateKey(serverPrivateKeyB64)
		if err != nil {
			return nil, fmt.Errorf("server private_key: %w", err)
		}
	}

	dummyUPSK, err := generateNonZeroRandom32()
	if err != nil {
		return nil, err
	}
	dummyStaticSS, err := generateNonZeroRandom32()
	if err != nil {
		return nil, err
	}

	auth := &ServerAuthenticator{
		staticPriv:    staticPriv,
		dummyUPSK:     dummyUPSK,
		dummyStaticSS: dummyStaticSS,
	}

	if len(cfgUsers) == 0 {
		if serverSecret == "" {
			return nil, fmt.Errorf("%w: %w", ErrMissingInboundSecret, ErrEmptySecret)
		}
		uPSK, err := DerivePSK(serverSecret)
		if err != nil {
			return nil, err
		}
		auth.mode = AuthModeSingleUser
		auth.singleUPSK = uPSK
		return auth, nil
	}

	table, err := NewUserTable(cfgUsers)
	if err != nil {
		return nil, err
	}
	auth.users = table

	if serverSecret != "" {
		iPSK, err := DerivePSK(serverSecret)
		if err != nil {
			return nil, fmt.Errorf("inbound server password/key: %w", err)
		}
		auth.mode = AuthModeMultiUserEIH
		auth.iPSK = iPSK
		return auth, nil
	}

	auth.mode = AuthModeMultiUserDirect
	return auth, nil
}

// NewServerAuthenticatorFromOptions constructs a ServerAuthenticator directly from AetherInboundOptions.
func NewServerAuthenticatorFromOptions(options option.AetherInboundOptions) (*ServerAuthenticator, error) {
	serverSecret, err := option.ResolveSecret(options.Password, options.Key)
	if err != nil {
		return nil, err
	}
	return NewServerAuthenticator(serverSecret, options.Users, options.ServerPrivateKey)
}

func (a *ServerAuthenticator) Mode() AuthMode {
	return a.mode
}

func (a *ServerAuthenticator) HasStaticKey() bool {
	return a.staticPriv != nil
}

func (a *ServerAuthenticator) ClientPrefixSize() int {
	if a.mode == AuthModeMultiUserEIH {
		return ClientPrefixEIHSize
	}
	return ClientPrefixNoEIHSize
}

func (a *ServerAuthenticator) evalStaticCandidate(uPSK, clientSalt, maskedEPK [32]byte) (*ecdh.PublicKey, [32]byte, bool) {
	rawEPK := MaskEPK(uPSK, clientSalt, maskedEPK)
	pub, err := ecdh.X25519().NewPublicKey(rawEPK[:])
	if err != nil {
		return nil, a.dummyStaticSS, false
	}
	// Go's x25519ScalarMult runs the full constant-time Montgomery ladder on every 32-byte
	// point before checking isZero(out), so low-order points take identical scalar-mult time.
	ssSlice, ecdhErr := a.staticPriv.ECDH(pub)
	if ecdhErr != nil || isAllZero32(rawEPK) {
		return nil, a.dummyStaticSS, false
	}
	var ss [32]byte
	copy(ss[:], ssSlice)
	if isAllZero32(ss) {
		return nil, a.dummyStaticSS, false
	}
	return pub, ss, true
}

// ServerHandshakeState holds verified fixed-prefix state for an in-progress server handshake.
type ServerHandshakeState struct {
	ClientSalt  [HandshakeSaltSize]byte
	UserName    string
	UserIndex   int
	uPSK        [PSKSize]byte
	clientEPK   *ecdh.PublicKey
	hasStatic   bool
	ssStatic    [32]byte
	fixedHeader [FixedHeaderPlainSize]byte
	initAEAD    cipher.AEAD
	varOpened   bool
}

func (s *ServerHandshakeState) ClientEPK() *ecdh.PublicKey {
	return s.clientEPK
}

// OpenClientFixedPrefix authenticates and decrypts the 96B (or 112B EIH) fixed client prefix
// with timing-safe handling across SingleUser, MultiUserEIH, and MultiUserDirect modes.
func (a *ServerAuthenticator) OpenClientFixedPrefix(prefix []byte) (*ServerHandshakeState, [FixedHeaderPlainSize]byte, error) {
	var zeroHdr [FixedHeaderPlainSize]byte
	if len(prefix) != a.ClientPrefixSize() {
		return nil, zeroHdr, ErrAuthenticationFailed
	}

	var clientSalt [HandshakeSaltSize]byte
	var maskedEPK [EPKSize]byte
	copy(clientSalt[:], prefix[0:32])
	copy(maskedEPK[:], prefix[32:64])

	var nonce0 [AEADNonceSize]byte
	EncodeNonce(0, &nonce0)

	switch a.mode {
	case AuthModeSingleUser:
		aad := prefix[0:64]
		encFixed := prefix[64:96]
		var plainBuf [FixedHeaderPlainSize]byte

		if a.staticPriv != nil {
			peerPub, ssStatic, epkValid := a.evalStaticCandidate(a.singleUPSK, clientSalt, maskedEPK)
			initAEAD, err := DeriveClientInitAEAD(a.singleUPSK, clientSalt, ssStatic[:])
			if err != nil {
				return nil, zeroHdr, ErrAuthenticationFailed
			}
			plain, openErr := initAEAD.Open(plainBuf[:0], nonce0[:], encFixed, aad)
			if openErr != nil || !epkValid {
				return nil, zeroHdr, ErrAuthenticationFailed
			}
			var fixedOut [FixedHeaderPlainSize]byte
			copy(fixedOut[:], plain)
			return &ServerHandshakeState{
				ClientSalt:  clientSalt,
				UserIndex:   -1,
				uPSK:        a.singleUPSK,
				clientEPK:   peerPub,
				hasStatic:   true,
				ssStatic:    ssStatic,
				fixedHeader: fixedOut,
				initAEAD:    initAEAD,
			}, fixedOut, nil
		}

		initAEAD, err := DeriveClientInitAEAD(a.singleUPSK, clientSalt, nil)
		if err != nil {
			return nil, zeroHdr, ErrAuthenticationFailed
		}
		plain, openErr := initAEAD.Open(plainBuf[:0], nonce0[:], encFixed, aad)
		if openErr != nil {
			return nil, zeroHdr, ErrAuthenticationFailed
		}
		peerPub, err := UnmaskEPK(a.singleUPSK, clientSalt, maskedEPK)
		if err != nil {
			return nil, zeroHdr, ErrAuthenticationFailed
		}
		var fixedOut [FixedHeaderPlainSize]byte
		copy(fixedOut[:], plain)
		return &ServerHandshakeState{
			ClientSalt:  clientSalt,
			UserIndex:   -1,
			uPSK:        a.singleUPSK,
			clientEPK:   peerPub,
			fixedHeader: fixedOut,
			initAEAD:    initAEAD,
		}, fixedOut, nil

	case AuthModeMultiUserEIH:
		var eih [EIHSize]byte
		copy(eih[:], prefix[64:80])
		aad := prefix[0:80]
		encFixed := prefix[80:112]

		rec, found := a.users.LookupEIH(a.iPSK, clientSalt, eih)
		candUPSK := a.dummyUPSK
		userName := ""
		userIndex := -1
		if found {
			candUPSK = rec.UPSK
			userName = rec.Name
			userIndex = rec.Index
		}

		var plainBuf [FixedHeaderPlainSize]byte
		if a.staticPriv != nil {
			peerPub, ssStatic, epkValid := a.evalStaticCandidate(candUPSK, clientSalt, maskedEPK)
			initAEAD, err := DeriveClientInitAEAD(candUPSK, clientSalt, ssStatic[:])
			if err != nil {
				return nil, zeroHdr, ErrAuthenticationFailed
			}
			plain, openErr := initAEAD.Open(plainBuf[:0], nonce0[:], encFixed, aad)
			if !found || openErr != nil || !epkValid {
				return nil, zeroHdr, ErrAuthenticationFailed
			}
			var fixedOut [FixedHeaderPlainSize]byte
			copy(fixedOut[:], plain)
			return &ServerHandshakeState{
				ClientSalt:  clientSalt,
				UserName:    userName,
				UserIndex:   userIndex,
				uPSK:        candUPSK,
				clientEPK:   peerPub,
				hasStatic:   true,
				ssStatic:    ssStatic,
				fixedHeader: fixedOut,
				initAEAD:    initAEAD,
			}, fixedOut, nil
		}

		initAEAD, err := DeriveClientInitAEAD(candUPSK, clientSalt, nil)
		if err != nil {
			return nil, zeroHdr, ErrAuthenticationFailed
		}
		plain, openErr := initAEAD.Open(plainBuf[:0], nonce0[:], encFixed, aad)
		if !found || openErr != nil {
			return nil, zeroHdr, ErrAuthenticationFailed
		}
		peerPub, err := UnmaskEPK(candUPSK, clientSalt, maskedEPK)
		if err != nil {
			return nil, zeroHdr, ErrAuthenticationFailed
		}
		var fixedOut [FixedHeaderPlainSize]byte
		copy(fixedOut[:], plain)
		return &ServerHandshakeState{
			ClientSalt:  clientSalt,
			UserName:    userName,
			UserIndex:   userIndex,
			uPSK:        candUPSK,
			clientEPK:   peerPub,
			fixedHeader: fixedOut,
			initAEAD:    initAEAD,
		}, fixedOut, nil

	case AuthModeMultiUserDirect:
		aad := prefix[0:64]
		encFixed := prefix[64:96]
		users := a.users.Users()

		var (
			matchedRec      *UserRecord
			matchedPlain    [FixedHeaderPlainSize]byte
			matchedInitAEAD cipher.AEAD
			matchedPeerPub  *ecdh.PublicKey
			matchedSSStatic [32]byte
		)

		if a.staticPriv == nil {
			// Deferred UnmaskEPK: scan all M users without early break so user[0] and user[M-1]
			// exhibit uniform handshake CPU work, and unmask epk_c only once after the scan.
			for _, rec := range users {
				initAEAD, err := DeriveClientInitAEAD(rec.UPSK, clientSalt, nil)
				if err != nil {
					continue
				}
				var candPlain [FixedHeaderPlainSize]byte
				plain, openErr := initAEAD.Open(candPlain[:0], nonce0[:], encFixed, aad)
				if openErr == nil && matchedRec == nil {
					matchedRec = rec
					copy(matchedPlain[:], plain)
					matchedInitAEAD = initAEAD
				}
			}
			if matchedRec == nil {
				return nil, zeroHdr, ErrAuthenticationFailed
			}
			peerPub, err := UnmaskEPK(matchedRec.UPSK, clientSalt, maskedEPK)
			if err != nil {
				return nil, zeroHdr, ErrAuthenticationFailed
			}
			return &ServerHandshakeState{
				ClientSalt:  clientSalt,
				UserName:    matchedRec.Name,
				UserIndex:   matchedRec.Index,
				uPSK:        matchedRec.UPSK,
				clientEPK:   peerPub,
				fixedHeader: matchedPlain,
				initAEAD:    matchedInitAEAD,
			}, matchedPlain, nil
		}

		for _, rec := range users {
			peerPub, ssStatic, epkValid := a.evalStaticCandidate(rec.UPSK, clientSalt, maskedEPK)
			initAEAD, err := DeriveClientInitAEAD(rec.UPSK, clientSalt, ssStatic[:])
			if err != nil {
				continue
			}
			var candPlain [FixedHeaderPlainSize]byte
			plain, openErr := initAEAD.Open(candPlain[:0], nonce0[:], encFixed, aad)
			if openErr == nil && epkValid && matchedRec == nil {
				matchedRec = rec
				copy(matchedPlain[:], plain)
				matchedInitAEAD = initAEAD
				matchedPeerPub = peerPub
				matchedSSStatic = ssStatic
			}
		}
		if matchedRec == nil {
			return nil, zeroHdr, ErrAuthenticationFailed
		}
		return &ServerHandshakeState{
			ClientSalt:  clientSalt,
			UserName:    matchedRec.Name,
			UserIndex:   matchedRec.Index,
			uPSK:        matchedRec.UPSK,
			clientEPK:   matchedPeerPub,
			hasStatic:   true,
			ssStatic:    matchedSSStatic,
			fixedHeader: matchedPlain,
			initAEAD:    matchedInitAEAD,
		}, matchedPlain, nil

	default:
		return nil, zeroHdr, ErrAuthenticationFailed
	}
}

// OpenVarHeader decrypts EncryptedVarHeader using initAEAD (nonce=1, AAD=FixedHeaderPlaintext[16]).
func (s *ServerHandshakeState) OpenVarHeader(dst, ciphertext []byte) ([]byte, error) {
	if s.varOpened || len(ciphertext) < AEADTagSize {
		return nil, ErrAuthenticationFailed
	}
	var nonce1 [AEADNonceSize]byte
	EncodeNonce(1, &nonce1)
	plain, err := s.initAEAD.Open(dst, nonce1[:], ciphertext, s.fixedHeader[:])
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	s.varOpened = true
	return plain, nil
}

// Complete generates ServerSalt and MaskedServerEPK, computes ephemeral ECDH (rejecting all 14
// low-order Curve25519 points), derives dual-salt session keys, seals the 84-byte server response
// prefix, and returns server send (S2C) and recv (C2S) DirectionalCiphers.
func (s *ServerHandshakeState) Complete(
	cipherSuite uint8,
	respPlain [RespHeaderPlainSize]byte,
) (respPrefix [ServerRespPrefixSize]byte, send *DirectionalCipher, recv *DirectionalCipher, err error) {
	if !IsValidCipherSuite(cipherSuite) {
		return respPrefix, nil, nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedCipherSuite, cipherSuite)
	}
	serverSalt, err := GenerateRandomSalt()
	if err != nil {
		return respPrefix, nil, nil, err
	}
	ekS, maskedServerEPK, err := GenerateMaskedEPK(s.uPSK, serverSalt)
	if err != nil {
		return respPrefix, nil, nil, err
	}
	ssEph, err := ComputeECDH(ekS, s.clientEPK)
	if err != nil {
		return respPrefix, nil, nil, err
	}

	var staticSlice []byte
	if s.hasStatic {
		staticSlice = s.ssStatic[:]
	}
	keys, err := DeriveSessionKeys(s.uPSK, ssEph, staticSlice, s.ClientSalt, serverSalt)
	if err != nil {
		return respPrefix, nil, nil, err
	}
	respAEAD, err := NewRespAEAD(keys.RespKey)
	if err != nil {
		return respPrefix, nil, nil, err
	}

	var aad [96]byte
	copy(aad[0:32], s.ClientSalt[:])
	copy(aad[32:64], serverSalt[:])
	copy(aad[64:96], maskedServerEPK[:])

	var nonce0 [AEADNonceSize]byte
	EncodeNonce(0, &nonce0)

	copy(respPrefix[0:32], serverSalt[:])
	copy(respPrefix[32:64], maskedServerEPK[:])
	respAEAD.Seal(respPrefix[64:64], nonce0[:], respPlain[:], aad[:])

	send, err = NewDirectionalCipher(cipherSuite, keys.S2CHeaderKey, keys.S2CPayloadKey)
	if err != nil {
		return [ServerRespPrefixSize]byte{}, nil, nil, err
	}
	recv, err = NewDirectionalCipher(cipherSuite, keys.C2SHeaderKey, keys.C2SPayloadKey)
	if err != nil {
		return [ServerRespPrefixSize]byte{}, nil, nil, err
	}
	return respPrefix, send, recv, nil
}

// ClientHandshakeState holds ephemeral state for an outbound client handshake.
type ClientHandshakeState struct {
	clientSalt  [HandshakeSaltSize]byte
	uPSK        [PSKSize]byte
	ekC         *ecdh.PrivateKey
	hasStatic   bool
	ssStatic    [32]byte
	fixedHeader [FixedHeaderPlainSize]byte
	initAEAD    cipher.AEAD
	varSealed   bool
}

func (c *ClientHandshakeState) ClientSalt() [HandshakeSaltSize]byte {
	return c.clientSalt
}

// StartClientHandshake generates ClientSalt and MaskedClientEPK, computes optional static 0-RTT
// ECDH, and seals FixedHeaderPlaintext into a 96-byte (or 112-byte EIH) client prefix.
func StartClientHandshake(
	creds ClientCredentials,
	serverStaticPub *ecdh.PublicKey,
	fixedPlain [FixedHeaderPlainSize]byte,
) (*ClientHandshakeState, []byte, error) {
	clientSalt, err := GenerateRandomSalt()
	if err != nil {
		return nil, nil, err
	}
	ekC, maskedClientEPK, err := GenerateMaskedEPK(creds.UPSK, clientSalt)
	if err != nil {
		return nil, nil, err
	}

	var (
		hasStatic   bool
		ssStatic    [32]byte
		staticSlice []byte
	)
	if serverStaticPub != nil {
		ssStatic, err = ComputeECDH(ekC, serverStaticPub)
		if err != nil {
			return nil, nil, err
		}
		hasStatic = true
		staticSlice = ssStatic[:]
	}

	initAEAD, err := DeriveClientInitAEAD(creds.UPSK, clientSalt, staticSlice)
	if err != nil {
		return nil, nil, err
	}

	var nonce0 [AEADNonceSize]byte
	EncodeNonce(0, &nonce0)

	var prefix []byte
	if creds.HasServerPSK {
		eih := MaskEIH(creds.IPSK, clientSalt, creds.UserID)
		prefix = make([]byte, ClientPrefixEIHSize)
		copy(prefix[0:32], clientSalt[:])
		copy(prefix[32:64], maskedClientEPK[:])
		copy(prefix[64:80], eih[:])
		initAEAD.Seal(prefix[80:80], nonce0[:], fixedPlain[:], prefix[0:80])
	} else {
		prefix = make([]byte, ClientPrefixNoEIHSize)
		copy(prefix[0:32], clientSalt[:])
		copy(prefix[32:64], maskedClientEPK[:])
		initAEAD.Seal(prefix[64:64], nonce0[:], fixedPlain[:], prefix[0:64])
	}

	return &ClientHandshakeState{
		clientSalt:  clientSalt,
		uPSK:        creds.UPSK,
		ekC:         ekC,
		hasStatic:   hasStatic,
		ssStatic:    ssStatic,
		fixedHeader: fixedPlain,
		initAEAD:    initAEAD,
	}, prefix, nil
}

// SealVarHeader encrypts varPlain with initAEAD (nonce=1, AAD=FixedHeaderPlaintext[16]).
func (c *ClientHandshakeState) SealVarHeader(dst, varPlain []byte) []byte {
	var nonce1 [AEADNonceSize]byte
	EncodeNonce(1, &nonce1)
	c.varSealed = true
	return c.initAEAD.Seal(dst, nonce1[:], varPlain, c.fixedHeader[:])
}

// Complete processes the 84-byte server response prefix, verifies RespHeader ([0x02, 0x00, suite, 0x00]),
// and returns client send (C2S) and recv (S2C) DirectionalCiphers.
func (c *ClientHandshakeState) Complete(
	respPrefix []byte,
	expectedCipherSuite uint8,
) (respPlain [RespHeaderPlainSize]byte, send *DirectionalCipher, recv *DirectionalCipher, err error) {
	if len(respPrefix) != ServerRespPrefixSize {
		return respPlain, nil, nil, ErrInvalidRespHeader
	}
	if !IsValidCipherSuite(expectedCipherSuite) {
		return respPlain, nil, nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedCipherSuite, expectedCipherSuite)
	}

	var serverSalt [HandshakeSaltSize]byte
	var maskedServerEPK [EPKSize]byte
	copy(serverSalt[:], respPrefix[0:32])
	copy(maskedServerEPK[:], respPrefix[32:64])
	encRespHdr := respPrefix[64:84]

	ssEph, err := UnmaskAndECDH(c.ekC, c.uPSK, serverSalt, maskedServerEPK)
	if err != nil {
		return respPlain, nil, nil, err
	}

	var staticSlice []byte
	if c.hasStatic {
		staticSlice = c.ssStatic[:]
	}
	keys, err := DeriveSessionKeys(c.uPSK, ssEph, staticSlice, c.clientSalt, serverSalt)
	if err != nil {
		return respPlain, nil, nil, err
	}
	respAEAD, err := NewRespAEAD(keys.RespKey)
	if err != nil {
		return respPlain, nil, nil, err
	}

	var aad [96]byte
	copy(aad[0:32], c.clientSalt[:])
	copy(aad[32:64], serverSalt[:])
	copy(aad[64:96], maskedServerEPK[:])

	var nonce0 [AEADNonceSize]byte
	EncodeNonce(0, &nonce0)

	plain, err := respAEAD.Open(respPlain[:0], nonce0[:], encRespHdr, aad[:])
	if err != nil {
		return [RespHeaderPlainSize]byte{}, nil, nil, ErrAuthenticationFailed
	}
	copy(respPlain[:], plain)
	if respPlain[0] != ProtocolVersion || respPlain[1] != 0x00 || respPlain[2] != expectedCipherSuite || respPlain[3] != 0x00 {
		return [RespHeaderPlainSize]byte{}, nil, nil, ErrInvalidRespHeader
	}

	send, err = NewDirectionalCipher(expectedCipherSuite, keys.C2SHeaderKey, keys.C2SPayloadKey)
	if err != nil {
		return [RespHeaderPlainSize]byte{}, nil, nil, err
	}
	recv, err = NewDirectionalCipher(expectedCipherSuite, keys.S2CHeaderKey, keys.S2CPayloadKey)
	if err != nil {
		return [RespHeaderPlainSize]byte{}, nil, nil, err
	}
	return respPlain, send, recv, nil
}
