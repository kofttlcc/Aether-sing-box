package aether

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	require.NoError(t, err)
	require.Len(t, raw, 32)
	var out [32]byte
	copy(out[:], raw)
	return out
}

func mustHex16(t *testing.T, s string) [16]byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	require.NoError(t, err)
	require.Len(t, raw, 16)
	var out [16]byte
	copy(out[:], raw)
	return out
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	require.NoError(t, err)
	return raw
}

var all14X25519LowOrderPointsHex = []string{
	// u = 0 (canonical & non-canonical +2^255, p, p+2^255)
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	// u = 1 (order 4: canonical & +2^255, p+1, p+1+2^255)
	"0100000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000080",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	// Order 8 #1 (canonical & +2^255)
	"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
	"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
	// Order 8 #2 (canonical & +2^255)
	"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
	"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
	// u = p - 1 (quadratic twist order 4: canonical & +2^255)
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

func TestKAT_All29IndependentReferenceVectors(t *testing.T) {
	t.Parallel()

	// Vector 1: Argon2id 16-char boundary passphrase
	psk1, err := DerivePSK("AetherV2-TestKey")
	require.NoError(t, err)
	require.Equal(t, "eeb853fabf4168e7bf4c37b42c9f0e95b7b3abe6a3174f1ed9993af8739d476f", hex.EncodeToString(psk1[:]))

	// Vector 2: Argon2id 24-char passphrase
	psk2, err := DerivePSK("DedicatedLine-Secret-001")
	require.NoError(t, err)
	require.Equal(t, "053d012dd9c7d2b906cf72d5e6649af6daede7c0d82fe616a38f4a7d99253d4c", hex.EncodeToString(psk2[:]))

	// Vectors 3..6: 32-byte Base64 fast-path across all 4 encodings
	const expectedUPSKHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1dfbff"
	for _, encoded := range []string{
		"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd+/8=", // Vector 3: StdEncoding
		"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd+/8",  // Vector 4: RawStdEncoding
		"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd-_8=", // Vector 5: URLEncoding
		"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd-_8",  // Vector 6: RawURLEncoding
	} {
		got, deriveErr := DerivePSK(encoded)
		require.NoError(t, deriveErr, "encoding=%q", encoded)
		require.Equal(t, expectedUPSKHex, hex.EncodeToString(got[:]))
	}
	uPSK := mustHex32(t, expectedUPSKHex)

	// Vector 7: iPSK via StdEncoding
	iPSK, err := DerivePSK("EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8=")
	require.NoError(t, err)
	require.Equal(t, "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f", hex.EncodeToString(iPSK[:]))

	// Vector 8: DeriveUserID
	userID := DeriveUserID(uPSK)
	require.Equal(t, "998a38f4e1515394497d30bc75249448", hex.EncodeToString(userID[:]))

	// Vectors 9 & 10: deriveEIHMask & MaskEIH / UnmaskEIH
	clientSalt := mustHex32(t, "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
	eihMask := deriveEIHMask(iPSK, clientSalt)
	require.Equal(t, "6e288f81aa5d91ce92d56ef029fbf6b4", hex.EncodeToString(eihMask[:]))
	eih := MaskEIH(iPSK, clientSalt, userID)
	require.Equal(t, "f7a2b7754b0cc25adba85e4c5cdf62fc", hex.EncodeToString(eih[:]))
	require.Equal(t, userID, UnmaskEIH(iPSK, clientSalt, eih))

	// Vectors 11 & 12: Client ephemeral X25519 + ChaCha20 MaskEPK / UnmaskEPK
	ekCRaw := mustHex32(t, "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
	ekC, err := ecdh.X25519().NewPrivateKey(ekCRaw[:])
	require.NoError(t, err)
	var epkC [32]byte
	copy(epkC[:], ekC.PublicKey().Bytes())
	require.Equal(t, "34e42d4af5ef94a07a3a84201b889d4cd1a743cb27b11b6a10438a8feb8e5847", hex.EncodeToString(epkC[:]))

	maskedEPKC := MaskEPK(uPSK, clientSalt, epkC)
	require.Equal(t, "e6208fb969ed169629dfb561c13f3c71239d49176a3a1f9008dc0147862189dd", hex.EncodeToString(maskedEPKC[:]))
	require.NotZero(t, maskedEPKC[31]&0x80, "KAT maskedEPKC byte 31 = 0xdd has MSB=1")
	unmaskedPubC, err := UnmaskEPK(uPSK, clientSalt, maskedEPKC)
	require.NoError(t, err)
	require.True(t, unmaskedPubC.Equal(ekC.PublicKey()))

	// Vectors 13 & 14: Server ephemeral X25519 + ChaCha20 MaskEPK / UnmaskEPK
	serverSalt := mustHex32(t, "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf")
	ekSRaw := mustHex32(t, "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f")
	ekS, err := ecdh.X25519().NewPrivateKey(ekSRaw[:])
	require.NoError(t, err)
	var epkS [32]byte
	copy(epkS[:], ekS.PublicKey().Bytes())
	require.Equal(t, "392d174a38b3b1beafaf1fe824870841c5fa531bc6eafdb6402c124664488c1c", hex.EncodeToString(epkS[:]))

	maskedEPKS := MaskEPK(uPSK, serverSalt, epkS)
	require.Equal(t, "8020e59ea04bc2e69b3337ecca8157743500a65f2b699f792811b1b91d856c4f", hex.EncodeToString(maskedEPKS[:]))
	unmaskedPubS, err := UnmaskEPK(uPSK, serverSalt, maskedEPKS)
	require.NoError(t, err)
	require.True(t, unmaskedPubS.Equal(ekS.PublicKey()))

	// Vector 15: Static server X25519 keypair
	skS, err := ParseX25519PrivateKey("cHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo8=")
	require.NoError(t, err)
	spkS, err := ParseX25519PublicKey("I7e7jJGuAIcR+xKEZ4C83x4GX4Ib3+xJ9X58fc1MSCM=")
	require.NoError(t, err)
	require.True(t, skS.PublicKey().Equal(spkS))
	require.Equal(t, "23b7bb8c91ae008711fb12846780bcdf1e065f821bdfec49f57e7c7dcd4c4823", hex.EncodeToString(spkS.Bytes()))

	// Vector 16: Ephemeral ECDH shared secret symmetry
	ssEphClient, err := ComputeECDH(ekC, unmaskedPubS)
	require.NoError(t, err)
	ssEphServer, err := ComputeECDH(ekS, unmaskedPubC)
	require.NoError(t, err)
	require.Equal(t, ssEphClient, ssEphServer)
	require.Equal(t, "d800703cfb0fc9422762b8cf9b29c7211cb2ef6abac6a29d2df1de283c1a5a50", hex.EncodeToString(ssEphClient[:]))

	// Vector 17: Static 0-RTT ECDH shared secret symmetry
	ssStaticClient, err := ComputeECDH(ekC, spkS)
	require.NoError(t, err)
	ssStaticServer, err := ComputeECDH(skS, unmaskedPubC)
	require.NoError(t, err)
	require.Equal(t, ssStaticClient, ssStaticServer)
	require.Equal(t, "436be988cf0004b93d7b4c35403a45d6004b6def411a14c3633af43f27a8263e", hex.EncodeToString(ssStaticClient[:]))

	// Vectors 18, 19a, 19b: DeriveClientInitKey & initAEAD (No Static Key, 64B AAD)
	initKeyA, err := DeriveClientInitKey(uPSK, clientSalt, nil)
	require.NoError(t, err)
	require.Equal(t, "5b33be524b9fe4faaddc1ecb4e7f0e1115d58695f065b89e2d2546483ff8ce4d", hex.EncodeToString(initKeyA[:]))

	initAEADA, err := DeriveClientInitAEAD(uPSK, clientSalt, nil)
	require.NoError(t, err)
	fixedPT := mustHex16(t, "02010100000000006735398000200040")
	varPT := mustHexBytes(t, "000102030405060708090a0b0c0d0e0f")
	var aad64 [64]byte
	copy(aad64[0:32], clientSalt[:])
	copy(aad64[32:64], maskedEPKC[:])

	var nonce0, nonce1 [AEADNonceSize]byte
	EncodeNonce(0, &nonce0)
	EncodeNonce(1, &nonce1)

	fixedCTA := initAEADA.Seal(nil, nonce0[:], fixedPT[:], aad64[:])
	require.Equal(t, "092e24e7e20a13b2b659db54f390d746922d2cfab66446c3be97eeebbd321bc0", hex.EncodeToString(fixedCTA))
	openedFixedA, err := initAEADA.Open(nil, nonce0[:], fixedCTA, aad64[:])
	require.NoError(t, err)
	require.Equal(t, fixedPT[:], openedFixedA)

	varCTA := initAEADA.Seal(nil, nonce1[:], varPT, fixedPT[:])
	require.Equal(t, "f315719703210366b2520ed62b8e4e7fb29a983b6718604e417a9b8e7a34ec0b", hex.EncodeToString(varCTA))
	openedVarA, err := initAEADA.Open(nil, nonce1[:], varCTA, fixedPT[:])
	require.NoError(t, err)
	require.Equal(t, varPT, openedVarA)

	// Vectors 20, 21a, 21b: DeriveClientInitKey & initAEAD (With Static Key + EIH 80B AAD)
	initKeyB, err := DeriveClientInitKey(uPSK, clientSalt, ssStaticClient[:])
	require.NoError(t, err)
	require.Equal(t, "7726f62a03009bf8ded213d1a33d883c6379dbaa2cd0706fbef18321d378dfa9", hex.EncodeToString(initKeyB[:]))

	initAEADB, err := DeriveClientInitAEAD(uPSK, clientSalt, ssStaticClient[:])
	require.NoError(t, err)
	var aad80 [80]byte
	copy(aad80[0:32], clientSalt[:])
	copy(aad80[32:64], maskedEPKC[:])
	copy(aad80[64:80], eih[:])

	fixedCTB := initAEADB.Seal(nil, nonce0[:], fixedPT[:], aad80[:])
	require.Equal(t, "f068e6150e6940aebc05f8dedbb3b1badf67b13261ec4fa7dc4c1e291c7e25c9", hex.EncodeToString(fixedCTB))
	openedFixedB, err := initAEADB.Open(nil, nonce0[:], fixedCTB, aad80[:])
	require.NoError(t, err)
	require.Equal(t, fixedPT[:], openedFixedB)

	varCTB := initAEADB.Seal(nil, nonce1[:], varPT, fixedPT[:])
	require.Equal(t, "43194279f1b28055e482dd5fa1525b71dce4fdc0cc494dbb3cca7151cabda063", hex.EncodeToString(varCTB))
	openedVarB, err := initAEADB.Open(nil, nonce1[:], varCTB, fixedPT[:])
	require.NoError(t, err)
	require.Equal(t, varPT, openedVarB)

	// Vector 22: DeriveSessionKeys Mode A (no static key)
	keysA, err := DeriveSessionKeys(uPSK, ssEphClient, nil, clientSalt, serverSalt)
	require.NoError(t, err)
	require.Equal(t, "53a7cb25b894ffd419534566ef25690b0e805de3584044933d1e1a10c57f047f", hex.EncodeToString(keysA.MasterSecret[:]))
	require.Equal(t, "8fe832c3e4bfc413e045fb63728274d09c4be7c74fe35f8dea634dadb6bcbd2a", hex.EncodeToString(keysA.RespKey[:]))
	require.Equal(t, "26daf3f0067dba1ccfdc08c0ccfefa93ca2bc66f120b47231e36da28d01d4a2c", hex.EncodeToString(keysA.C2SHeaderKey[:]))
	require.Equal(t, "e983abacfcc4ca33b2d4653960272b55bb726d92e3a04380007144c131c50e9a", hex.EncodeToString(keysA.C2SPayloadKey[:]))
	require.Equal(t, "8a165fa7db2673adc4f9f347250df2d00555fdf471a3a984c3ac1d8ccd67017c", hex.EncodeToString(keysA.S2CHeaderKey[:]))
	require.Equal(t, "0648cd952b50062de4a33c38c3463d4c87b41a2c23d8efe1dca4f5a289b5b4d0", hex.EncodeToString(keysA.S2CPayloadKey[:]))

	// Vector 23: DeriveSessionKeys Mode B (with static 0-RTT PFS key)
	keysB, err := DeriveSessionKeys(uPSK, ssEphClient, ssStaticClient[:], clientSalt, serverSalt)
	require.NoError(t, err)
	require.Equal(t, "c9f1be6a318b408127f55c097b1ea3e2be3bbe78476a19ddf38654309d4b1da3", hex.EncodeToString(keysB.MasterSecret[:]))
	require.Equal(t, "211d02251c455824e343957d7c22e0f83e116ef20f1a72867af21476c5c7420f", hex.EncodeToString(keysB.RespKey[:]))
	require.Equal(t, "34882c16081a2f4eeccb3cfe8529a711ab319dddce31677ddb191388a5faf65c", hex.EncodeToString(keysB.C2SHeaderKey[:]))
	require.Equal(t, "5a4de848efc45576d045d387dd7a35fede4f43ef96712f214cb55bf3cca25547", hex.EncodeToString(keysB.C2SPayloadKey[:]))
	require.Equal(t, "58dd5de42209042a1bbc3d4780216072c8fb57d78fd0b683bc28244f14a332e2", hex.EncodeToString(keysB.S2CHeaderKey[:]))
	require.Equal(t, "c6f454f144cd0ad6b898151ca0fb5cfabcd1d226f3e9946a278b24e2d943725d", hex.EncodeToString(keysB.S2CPayloadKey[:]))

	// Vector 24: NewRespAEAD EncryptedRespHeader (20B)
	respAEAD, err := NewRespAEAD(keysA.RespKey)
	require.NoError(t, err)
	var aad96 [96]byte
	copy(aad96[0:32], clientSalt[:])
	copy(aad96[32:64], serverSalt[:])
	copy(aad96[64:96], maskedEPKS[:])
	respPlain := []byte{0x02, 0x00, 0x01, 0x00}
	respCT := respAEAD.Seal(nil, nonce0[:], respPlain, aad96[:])
	require.Equal(t, "4882aaf223bc8333c5a0c6184ca6cd5ec7658a1a", hex.EncodeToString(respCT))
	openedResp, err := respAEAD.Open(nil, nonce0[:], respCT, aad96[:])
	require.NoError(t, err)
	require.Equal(t, respPlain, openedResp)

	// Vector 25: EncodeNonce(5, &nonce5)
	var nonce5 [AEADNonceSize]byte
	EncodeNonce(5, &nonce5)
	require.Equal(t, "000000000000000000000005", hex.EncodeToString(nonce5[:]))

	// Vector 26: NewDataAEAD AES-256-GCM (18B encrypted length header)
	aesAEAD, err := NewDataAEAD(CipherAES256GCM, keysA.C2SHeaderKey)
	require.NoError(t, err)
	lenPT := []byte{0x00, 0x42}
	aesCT := aesAEAD.Seal(nil, nonce5[:], lenPT, nil)
	require.Equal(t, "c00985665d956f030e74ad4d72804f65923b", hex.EncodeToString(aesCT))
	openedAES, err := aesAEAD.Open(nil, nonce5[:], aesCT, nil)
	require.NoError(t, err)
	require.Equal(t, lenPT, openedAES)

	// Vector 27: NewDataAEAD ChaCha20-Poly1305 (18B encrypted length header)
	chachaAEAD, err := NewDataAEAD(CipherChaCha20Poly1305, keysA.C2SHeaderKey)
	require.NoError(t, err)
	chachaCT := chachaAEAD.Seal(nil, nonce5[:], lenPT, nil)
	require.Equal(t, "7212bfbad161bce2c38e4d335b5cd7c654aa", hex.EncodeToString(chachaCT))
	openedChaCha, err := chachaAEAD.Open(nil, nonce5[:], chachaCT, nil)
	require.NoError(t, err)
	require.Equal(t, lenPT, openedChaCha)
}

func TestDerivePSK_BoundariesAndMalleabilityRejections(t *testing.T) {
	t.Parallel()

	_, err := DerivePSK("")
	require.ErrorIs(t, err, ErrEmptySecret)

	for length := 1; length < MinPassphraseLength; length++ {
		_, weakErr := DerivePSK(strings.Repeat("a", length))
		require.ErrorIs(t, weakErr, ErrWeakPassword, "length=%d", length)
	}

	// All-zero 32B Base64 in padded and unpadded forms MUST fail with ErrAllZeroKey (never fall through to Argon2id)
	var zero32 [32]byte
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		_, zeroErr := DerivePSK(enc.EncodeToString(zero32[:]))
		require.ErrorIs(t, zeroErr, ErrAllZeroKey)
	}

	// Base64 fast-path latency check: 1,000 strict Base64 decodes must stay far below Argon2id cost (>50s) even under -race + t.Parallel().
	const validB64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd+/8="
	start := time.Now()
	for range 1000 {
		_, fastErr := DerivePSK(validB64)
		require.NoError(t, fastErr)
	}
	require.Less(t, time.Since(start), 500*time.Millisecond)

	// Non-canonical trailing padding bit mutation ("...+/9=" vs "...+/8=") must NOT alias to the 32B Base64 key
	canonicalPSK, err := DerivePSK(validB64)
	require.NoError(t, err)
	mutatedPadPSK, err := DerivePSK("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd+/9=")
	require.NoError(t, err)
	require.NotEqual(t, canonicalPSK, mutatedPadPSK)

	// Embedded CR/LF in a 32B Base64 string must NOT alias to the canonical Base64 key
	withNewline := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd\n+/8="
	_, ok := decodeBase64Key32(withNewline)
	require.False(t, ok)
	newlinePSK, err := DerivePSK(withNewline)
	require.NoError(t, err)
	require.NotEqual(t, canonicalPSK, newlinePSK)

	// 32-char ASCII hex (24B Base64) and 44-char non-'=' string (33B Base64) must take Argon2id path cleanly
	hex32PSK, err := DerivePSK("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	require.False(t, isAllZero32(hex32PSK))

	ascii44PSK, err := DerivePSK("0123456789abcdef0123456789abcdef0123456789ab")
	require.NoError(t, err)
	require.False(t, isAllZero32(ascii44PSK))
}

func TestParseOutboundCredentials_SplittingAndEdgeCases(t *testing.T) {
	t.Parallel()

	const b64Server = "EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8="
	const b64User = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd+/8="
	const b64Zero = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	// Single Base64 credential
	c1, err := ParseOutboundCredentials(b64User)
	require.NoError(t, err)
	require.False(t, c1.HasServerPSK)
	require.Equal(t, [32]byte{}, c1.IPSK)
	require.Equal(t, mustHex32(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1dfbff"), c1.UPSK)
	require.Equal(t, mustHex16(t, "998a38f4e1515394497d30bc75249448"), c1.UserID)

	// Single passphrase containing colon where one side < 16 chars -> single credential
	cColonSingle, err := ParseOutboundCredentials("ab:cdefghijklmnopqrs")
	require.NoError(t, err)
	require.False(t, cColonSingle.HasServerPSK)

	// Multi-colon single passphrase where no split leaves >= 16 chars on both sides
	cMultiSingle, err := ParseOutboundCredentials("aether:sz:2026:transit")
	require.NoError(t, err)
	require.False(t, cMultiSingle.HasServerPSK)

	// Dual Base64 credentials "<iPSK>:<uPSK>"
	cDualB64, err := ParseOutboundCredentials(b64Server + ":" + b64User)
	require.NoError(t, err)
	require.True(t, cDualB64.HasServerPSK)
	require.Equal(t, mustHex32(t, "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"), cDualB64.IPSK)
	require.Equal(t, c1.UPSK, cDualB64.UPSK)
	require.Equal(t, c1.UserID, cDualB64.UserID)

	// Dual passphrases "<16+>:<16+>"
	cDualPass, err := ParseOutboundCredentials("AetherV2-TestKey:DedicatedLine-Secret-001")
	require.NoError(t, err)
	require.True(t, cDualPass.HasServerPSK)
	require.Equal(t, mustHex32(t, "eeb853fabf4168e7bf4c37b42c9f0e95b7b3abe6a3174f1ed9993af8739d476f"), cDualPass.IPSK)
	require.Equal(t, mustHex32(t, "053d012dd9c7d2b906cf72d5e6649af6daede7c0d82fe616a38f4a7d99253d4c"), cDualPass.UPSK)

	// Multi-colon with Base64 on left or right -> unambiguous split
	cLeftB64Multi, err := ParseOutboundCredentials(b64Server + ":node:sz:prod:secret:2026")
	require.NoError(t, err)
	require.True(t, cLeftB64Multi.HasServerPSK)
	require.Equal(t, cDualB64.IPSK, cLeftB64Multi.IPSK)

	cRightB64Multi, err := ParseOutboundCredentials("node:sz:prod:secret:2026:" + b64User)
	require.NoError(t, err)
	require.True(t, cRightB64Multi.HasServerPSK)
	require.Equal(t, c1.UPSK, cRightB64Multi.UPSK)

	// Multi-colon ambiguous passphrase split -> ErrAmbiguousCredentials
	_, err = ParseOutboundCredentials("aaaa-bbbb-cccc-dddd:eeee:ffff-gggg-hhhh-iiii")
	require.ErrorIs(t, err, ErrAmbiguousCredentials)

	// Negative cases: empty, short:short, b64:short, short:b64, b64:empty, and all-zero Base64 never swallowed!
	_, err = ParseOutboundCredentials("")
	require.ErrorIs(t, err, ErrEmptySecret)

	_, err = ParseOutboundCredentials("short:short")
	require.ErrorIs(t, err, ErrWeakPassword)

	_, err = ParseOutboundCredentials(b64Server + ":short")
	require.ErrorIs(t, err, ErrWeakPassword)

	_, err = ParseOutboundCredentials("short:" + b64User)
	require.ErrorIs(t, err, ErrWeakPassword)

	_, err = ParseOutboundCredentials(b64Server + ":")
	require.ErrorIs(t, err, ErrEmptySecret)

	_, err = ParseOutboundCredentials(b64Server + ":" + b64Zero)
	require.ErrorIs(t, err, ErrAllZeroKey)

	_, err = ParseOutboundCredentials("AetherV2-TestKey:" + b64Zero)
	require.ErrorIs(t, err, ErrAllZeroKey)
}

func TestUserTable_LookupAndDuplicateRejection(t *testing.T) {
	t.Parallel()

	var nilTable *UserTable
	require.Equal(t, 0, nilTable.Len())
	require.Nil(t, nilTable.Users())
	_, ok := nilTable.Lookup([16]byte{})
	require.False(t, ok)
	_, ok = nilTable.LookupEIH([32]byte{}, [32]byte{}, [16]byte{})
	require.False(t, ok)

	_, err := NewUserTable(nil)
	require.ErrorIs(t, err, ErrEmptyUserTable)

	const keyAliceStd = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd+/8="
	const keyAliceRawURL = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd-_8"
	const keyBobStd = "EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8="

	table, err := NewUserTable([]option.AetherUser{
		{Name: "alice", Key: keyAliceStd},
		{Name: "bob", Password: keyBobStd},
	})
	require.NoError(t, err)
	require.Equal(t, 2, table.Len())
	require.Len(t, table.Users(), 2)
	require.Equal(t, "alice", table.Users()[0].Name)
	require.Equal(t, 0, table.Users()[0].Index)
	require.Equal(t, "bob", table.Users()[1].Name)
	require.Equal(t, 1, table.Users()[1].Index)

	iPSK, err := DerivePSK("DedicatedLine-Secret-001")
	require.NoError(t, err)
	salt, err := GenerateRandomSalt()
	require.NoError(t, err)
	eihAlice := MaskEIH(iPSK, salt, table.Users()[0].UserID)
	rec, found := table.LookupEIH(iPSK, salt, eihAlice)
	require.True(t, found)
	require.Equal(t, "alice", rec.Name)

	var unknownEIH [16]byte
	unknownEIH[0] = eihAlice[0] ^ 0xff
	_, found = table.LookupEIH(iPSK, salt, unknownEIH)
	require.False(t, found)

	// Duplicate user name (including empty "")
	_, err = NewUserTable([]option.AetherUser{
		{Name: "alice", Key: keyAliceStd},
		{Name: "alice", Key: keyBobStd},
	})
	require.ErrorIs(t, err, ErrDuplicateUserName)

	_, err = NewUserTable([]option.AetherUser{
		{Name: "", Key: keyAliceStd},
		{Name: "", Key: keyBobStd},
	})
	require.ErrorIs(t, err, ErrDuplicateUserName)

	// Duplicate uPSK across different Base64 encodings (Std vs RawURL)
	_, err = NewUserTable([]option.AetherUser{
		{Name: "alice", Key: keyAliceStd},
		{Name: "alice-url", Key: keyAliceRawURL},
	})
	require.ErrorIs(t, err, ErrDuplicateUserKey)

	// Conflicting Password and Key on user
	_, err = NewUserTable([]option.AetherUser{
		{Name: "conflict", Password: keyAliceStd, Key: keyBobStd},
	})
	require.ErrorContains(t, err, "conflicting password and key")
}

func TestX25519Keys_FourEncodingsClampedZeroAndAll14LowOrderPoints(t *testing.T) {
	t.Parallel()

	rawPriv := mustHex32(t, "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
	rawPub := mustHex32(t, "23b7bb8c91ae008711fb12846780bcdf1e065f821bdfec49f57e7c7dcd4c4823")

	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		priv, err := ParseX25519PrivateKey(enc.EncodeToString(rawPriv[:]))
		require.NoError(t, err)
		pub, err := ParseX25519PublicKey(enc.EncodeToString(rawPub[:]))
		require.NoError(t, err)
		require.True(t, priv.PublicKey().Equal(pub))
	}

	// Reject empty, wrong lengths, non-canonical Base64, and nil ECDH args
	for _, bad := range []string{"", "abcd", base64.StdEncoding.EncodeToString(make([]byte, 31)), base64.StdEncoding.EncodeToString(make([]byte, 33))} {
		_, err := ParseX25519PrivateKey(bad)
		require.ErrorIs(t, err, ErrInvalidX25519Key)
		_, err = ParseX25519PublicKey(bad)
		require.ErrorIs(t, err, ErrInvalidX25519Key)
	}
	_, err := ComputeECDH(nil, nil)
	require.ErrorIs(t, err, ErrInvalidX25519Key)
	_, err = UnmaskAndECDH(nil, [32]byte{}, [32]byte{}, [32]byte{})
	require.ErrorIs(t, err, ErrInvalidX25519Key)

	// Reject all-zero and clamped-zero variable-bit private keys
	clampedZeroPrivInputs := [][32]byte{
		{},
		{0: 0x01},
		{0: 0x07},
		{31: 0x40},
		{31: 0x80},
		{0: 0x07, 31: 0xc0},
	}
	for i, badPriv := range clampedZeroPrivInputs {
		_, parseErr := ParseX25519PrivateKey(base64.StdEncoding.EncodeToString(badPriv[:]))
		require.ErrorIs(t, parseErr, ErrInvalidX25519Key, "case %d", i)
		require.ErrorIs(t, parseErr, ErrAllZeroKey, "case %d", i)
	}

	// Reject all 14 Curve25519 & quadratic-twist low-order points at BOTH startup and runtime ECDH
	validPriv, err := ParseX25519PrivateKey(base64.StdEncoding.EncodeToString(rawPriv[:]))
	require.NoError(t, err)
	uPSK := mustHex32(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1dfbff")
	salt := mustHex32(t, "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf")

	require.Len(t, all14X25519LowOrderPointsHex, 14)
	for idx, ptHex := range all14X25519LowOrderPointsHex {
		pt := mustHex32(t, ptHex)
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding,
			base64.RawStdEncoding,
			base64.URLEncoding,
			base64.RawURLEncoding,
		} {
			_, pubErr := ParseX25519PublicKey(enc.EncodeToString(pt[:]))
			require.ErrorIs(t, pubErr, ErrInvalidX25519Key, "point #%d", idx)
			require.ErrorIs(t, pubErr, ErrLowOrderX25519Point, "point #%d", idx)
		}

		stdlibPub, newErr := ecdh.X25519().NewPublicKey(pt[:])
		require.NoError(t, newErr)
		_, ecdhErr := ComputeECDH(validPriv, stdlibPub)
		require.ErrorIs(t, ecdhErr, ErrLowOrderX25519Point, "point #%d", idx)

		maskedLowOrder := MaskEPK(uPSK, salt, pt)
		_, unmaskECDHErr := UnmaskAndECDH(validPriv, uPSK, salt, maskedLowOrder)
		require.ErrorIs(t, unmaskECDHErr, ErrLowOrderX25519Point, "point #%d", idx)
	}
}

func TestMaskedEPK_StatisticalUniformityAndPositiveControl(t *testing.T) {
	t.Parallel()

	const samples = 2000
	uPSK, err := DerivePSK("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd+/8=")
	require.NoError(t, err)

	var (
		unmaskedClientMSBOnes int
		unmaskedServerMSBOnes int
		rawClientByte31Counts [256]int

		maskedClientMSBOnes  int
		maskedServerMSBOnes  int
		maskedClientBitOnes  [256]int
		maskedServerBitOnes  [256]int
		maskedClientByteHist [32][256]int
		maskedServerByteHist [32][256]int
		pooledByteHist       [256]int
	)

	for range samples {
		clientSalt, saltErr := GenerateRandomSalt()
		require.NoError(t, saltErr)
		serverSalt, saltErr := GenerateRandomSalt()
		require.NoError(t, saltErr)

		ekC, maskedClientEPK, genErr := GenerateMaskedEPK(uPSK, clientSalt)
		require.NoError(t, genErr)
		ekS, maskedServerEPK, genErr := GenerateMaskedEPK(uPSK, serverSalt)
		require.NoError(t, genErr)

		rawClient := ekC.PublicKey().Bytes()
		rawServer := ekS.PublicKey().Bytes()

		// Round-trip verification
		recoveredC, recErr := UnmaskEPK(uPSK, clientSalt, maskedClientEPK)
		require.NoError(t, recErr)
		require.True(t, recoveredC.Equal(ekC.PublicKey()))

		recoveredS, recErr := UnmaskEPK(uPSK, serverSalt, maskedServerEPK)
		require.NoError(t, recErr)
		require.True(t, recoveredS.Equal(ekS.PublicKey()))

		// Positive control on raw X25519 public keys
		if rawClient[31]&0x80 != 0 {
			unmaskedClientMSBOnes++
		}
		if rawServer[31]&0x80 != 0 {
			unmaskedServerMSBOnes++
		}
		rawClientByte31Counts[rawClient[31]]++

		// Masked MSB & all-256-bits & per-byte histograms
		if maskedClientEPK[31]&0x80 != 0 {
			maskedClientMSBOnes++
		}
		if maskedServerEPK[31]&0x80 != 0 {
			maskedServerMSBOnes++
		}

		for j := range 32 {
			cb := maskedClientEPK[j]
			sb := maskedServerEPK[j]
			maskedClientByteHist[j][cb]++
			maskedServerByteHist[j][sb]++
			pooledByteHist[cb]++
			for bit := range 8 {
				if cb&(1<<bit) != 0 {
					maskedClientBitOnes[j*8+bit]++
				}
				if sb&(1<<bit) != 0 {
					maskedServerBitOnes[j*8+bit]++
				}
			}
		}
	}

	// 1. Positive Control: raw X25519 bit 255 is ALWAYS 0 and byte 31 chi-squared >> 1800
	require.Equal(t, 0, unmaskedClientMSBOnes)
	require.Equal(t, 0, unmaskedServerMSBOnes)

	const expectedPerBin = float64(samples) / 256.0 // 7.8125
	var unmaskedByte31Chi2 float64
	for v := range 256 {
		diff := float64(rawClientByte31Counts[v]) - expectedPerBin
		unmaskedByte31Chi2 += (diff * diff) / expectedPerBin
	}
	require.Greater(t, unmaskedByte31Chi2, 1800.0, "positive control must strongly reject unmasked X25519 byte 31")

	// 2. Masked bit-255 binomial test (N=2000, mu=1000, sigma=22.36 -> [888, 1112], 5.0*sigma)
	require.GreaterOrEqual(t, maskedClientMSBOnes, 888)
	require.LessOrEqual(t, maskedClientMSBOnes, 1112)
	require.GreaterOrEqual(t, maskedServerMSBOnes, 888)
	require.LessOrEqual(t, maskedServerMSBOnes, 1112)

	// 3. All 256 bit positions across client and server masked EPKs within [870, 1130] (FWER < 3.2e-6)
	for b := range 256 {
		require.GreaterOrEqual(t, maskedClientBitOnes[b], 870, "client bit %d", b)
		require.LessOrEqual(t, maskedClientBitOnes[b], 1130, "client bit %d", b)
		require.GreaterOrEqual(t, maskedServerBitOnes[b], 870, "server bit %d", b)
		require.LessOrEqual(t, maskedServerBitOnes[b], 1130, "server bit %d", b)
	}

	// 4. FWER-calibrated 64-column Pearson chi-squared test (df=255 -> [145.0, 405.0], FWER < 1e-6)
	for j := range 32 {
		var chi2Client, chi2Server float64
		for v := range 256 {
			dc := float64(maskedClientByteHist[j][v]) - expectedPerBin
			chi2Client += (dc * dc) / expectedPerBin
			ds := float64(maskedServerByteHist[j][v]) - expectedPerBin
			chi2Server += (ds * ds) / expectedPerBin
		}
		require.GreaterOrEqual(t, chi2Client, 145.0, "client byte %d chi2=%f", j, chi2Client)
		require.LessOrEqual(t, chi2Client, 405.0, "client byte %d chi2=%f", j, chi2Client)
		require.GreaterOrEqual(t, chi2Server, 145.0, "server byte %d chi2=%f", j, chi2Server)
		require.LessOrEqual(t, chi2Server, 405.0, "server byte %d chi2=%f", j, chi2Server)
	}

	// 5. Pooled 64,000-byte chi-squared test (E=250.0, df=255 -> [150.0, 400.0])
	const pooledExpected = float64(32*samples) / 256.0 // 250.0
	var pooledChi2 float64
	for v := range 256 {
		d := float64(pooledByteHist[v]) - pooledExpected
		pooledChi2 += (d * d) / pooledExpected
	}
	require.GreaterOrEqual(t, pooledChi2, 150.0)
	require.LessOrEqual(t, pooledChi2, 400.0)
}

func TestServerAuthenticator_AllThreeModesTamperAnd0RTTStaticMismatch(t *testing.T) {
	t.Parallel()

	const (
		serverKeyB64 = "EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8="
		user0KeyB64  = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd+/8="
		user1KeyB64  = "ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA="
		user2KeyB64  = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
		staticSkB64  = "cHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo8="
		staticPubB64 = "I7e7jJGuAIcR+xKEZ4C83x4GX4Ib3+xJ9X58fc1MSCM="
	)

	usersCfg := []option.AetherUser{
		{Name: "alice", Key: user0KeyB64},
		{Name: "bob", Key: user1KeyB64},
		{Name: "charlie", Key: user2KeyB64},
	}

	staticPub, err := ParseX25519PublicKey(staticPubB64)
	require.NoError(t, err)

	// Missing both server secret and users must fail
	_, err = NewServerAuthenticator("", nil, "")
	require.ErrorIs(t, err, ErrMissingInboundSecret)
	require.ErrorIs(t, err, ErrEmptySecret)

	for _, withStatic := range []bool{false, true} {
		privOpt := ""
		var pubKey *ecdh.PublicKey
		if withStatic {
			privOpt = staticSkB64
			pubKey = staticPub
		}

		// 1. SingleUser mode (96B)
		authSingle, err := NewServerAuthenticatorFromOptions(option.AetherInboundOptions{
			Key:              user0KeyB64,
			ServerPrivateKey: privOpt,
		})
		require.NoError(t, err)
		require.Equal(t, AuthModeSingleUser, authSingle.Mode())
		require.Equal(t, withStatic, authSingle.HasStaticKey())
		require.Equal(t, ClientPrefixNoEIHSize, authSingle.ClientPrefixSize())

		credsSingle, err := ParseOutboundCredentials(user0KeyB64)
		require.NoError(t, err)
		runFullHandshakeAndDataCheck(t, authSingle, credsSingle, pubKey, CipherAES256GCM, "", -1)
		runFullHandshakeAndDataCheck(t, authSingle, credsSingle, pubKey, CipherChaCha20Poly1305, "", -1)

		// 2. MultiUserEIH mode (112B)
		authEIH, err := NewServerAuthenticatorFromOptions(option.AetherInboundOptions{
			Password:         serverKeyB64,
			Users:            usersCfg,
			ServerPrivateKey: privOpt,
		})
		require.NoError(t, err)
		require.Equal(t, AuthModeMultiUserEIH, authEIH.Mode())
		require.Equal(t, ClientPrefixEIHSize, authEIH.ClientPrefixSize())

		for idx, u := range usersCfg {
			credsEIH, credErr := ParseOutboundCredentials(serverKeyB64 + ":" + u.Key)
			require.NoError(t, credErr)
			runFullHandshakeAndDataCheck(t, authEIH, credsEIH, pubKey, CipherAES256GCM, u.Name, idx)
		}

		// Revoked user who still possesses valid shared iPSK (EIH miss -> constant-time dummy fallback!)
		revokedCreds, err := ParseOutboundCredentials(serverKeyB64 + ":DedicatedLine-Secret-001")
		require.NoError(t, err)
		_, revokedPrefix, err := StartClientHandshake(revokedCreds, pubKey, [16]byte{0x02, 0x01, 0x01})
		require.NoError(t, err)
		_, _, err = authEIH.OpenClientFixedPrefix(revokedPrefix)
		require.ErrorIs(t, err, ErrAuthenticationFailed)

		// 3. MultiUserDirect mode (96B, first, middle, and last user without early break)
		authDirect, err := NewServerAuthenticatorFromOptions(option.AetherInboundOptions{
			Users:            usersCfg,
			ServerPrivateKey: privOpt,
		})
		require.NoError(t, err)
		require.Equal(t, AuthModeMultiUserDirect, authDirect.Mode())
		require.Equal(t, ClientPrefixNoEIHSize, authDirect.ClientPrefixSize())

		for idx, u := range usersCfg {
			credsDirect, credErr := ParseOutboundCredentials(u.Key)
			require.NoError(t, credErr)
			runFullHandshakeAndDataCheck(t, authDirect, credsDirect, pubKey, CipherChaCha20Poly1305, u.Name, idx)
		}

		// Unknown user in MultiUserDirect fails after full scan
		unknownDirectCreds, err := ParseOutboundCredentials("DedicatedLine-Secret-001")
		require.NoError(t, err)
		_, unknownDirectPrefix, err := StartClientHandshake(unknownDirectCreds, pubKey, [16]byte{0x02, 0x01, 0x02})
		require.NoError(t, err)
		_, _, err = authDirect.OpenClientFixedPrefix(unknownDirectPrefix)
		require.ErrorIs(t, err, ErrAuthenticationFailed)
	}

	// 4. Static 0-RTT PFS Mismatch Rejections
	authWithStatic, err := NewServerAuthenticator(user0KeyB64, nil, staticSkB64)
	require.NoError(t, err)
	authWithoutStatic, err := NewServerAuthenticator(user0KeyB64, nil, "")
	require.NoError(t, err)
	creds0, err := ParseOutboundCredentials(user0KeyB64)
	require.NoError(t, err)

	// Client omits public_key while server requires private_key -> rejected
	_, prefixNoStatic, err := StartClientHandshake(creds0, nil, [16]byte{0x02, 0x01, 0x01})
	require.NoError(t, err)
	_, _, err = authWithStatic.OpenClientFixedPrefix(prefixNoStatic)
	require.ErrorIs(t, err, ErrAuthenticationFailed)

	// Client sets public_key while server has no private_key -> rejected
	_, prefixWithStatic, err := StartClientHandshake(creds0, staticPub, [16]byte{0x02, 0x01, 0x01})
	require.NoError(t, err)
	_, _, err = authWithoutStatic.OpenClientFixedPrefix(prefixWithStatic)
	require.ErrorIs(t, err, ErrAuthenticationFailed)

	// Client sets WRONG static public_key -> rejected
	wrongPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, prefixWrongStatic, err := StartClientHandshake(creds0, wrongPriv.PublicKey(), [16]byte{0x02, 0x01, 0x01})
	require.NoError(t, err)
	_, _, err = authWithStatic.OpenClientFixedPrefix(prefixWrongStatic)
	require.ErrorIs(t, err, ErrAuthenticationFailed)

	// 5. Runtime Low-Order EPK Injection by Adversary Knowing Valid uPSK
	for _, ptHex := range all14X25519LowOrderPointsHex {
		pt := mustHex32(t, ptHex)
		salt, saltErr := GenerateRandomSalt()
		require.NoError(t, saltErr)
		maskedLowOrder := MaskEPK(creds0.UPSK, salt, pt)

		// Against non-static server: rejected either at OpenClientFixedPrefix (if all-zero) or Complete (non-zero low-order)
		initAEAD, initErr := DeriveClientInitAEAD(creds0.UPSK, salt, nil)
		require.NoError(t, initErr)
		var craftedPrefix [ClientPrefixNoEIHSize]byte
		copy(craftedPrefix[0:32], salt[:])
		copy(craftedPrefix[32:64], maskedLowOrder[:])
		var n0 [AEADNonceSize]byte
		EncodeNonce(0, &n0)
		var fixedHdr [16]byte
		fixedHdr[0] = ProtocolVersion
		fixedHdr[1] = 0x01
		fixedHdr[2] = CipherAES256GCM
		initAEAD.Seal(craftedPrefix[64:64], n0[:], fixedHdr[:], craftedPrefix[0:64])

		hs, _, openErr := authWithoutStatic.OpenClientFixedPrefix(craftedPrefix[:])
		if openErr == nil {
			_, _, _, compErr := hs.Complete(CipherAES256GCM, [4]byte{0x02, 0x00, CipherAES256GCM, 0x00})
			require.ErrorIs(t, compErr, ErrLowOrderX25519Point)
		} else {
			require.ErrorIs(t, openErr, ErrAuthenticationFailed)
		}
	}
}

func runFullHandshakeAndDataCheck(
	t *testing.T,
	auth *ServerAuthenticator,
	creds ClientCredentials,
	serverStaticPub *ecdh.PublicKey,
	suite uint8,
	expectedUser string,
	expectedIndex int,
) {
	t.Helper()

	var fixedPlain [FixedHeaderPlainSize]byte
	fixedPlain[0] = ProtocolVersion
	fixedPlain[1] = 0x01
	fixedPlain[2] = suite
	binary.BigEndian.PutUint64(fixedPlain[4:12], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint16(fixedPlain[12:14], 32)
	binary.BigEndian.PutUint16(fixedPlain[14:16], 64)

	clientHS, prefix, err := StartClientHandshake(creds, serverStaticPub, fixedPlain)
	require.NoError(t, err)
	require.Len(t, prefix, auth.ClientPrefixSize())

	// Bit-flip anywhere in prefix (Salt, MaskedClientEPK, [EIH], EncryptedFixedHeader) must fail authentication
	for _, byteIdx := range []int{0, 31, 32, 63, len(prefix) - 17, len(prefix) - 1} {
		tampered := append([]byte(nil), prefix...)
		tampered[byteIdx] ^= 0x01
		_, _, tamperErr := auth.OpenClientFixedPrefix(tampered)
		require.ErrorIs(t, tamperErr, ErrAuthenticationFailed)
	}

	serverHS, gotFixed, err := auth.OpenClientFixedPrefix(prefix)
	require.NoError(t, err)
	require.Equal(t, fixedPlain, gotFixed)
	require.Equal(t, expectedUser, serverHS.UserName)
	require.Equal(t, expectedIndex, serverHS.UserIndex)
	require.Equal(t, clientHS.ClientSalt(), serverHS.ClientSalt)

	// VarHeader Seal -> Tamper fail -> Open -> Replay OpenVarHeader rejected
	varPlain := []byte("noise-padding-and-socksaddr-and-0rtt-payload")
	varCipher := clientHS.SealVarHeader(nil, varPlain)
	tamperedVar := append([]byte(nil), varCipher...)
	tamperedVar[0] ^= 0x80
	_, err = serverHS.OpenVarHeader(nil, tamperedVar)
	require.ErrorIs(t, err, ErrAuthenticationFailed)

	openedVar, err := serverHS.OpenVarHeader(nil, varCipher)
	require.NoError(t, err)
	require.Equal(t, varPlain, openedVar)
	_, err = serverHS.OpenVarHeader(nil, varCipher)
	require.ErrorIs(t, err, ErrAuthenticationFailed, "second OpenVarHeader must be rejected")

	// Server Complete -> Tamper fail -> Client Complete
	respPlain := [RespHeaderPlainSize]byte{ProtocolVersion, 0x00, suite, 0x00}
	respPrefix, serverSend, serverRecv, err := serverHS.Complete(suite, respPlain)
	require.NoError(t, err)

	for _, idx := range []int{0, 32, 64, 83} {
		badResp := respPrefix
		badResp[idx] ^= 0x01
		_, _, _, badErr := clientHS.Complete(badResp[:], suite)
		require.Error(t, badErr)
	}

	gotResp, clientSend, clientRecv, err := clientHS.Complete(respPrefix[:], suite)
	require.NoError(t, err)
	require.Equal(t, respPlain, gotResp)

	// Verify C2S and S2C DirectionalCipher symmetry
	c2sBody := []byte{0x01, 0x00, 'h', 'e', 'l', 'l', 'o'}
	wireC2S, err := clientSend.SealFrame(nil, c2sBody)
	require.NoError(t, err)
	c2sLen, err := serverRecv.OpenLengthHeader(wireC2S[:EncryptedLengthSize])
	require.NoError(t, err)
	require.Equal(t, uint16(len(c2sBody)), c2sLen)
	gotC2S, err := serverRecv.OpenPayloadBody(nil, wireC2S[EncryptedLengthSize:])
	require.NoError(t, err)
	require.Equal(t, c2sBody, gotC2S)

	// Cross-direction key isolation check: C2S frame CANNOT be opened by clientRecv (S2C)
	_, err = clientRecv.OpenLengthHeader(wireC2S[:EncryptedLengthSize])
	require.Error(t, err)

	s2cBody := []byte{0x01, 0x00, 'w', 'o', 'r', 'l', 'd'}
	wireS2C, err := serverSend.SealFrame(nil, s2cBody)
	require.NoError(t, err)
	s2cLen, err := clientRecv.OpenLengthHeader(wireS2C[:EncryptedLengthSize])
	require.NoError(t, err)
	require.Equal(t, uint16(len(s2cBody)), s2cLen)
	gotS2C, err := clientRecv.OpenPayloadBody(nil, wireS2C[EncryptedLengthSize:])
	require.NoError(t, err)
	require.Equal(t, s2cBody, gotS2C)
}

func TestEncodeNonceCipherSelectionAndDirectionalCipherZeroAlloc(t *testing.T) {

	// EncodeNonce must zero bytes 0..3 even when dst contains dirty 0xff bytes
	dst := [AEADNonceSize]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	EncodeNonce(0x0102030405060708, &dst)
	require.Equal(t, "000000000102030405060708", hex.EncodeToString(dst[:]))
	EncodeNonce(math.MaxUint64, &dst)
	require.Equal(t, "00000000ffffffffffffffff", hex.EncodeToString(dst[:]))

	// Cipher suite selection & error contract ("unsupported aether cipher")
	suite, err := selectCipherSuiteWithHardware("", true)
	require.NoError(t, err)
	require.Equal(t, CipherAES256GCM, suite)

	suite, err = selectCipherSuiteWithHardware("auto", false)
	require.NoError(t, err)
	require.Equal(t, CipherChaCha20Poly1305, suite)

	suite, err = SelectCipherSuite("aes-256-gcm")
	require.NoError(t, err)
	require.Equal(t, CipherAES256GCM, suite)

	suite, err = SelectCipherSuite("chacha20-poly1305")
	require.NoError(t, err)
	require.Equal(t, CipherChaCha20Poly1305, suite)

	_, err = SelectCipherSuite("aes-128-gcm")
	require.Error(t, err)
	require.ErrorContains(t, err, "unsupported aether cipher")

	require.True(t, IsValidCipherSuite(CipherAES256GCM))
	require.True(t, IsValidCipherSuite(CipherChaCha20Poly1305))
	require.False(t, IsValidCipherSuite(0x00))
	require.False(t, IsValidCipherSuite(0xff))

	_, err = NewDataAEAD(0xff, [32]byte{})
	require.ErrorIs(t, err, ErrUnsupportedCipherSuite)

	// DirectionalCipher bounds, nonce exhaustion, and 0 allocs/op check
	hdrKey := mustHex32(t, "26daf3f0067dba1ccfdc08c0ccfefa93ca2bc66f120b47231e36da28d01d4a2c")
	payKey := mustHex32(t, "e983abacfcc4ca33b2d4653960272b55bb726d92e3a04380007144c131c50e9a")

	for _, s := range []uint8{CipherAES256GCM, CipherChaCha20Poly1305} {
		sender, sErr := NewDirectionalCipher(s, hdrKey, payKey)
		require.NoError(t, sErr)
		receiver, rErr := NewDirectionalCipher(s, hdrKey, payKey)
		require.NoError(t, rErr)
		require.Equal(t, s, sender.Suite())

		// Bounds rejections (< 2B and > 16641B)
		_, err = sender.SealFrame(nil, []byte{0x01})
		require.ErrorIs(t, err, ErrInvalidFrameLength)
		_, err = sender.SealFrame(nil, make([]byte, MaxFramePlainSize+1))
		require.ErrorIs(t, err, ErrInvalidFrameLength)

		payload := make([]byte, 1400)
		payload[0] = 0x01
		wireBuf := make([]byte, 0, EncryptedLengthSize+len(payload)+AEADTagSize)
		plainBuf := make([]byte, 0, len(payload))

		allocs := testing.AllocsPerRun(200, func() {
			sealed, sealErr := sender.SealFrame(wireBuf[:0], payload)
			if sealErr != nil {
				t.Fatal(sealErr)
			}
			bodyLen, lenErr := receiver.OpenLengthHeader(sealed[:EncryptedLengthSize])
			if lenErr != nil || int(bodyLen) != len(payload) {
				t.Fatal(lenErr)
			}
			opened, openErr := receiver.OpenPayloadBody(plainBuf[:0], sealed[EncryptedLengthSize:])
			if openErr != nil || len(opened) != len(payload) {
				t.Fatal(openErr)
			}
		})
		require.Equal(t, float64(0), allocs, "suite=0x%02x must allocate 0 B/op", s)

		// Exhausted sequence number check
		sender.seq = math.MaxUint64
		_, err = sender.SealFrame(wireBuf[:0], payload)
		require.ErrorIs(t, err, ErrNonceExhausted)
		receiver.seq = math.MaxUint64
		_, err = receiver.OpenLengthHeader(make([]byte, EncryptedLengthSize))
		require.ErrorIs(t, err, ErrNonceExhausted)
		_, err = receiver.OpenPayloadBody(nil, make([]byte, MinFramePlainSize+AEADTagSize))
		require.ErrorIs(t, err, ErrNonceExhausted)
	}
}

func BenchmarkDirectionalCipher_AES256GCM(b *testing.B) {
	benchmarkDirectionalCipherSuite(b, CipherAES256GCM)
}

func BenchmarkDirectionalCipher_ChaCha20Poly1305(b *testing.B) {
	benchmarkDirectionalCipherSuite(b, CipherChaCha20Poly1305)
}

func benchmarkDirectionalCipherSuite(b *testing.B, suite uint8) {
	var hdrKey, payKey [32]byte
	hdrKey[0] = 1
	payKey[0] = 2
	sender, err := NewDirectionalCipher(suite, hdrKey, payKey)
	if err != nil {
		b.Fatal(err)
	}
	receiver, err := NewDirectionalCipher(suite, hdrKey, payKey)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 1400)
	payload[0] = 0x01
	wireBuf := make([]byte, 0, EncryptedLengthSize+len(payload)+AEADTagSize)
	plainBuf := make([]byte, 0, len(payload))

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		sealed, sealErr := sender.SealFrame(wireBuf[:0], payload)
		if sealErr != nil {
			b.Fatal(sealErr)
		}
		if _, lenErr := receiver.OpenLengthHeader(sealed[:EncryptedLengthSize]); lenErr != nil {
			b.Fatal(lenErr)
		}
		if _, openErr := receiver.OpenPayloadBody(plainBuf[:0], sealed[EncryptedLengthSize:]); openErr != nil {
			b.Fatal(openErr)
		}
	}
}

func BenchmarkMaskEPK(b *testing.B) {
	var uPSK, salt, epk [32]byte
	uPSK[0] = 0xaa
	salt[0] = 0xbb
	epk[0] = 0xcc
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		epk = MaskEPK(uPSK, salt, epk)
	}
}
