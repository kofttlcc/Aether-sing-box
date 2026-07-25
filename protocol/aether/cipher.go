package aether

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	SaltSize       = 32
	KeySize        = 32
	TagSize        = chacha20poly1305.Overhead // 16 bytes
	NonceSize      = chacha20poly1305.NonceSize // 12 bytes
	HKDFInfoString = "AetherFlow-v1-Session-Subkey"
)

var (
	ErrInvalidTag     = errors.New("aether: AEAD authentication tag verification failed")
	ErrShortBuffer    = errors.New("aether: buffer too short")
	ErrReplayDetected = errors.New("aether: potential replay attack detected")
	ErrInvalidHeader  = errors.New("aether: invalid protocol header")
)

type CipherSession struct {
	clientKey [KeySize]byte
	serverKey [KeySize]byte
	maskKey   [16]byte

	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD

	sendNonce uint64
	recvNonce uint64
}

func GenerateSalt() ([SaltSize]byte, error) {
	var salt [SaltSize]byte
	_, err := io.ReadFull(rand.Reader, salt[:])
	return salt, err
}

func KeyFromPassword(password string) [KeySize]byte {
	return sha256.Sum256([]byte(password))
}

func NewCipherSession(psk [KeySize]byte, salt [SaltSize]byte, isClient bool) (*CipherSession, error) {
	kdf := hkdf.New(sha256.New, psk[:], salt[:], []byte(HKDFInfoString))

	var derived [80]byte
	if _, err := io.ReadFull(kdf, derived[:]); err != nil {
		return nil, fmt.Errorf("hkdf key derivation failed: %w", err)
	}

	cs := &CipherSession{}
	copy(cs.clientKey[:], derived[0:32])
	copy(cs.serverKey[:], derived[32:64])
	copy(cs.maskKey[:], derived[64:80])

	var sendKey, recvKey []byte
	if isClient {
		sendKey = cs.clientKey[:]
		recvKey = cs.serverKey[:]
	} else {
		sendKey = cs.serverKey[:]
		recvKey = cs.clientKey[:]
	}

	var err error
	cs.sendAEAD, err = chacha20poly1305.New(sendKey)
	if err != nil {
		return nil, fmt.Errorf("failed to init send AEAD: %w", err)
	}

	cs.recvAEAD, err = chacha20poly1305.New(recvKey)
	if err != nil {
		return nil, fmt.Errorf("failed to init recv AEAD: %w", err)
	}

	return cs, nil
}

func (cs *CipherSession) MaskKey() [16]byte {
	return cs.maskKey
}

func (cs *CipherSession) EncryptChunk(dst, plaintext []byte) []byte {
	var nonceBuf [NonceSize]byte
	encodeNonce(cs.sendNonce, nonceBuf[:])
	cs.sendNonce++

	return cs.sendAEAD.Seal(dst, nonceBuf[:], plaintext, nil)
}

func (cs *CipherSession) DecryptChunk(dst, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < TagSize {
		return nil, ErrShortBuffer
	}

	var nonceBuf [NonceSize]byte
	encodeNonce(cs.recvNonce, nonceBuf[:])

	plaintext, err := cs.recvAEAD.Open(dst, nonceBuf[:], ciphertext, nil)
	if err != nil {
		return nil, ErrInvalidTag
	}

	cs.recvNonce++
	return plaintext, nil
}

func encodeNonce(seq uint64, dst []byte) {
	dst[0] = byte(seq)
	dst[1] = byte(seq >> 8)
	dst[2] = byte(seq >> 16)
	dst[3] = byte(seq >> 24)
	dst[4] = byte(seq >> 32)
	dst[5] = byte(seq >> 40)
	dst[6] = byte(seq >> 48)
	dst[7] = byte(seq >> 56)
}
