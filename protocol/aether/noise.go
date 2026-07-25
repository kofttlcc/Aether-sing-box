package aether

import (
	"crypto/rand"
	"math/big"
)

const (
	MinNoisePadding = 16
	MaxNoisePadding = 128
)

func GenerateRandomNoise(minLen, maxLen int) ([]byte, error) {
	if minLen < 0 || maxLen < minLen {
		minLen = MinNoisePadding
		maxLen = MaxNoisePadding
	}

	rangeSize := big.NewInt(int64(maxLen - minLen + 1))
	nBig, err := rand.Int(rand.Reader, rangeSize)
	if err != nil {
		return nil, err
	}
	length := int(nBig.Int64()) + minLen

	noise := make([]byte, length)
	if _, err := rand.Read(noise); err != nil {
		return nil, err
	}

	return noise, nil
}

func MaskLength(length uint16, maskKey [16]byte, seq uint64) uint16 {
	k0 := maskKey[seq%15]
	k1 := maskKey[(seq+1)%16]
	mask := uint16(k0) | (uint16(k1) << 8)
	return length ^ mask
}

func UnmaskLength(maskedLength uint16, maskKey [16]byte, seq uint64) uint16 {
	return MaskLength(maskedLength, maskKey, seq)
}
