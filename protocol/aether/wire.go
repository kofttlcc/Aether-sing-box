package aether

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// Aether v2 command identifiers carried in the encrypted FixedHeader.
const (
	CommandTCP uint8 = 0x01
	CommandUDP uint8 = 0x02
	CommandMux uint8 = 0x03
	CommandUoT uint8 = 0x04
)

// Aether v2 encrypted frame types (0x00 and >= 0x05 are invalid on the wire).
const (
	FrameData       uint8 = 0x01
	FramePing       uint8 = 0x02
	FramePong       uint8 = 0x03
	FrameCloseWrite uint8 = 0x04
)

// Wire format bounds and head-only shaping parameters.
const (
	MinNoiseLen     = 32
	MaxNoiseLen     = 384
	MaxVarHeaderLen = 16384
	RespStatusOK    = uint8(0x00)

	MinPingPadLen = 32
	MaxPingPadLen = 224

	ShapingFrameLimit = 6
	ShapingThreshold  = 1200
	ShapingSplitMin   = 512
	ShapingSplitMax   = 1100
	ShapingPadMin     = 16
	ShapingPadMax     = 255
)

var (
	// ErrInvalidVersion indicates a non-v2 FixedHeader or RespHeader version byte.
	ErrInvalidVersion = errors.New("aether: invalid protocol version")
	// ErrInvalidCommand indicates an unknown Command byte in FixedHeader.
	ErrInvalidCommand = errors.New("aether: invalid command")
	// ErrInvalidReserved indicates a non-zero reserved byte in FixedHeader or RespHeader.
	ErrInvalidReserved = errors.New("aether: non-zero reserved byte")
	// ErrInvalidNoiseLength indicates NoiseLen outside [32, 384].
	ErrInvalidNoiseLength = errors.New("aether: invalid noise length")
	// ErrInvalidVarHeaderLen indicates VarHeaderLen outside (NoiseLen, 16384].
	ErrInvalidVarHeaderLen = errors.New("aether: invalid variable header length")
	// ErrInvalidVarHeader indicates a malformed VarHeader payload.
	ErrInvalidVarHeader = errors.New("aether: invalid variable header")
	// ErrInvalidFrameType indicates a frame type outside [FrameData, FrameCloseWrite].
	ErrInvalidFrameType = errors.New("aether: invalid frame type")
	// ErrInvalidFramePadding indicates PadLen exceeding the decrypted frame body length.
	ErrInvalidFramePadding = errors.New("aether: invalid frame padding")
	// ErrInvalidFrameDataLen indicates FrameData payload exceeding MaxFrameDataSize.
	ErrInvalidFrameDataLen = errors.New("aether: frame data exceeds maximum")
	// ErrMalformedControlFrame indicates invalid PadLen or non-empty data on a control frame.
	ErrMalformedControlFrame = errors.New("aether: malformed control frame")
)

// IsValidCommand reports whether cmd is one of the four defined Aether v2 commands.
func IsValidCommand(cmd uint8) bool {
	return cmd >= CommandTCP && cmd <= CommandUoT
}

// IsValidFrameType reports whether ft is a valid Aether v2 frame type (0x01..0x04).
func IsValidFrameType(ft uint8) bool {
	return ft >= FrameData && ft <= FrameCloseWrite
}

// FixedHeader represents the 16-byte BigEndian plaintext FixedHeader inside ClientPrefix.
type FixedHeader struct {
	Version      uint8
	Command      uint8
	CipherSuite  uint8
	Reserved     uint8
	TimestampSec int64
	NoiseLen     uint16
	VarHeaderLen uint16
}

// Validate checks all structural invariants on h.
func (h FixedHeader) Validate() error {
	if h.Version != ProtocolVersion {
		return fmt.Errorf("%w: got 0x%02x", ErrInvalidVersion, h.Version)
	}
	if !IsValidCommand(h.Command) {
		return fmt.Errorf("%w: got 0x%02x", ErrInvalidCommand, h.Command)
	}
	if !IsValidCipherSuite(h.CipherSuite) {
		return fmt.Errorf("%w: got 0x%02x", ErrUnsupportedCipherSuite, h.CipherSuite)
	}
	if h.Reserved != 0 {
		return fmt.Errorf("%w: got 0x%02x", ErrInvalidReserved, h.Reserved)
	}
	if h.NoiseLen < MinNoiseLen || h.NoiseLen > MaxNoiseLen {
		return fmt.Errorf("%w: %d", ErrInvalidNoiseLength, h.NoiseLen)
	}
	if int(h.VarHeaderLen) <= int(h.NoiseLen) || h.VarHeaderLen > MaxVarHeaderLen {
		return fmt.Errorf("%w: varLen=%d noiseLen=%d", ErrInvalidVarHeaderLen, h.VarHeaderLen, h.NoiseLen)
	}
	return nil
}

// EncodeFixedHeader validates and serializes h into a 16-byte BigEndian block.
func EncodeFixedHeader(h FixedHeader) ([FixedHeaderPlainSize]byte, error) {
	var out [FixedHeaderPlainSize]byte
	if err := h.Validate(); err != nil {
		return out, err
	}
	out[0] = h.Version
	out[1] = h.Command
	out[2] = h.CipherSuite
	out[3] = h.Reserved
	binary.BigEndian.PutUint64(out[4:12], uint64(h.TimestampSec))
	binary.BigEndian.PutUint16(out[12:14], h.NoiseLen)
	binary.BigEndian.PutUint16(out[14:16], h.VarHeaderLen)
	return out, nil
}

// DecodeFixedHeader parses and validates a 16-byte BigEndian FixedHeader plaintext.
func DecodeFixedHeader(b []byte) (FixedHeader, error) {
	if len(b) != FixedHeaderPlainSize {
		return FixedHeader{}, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidVarHeader, FixedHeaderPlainSize, len(b))
	}
	h := FixedHeader{
		Version:      b[0],
		Command:      b[1],
		CipherSuite:  b[2],
		Reserved:     b[3],
		TimestampSec: int64(binary.BigEndian.Uint64(b[4:12])),
		NoiseLen:     binary.BigEndian.Uint16(b[12:14]),
		VarHeaderLen: binary.BigEndian.Uint16(b[14:16]),
	}
	if err := h.Validate(); err != nil {
		return FixedHeader{}, err
	}
	return h, nil
}

// normalizeClientTargetAddr ensures SocksaddrSerializer always receives a valid address
// when CommandUDP/Mux/UoT opens a session without an initial per-stream target.
func normalizeClientTargetAddr(command uint8, addr M.Socksaddr) (M.Socksaddr, error) {
	if addr.IsValid() {
		return addr, nil
	}
	if command == CommandTCP {
		return M.Socksaddr{}, fmt.Errorf("%w: invalid TCP target address", ErrInvalidVarHeader)
	}
	return M.Socksaddr{Addr: netip.IPv4Unspecified()}, nil
}

// MaxInitialPayloadLen returns the maximum 0-RTT initial payload bytes that fit in VarHeader
// for the given noiseLen and targetAddr.
func MaxInitialPayloadLen(noiseLen int, targetAddr M.Socksaddr) int {
	addrLen := M.SocksaddrSerializer.AddrPortLen(targetAddr)
	avail := MaxVarHeaderLen - noiseLen - addrLen
	if avail < 0 {
		return 0
	}
	return avail
}

// EncodeVarHeader writes [NoisePadding (noiseLen rand bytes)][TargetAddr][InitialPayload] into dst
// and returns the extended slice. dst may be nil or preallocated with capacity.
func EncodeVarHeader(dst []byte, noiseLen int, targetAddr M.Socksaddr, initialPayload []byte) ([]byte, error) {
	if noiseLen < MinNoiseLen || noiseLen > MaxNoiseLen {
		return nil, fmt.Errorf("%w: %d", ErrInvalidNoiseLength, noiseLen)
	}
	if !targetAddr.IsValid() {
		return nil, fmt.Errorf("%w: empty target address", ErrInvalidVarHeader)
	}
	addrLen := M.SocksaddrSerializer.AddrPortLen(targetAddr)
	totalLen := noiseLen + addrLen + len(initialPayload)
	if totalLen <= noiseLen || totalLen > MaxVarHeaderLen {
		return nil, fmt.Errorf("%w: total=%d", ErrInvalidVarHeaderLen, totalLen)
	}

	b := buf.NewSize(totalLen)
	defer b.Release()

	b.WriteRandom(noiseLen)
	if err := M.SocksaddrSerializer.WriteAddrPort(b, targetAddr); err != nil {
		return nil, fmt.Errorf("%w: write target address: %w", ErrInvalidVarHeader, err)
	}
	if len(initialPayload) > 0 {
		if _, err := b.Write(initialPayload); err != nil {
			return nil, fmt.Errorf("%w: write initial payload: %w", ErrInvalidVarHeader, err)
		}
	}
	out := append(dst, b.Bytes()...)
	return out, nil
}

// DecodeVarHeader validates and parses VarHeader plaintext after skipping noiseLen padding bytes.
// The returned initialPayload slice aliases varPlain unless empty.
func DecodeVarHeader(varPlain []byte, noiseLen uint16) (M.Socksaddr, []byte, error) {
	if noiseLen < MinNoiseLen || noiseLen > MaxNoiseLen {
		return M.Socksaddr{}, nil, fmt.Errorf("%w: %d", ErrInvalidNoiseLength, noiseLen)
	}
	if len(varPlain) <= int(noiseLen) || len(varPlain) > MaxVarHeaderLen {
		return M.Socksaddr{}, nil, fmt.Errorf("%w: varPlain=%d noiseLen=%d", ErrInvalidVarHeaderLen, len(varPlain), noiseLen)
	}

	r := bytes.NewReader(varPlain[int(noiseLen):])
	targetAddr, err := M.SocksaddrSerializer.ReadAddrPort(r)
	if err != nil {
		return M.Socksaddr{}, nil, fmt.Errorf("%w: read target address: %w", ErrInvalidVarHeader, err)
	}
	if !targetAddr.IsValid() {
		return M.Socksaddr{}, nil, fmt.Errorf("%w: invalid target address", ErrInvalidVarHeader)
	}

	offset := len(varPlain) - r.Len()
	if offset < int(noiseLen) || offset > len(varPlain) {
		return M.Socksaddr{}, nil, ErrInvalidVarHeader
	}
	initialPayload := varPlain[offset:]
	return targetAddr, initialPayload, nil
}

// EncodeRespHeader builds the 4-byte Server ResponseHeader: [0x02, 0x00, CipherSuite, 0x00].
func EncodeRespHeader(cipherSuite uint8) ([RespHeaderPlainSize]byte, error) {
	var out [RespHeaderPlainSize]byte
	if !IsValidCipherSuite(cipherSuite) {
		return out, fmt.Errorf("%w: 0x%02x", ErrUnsupportedCipherSuite, cipherSuite)
	}
	out[0] = ProtocolVersion
	out[1] = RespStatusOK
	out[2] = cipherSuite
	out[3] = 0x00
	return out, nil
}

// DecodeAndValidateRespHeader verifies the 4-byte Server ResponseHeader against expectedCipherSuite.
func DecodeAndValidateRespHeader(b []byte, expectedCipherSuite uint8) error {
	if len(b) != RespHeaderPlainSize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidRespHeader, RespHeaderPlainSize, len(b))
	}
	if b[0] != ProtocolVersion || b[1] != RespStatusOK || b[2] != expectedCipherSuite || b[3] != 0x00 {
		return fmt.Errorf("%w: got %x (expected suite 0x%02x)", ErrInvalidRespHeader, b, expectedCipherSuite)
	}
	return nil
}

// AppendFrameBody appends [FrameType (1B)][PadLen (1B)][Padding (padLen rand bytes)][data]
// to dst, validating all Aether v2 frame invariants before writing.
func AppendFrameBody(dst []byte, frameType uint8, padLen uint8, data []byte) ([]byte, error) {
	if !IsValidFrameType(frameType) {
		return nil, fmt.Errorf("%w: 0x%02x", ErrInvalidFrameType, frameType)
	}
	switch frameType {
	case FramePing, FramePong:
		if padLen < MinPingPadLen || padLen > MaxPingPadLen {
			return nil, fmt.Errorf("%w: ping/pong padLen=%d", ErrMalformedControlFrame, padLen)
		}
		if len(data) != 0 {
			return nil, fmt.Errorf("%w: ping/pong has %d data bytes", ErrMalformedControlFrame, len(data))
		}
	case FrameCloseWrite:
		if len(data) != 0 {
			return nil, fmt.Errorf("%w: close-write has %d data bytes", ErrMalformedControlFrame, len(data))
		}
	case FrameData:
		if len(data) > MaxFrameDataSize {
			return nil, fmt.Errorf("%w: %d > %d", ErrInvalidFrameDataLen, len(data), MaxFrameDataSize)
		}
	}

	plainLen := MinFramePlainSize + int(padLen) + len(data)
	if plainLen > MaxFramePlainSize {
		return nil, fmt.Errorf("%w: total plain length %d > %d", ErrInvalidFrameLength, plainLen, MaxFramePlainSize)
	}

	oldLen := len(dst)
	if cap(dst)-oldLen >= plainLen {
		dst = dst[:oldLen+plainLen]
	} else {
		grown := make([]byte, oldLen+plainLen)
		copy(grown, dst)
		dst = grown
	}
	body := dst[oldLen:]
	body[0] = frameType
	body[1] = padLen
	if padLen > 0 {
		if _, err := io.ReadFull(rand.Reader, body[MinFramePlainSize:MinFramePlainSize+int(padLen)]); err != nil {
			return nil, fmt.Errorf("aether: read frame padding randomness: %w", err)
		}
	}
	if len(data) > 0 {
		copy(body[MinFramePlainSize+int(padLen):], data)
	}
	return dst, nil
}

// ParseFrameBody validates a decrypted frame body and returns its FrameType and data slice
// aliasing bodyPlain. Bounds checks run strictly prior to slicing.
func ParseFrameBody(bodyPlain []byte) (frameType uint8, data []byte, err error) {
	if len(bodyPlain) < MinFramePlainSize {
		return 0, nil, fmt.Errorf("%w: body length %d", ErrInvalidFrameLength, len(bodyPlain))
	}
	frameType = bodyPlain[0]
	if !IsValidFrameType(frameType) {
		return 0, nil, fmt.Errorf("%w: 0x%02x", ErrInvalidFrameType, frameType)
	}
	padLen := int(bodyPlain[1])
	dataStart := MinFramePlainSize + padLen
	if dataStart > len(bodyPlain) {
		return 0, nil, fmt.Errorf("%w: padLen=%d exceeds plainLen=%d", ErrInvalidFramePadding, padLen, len(bodyPlain))
	}
	data = bodyPlain[dataStart:]

	switch frameType {
	case FramePing, FramePong:
		if padLen < MinPingPadLen || padLen > MaxPingPadLen || len(data) != 0 {
			return 0, nil, fmt.Errorf("%w: type=0x%02x padLen=%d dataLen=%d", ErrMalformedControlFrame, frameType, padLen, len(data))
		}
	case FrameCloseWrite:
		if len(data) != 0 {
			return 0, nil, fmt.Errorf("%w: close-write dataLen=%d", ErrMalformedControlFrame, len(data))
		}
	case FrameData:
		if len(data) > MaxFrameDataSize {
			return 0, nil, fmt.Errorf("%w: %d > %d", ErrInvalidFrameDataLen, len(data), MaxFrameDataSize)
		}
	}
	return frameType, data, nil
}

// NextDataChunk computes (chunkLen, padLen) for the next FrameData frame according to
// head-only traffic shaping (sendFrameIdx < 6 && !disableShaping) or steady-state framing.
func NextDataChunk(remainingLen int, sendFrameIdx uint64, disableShaping bool) (chunkLen int, padLen uint8, err error) {
	if remainingLen <= 0 {
		return 0, 0, nil
	}
	if sendFrameIdx < ShapingFrameLimit && !disableShaping {
		p, err := cryptoRandRange(ShapingPadMin, ShapingPadMax)
		if err != nil {
			return 0, 0, err
		}
		if remainingLen > ShapingThreshold {
			cLen, err := cryptoRandRange(ShapingSplitMin, ShapingSplitMax)
			if err != nil {
				return 0, 0, err
			}
			return cLen, uint8(p), nil
		}
		return remainingLen, uint8(p), nil
	}
	if remainingLen > MaxFrameDataSize {
		return MaxFrameDataSize, 0, nil
	}
	return remainingLen, 0, nil
}

// RandomNoiseLen returns a cryptographically uniform NoiseLen in [MinNoiseLen, MaxNoiseLen].
func RandomNoiseLen() (int, error) {
	return cryptoRandRange(MinNoiseLen, MaxNoiseLen)
}

// RandomPingPadLen returns a cryptographically uniform PadLen in [MinPingPadLen, MaxPingPadLen].
func RandomPingPadLen() (uint8, error) {
	v, err := cryptoRandRange(MinPingPadLen, MaxPingPadLen)
	return uint8(v), err
}

// cryptoRandRange returns an unbiased uniform integer in [minVal, maxVal] via crypto/rand.
func cryptoRandRange(minVal, maxVal int) (int, error) {
	if maxVal < minVal {
		return 0, fmt.Errorf("aether: invalid random range [%d, %d]", minVal, maxVal)
	}
	if minVal == maxVal {
		return minVal, nil
	}
	span := uint64(maxVal - minVal + 1)
	maxUnbiased := ^uint64(0) - ((^uint64(0) % span) + 1)
	var b [8]byte
	for {
		if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
			return 0, err
		}
		v := binary.BigEndian.Uint64(b[:])
		if v <= maxUnbiased {
			return minVal + int(v%span), nil
		}
	}
}
