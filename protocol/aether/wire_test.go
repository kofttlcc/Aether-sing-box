package aether

import (
	"bytes"
	"errors"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func TestFixedHeaderEncodeDecodeAndValidation(t *testing.T) {
	validCases := []FixedHeader{
		{
			Version:      ProtocolVersion,
			Command:      CommandTCP,
			CipherSuite:  CipherAES256GCM,
			Reserved:     0,
			TimestampSec: 1730000000,
			NoiseLen:     MinNoiseLen,
			VarHeaderLen: MinNoiseLen + 1,
		},
		{
			Version:      ProtocolVersion,
			Command:      CommandUDP,
			CipherSuite:  CipherChaCha20Poly1305,
			Reserved:     0,
			TimestampSec: -42,
			NoiseLen:     MaxNoiseLen,
			VarHeaderLen: MaxVarHeaderLen,
		},
		{
			Version:      ProtocolVersion,
			Command:      CommandMux,
			CipherSuite:  CipherAES256GCM,
			Reserved:     0,
			TimestampSec: 0,
			NoiseLen:     128,
			VarHeaderLen: 512,
		},
		{
			Version:      ProtocolVersion,
			Command:      CommandUoT,
			CipherSuite:  CipherChaCha20Poly1305,
			Reserved:     0,
			TimestampSec: 1 << 40,
			NoiseLen:     64,
			VarHeaderLen: 4096,
		},
	}

	for i, tc := range validCases {
		enc, err := EncodeFixedHeader(tc)
		if err != nil {
			t.Fatalf("case %d EncodeFixedHeader unexpected error: %v", i, err)
		}
		got, err := DecodeFixedHeader(enc[:])
		if err != nil {
			t.Fatalf("case %d DecodeFixedHeader unexpected error: %v", i, err)
		}
		if got != tc {
			t.Fatalf("case %d mismatch: got %+v, want %+v", i, got, tc)
		}
	}

	invalidCases := []struct {
		name string
		hdr  FixedHeader
		want error
	}{
		{"wrong_version_1", FixedHeader{Version: 0x01, Command: CommandTCP, CipherSuite: CipherAES256GCM, NoiseLen: 32, VarHeaderLen: 64}, ErrInvalidVersion},
		{"wrong_version_3", FixedHeader{Version: 0x03, Command: CommandTCP, CipherSuite: CipherAES256GCM, NoiseLen: 32, VarHeaderLen: 64}, ErrInvalidVersion},
		{"command_0", FixedHeader{Version: ProtocolVersion, Command: 0x00, CipherSuite: CipherAES256GCM, NoiseLen: 32, VarHeaderLen: 64}, ErrInvalidCommand},
		{"command_5", FixedHeader{Version: ProtocolVersion, Command: 0x05, CipherSuite: CipherAES256GCM, NoiseLen: 32, VarHeaderLen: 64}, ErrInvalidCommand},
		{"suite_0", FixedHeader{Version: ProtocolVersion, Command: CommandTCP, CipherSuite: 0x00, NoiseLen: 32, VarHeaderLen: 64}, ErrUnsupportedCipherSuite},
		{"suite_3", FixedHeader{Version: ProtocolVersion, Command: CommandTCP, CipherSuite: 0x03, NoiseLen: 32, VarHeaderLen: 64}, ErrUnsupportedCipherSuite},
		{"reserved_nonzero", FixedHeader{Version: ProtocolVersion, Command: CommandTCP, CipherSuite: CipherAES256GCM, Reserved: 0x01, NoiseLen: 32, VarHeaderLen: 64}, ErrInvalidReserved},
		{"noise_too_small", FixedHeader{Version: ProtocolVersion, Command: CommandTCP, CipherSuite: CipherAES256GCM, NoiseLen: 31, VarHeaderLen: 64}, ErrInvalidNoiseLength},
		{"noise_too_large", FixedHeader{Version: ProtocolVersion, Command: CommandTCP, CipherSuite: CipherAES256GCM, NoiseLen: 385, VarHeaderLen: 500}, ErrInvalidNoiseLength},
		{"var_equal_noise", FixedHeader{Version: ProtocolVersion, Command: CommandTCP, CipherSuite: CipherAES256GCM, NoiseLen: 64, VarHeaderLen: 64}, ErrInvalidVarHeaderLen},
		{"var_less_noise", FixedHeader{Version: ProtocolVersion, Command: CommandTCP, CipherSuite: CipherAES256GCM, NoiseLen: 64, VarHeaderLen: 63}, ErrInvalidVarHeaderLen},
		{"var_too_large", FixedHeader{Version: ProtocolVersion, Command: CommandTCP, CipherSuite: CipherAES256GCM, NoiseLen: 64, VarHeaderLen: MaxVarHeaderLen + 1}, ErrInvalidVarHeaderLen},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := EncodeFixedHeader(tc.hdr); !errors.Is(err, tc.want) {
				t.Fatalf("EncodeFixedHeader error = %v, want %v", err, tc.want)
			}
		})
	}

	if _, err := DecodeFixedHeader(make([]byte, 15)); !errors.Is(err, ErrInvalidVarHeader) {
		t.Fatalf("DecodeFixedHeader short input err = %v", err)
	}
}

func TestVarHeaderEncodeDecodeRoundTrip(t *testing.T) {
	addrs := []M.Socksaddr{
		M.ParseSocksaddrHostPort("192.0.2.10", 443),
		M.ParseSocksaddrHostPort("2001:db8::1", 8443),
		M.ParseSocksaddrHostPort("api.example.com", 443),
	}

	for _, addr := range addrs {
		for _, noiseLen := range []int{MinNoiseLen, 100, MaxNoiseLen} {
			maxInit := MaxInitialPayloadLen(noiseLen, addr)
			for _, initPayload := range [][]byte{
				nil,
				[]byte("GET / HTTP/1.1\r\n\r\n"),
				bytes.Repeat([]byte{0x5a}, maxInit),
			} {
				vh, err := EncodeVarHeader(nil, noiseLen, addr, initPayload)
				if err != nil {
					t.Fatalf("EncodeVarHeader(addr=%s, noise=%d, init=%d) err: %v", addr, noiseLen, len(initPayload), err)
				}
				if len(vh) > MaxVarHeaderLen {
					t.Fatalf("VarHeader exceeded %d: got %d", MaxVarHeaderLen, len(vh))
				}
				gotAddr, gotInit, err := DecodeVarHeader(vh, uint16(noiseLen))
				if err != nil {
					t.Fatalf("DecodeVarHeader err: %v", err)
				}
				if gotAddr.String() != addr.String() {
					t.Fatalf("target addr = %s, want %s", gotAddr, addr)
				}
				if !bytes.Equal(gotInit, initPayload) {
					t.Fatalf("initial payload len = %d, want %d", len(gotInit), len(initPayload))
				}
			}

			overflow := make([]byte, maxInit+1)
			if _, err := EncodeVarHeader(nil, noiseLen, addr, overflow); !errors.Is(err, ErrInvalidVarHeaderLen) {
				t.Fatalf("overflow EncodeVarHeader err = %v, want ErrInvalidVarHeaderLen", err)
			}
		}
	}

	// Corrupt socksaddr family byte after noise padding.
	bad := make([]byte, 48)
	bad[32] = 0x7f
	if _, _, err := DecodeVarHeader(bad, 32); !errors.Is(err, ErrInvalidVarHeader) {
		t.Fatalf("bad socksaddr err = %v, want ErrInvalidVarHeader", err)
	}
}

func TestRespHeaderEncodeAndValidate(t *testing.T) {
	for _, suite := range []uint8{CipherAES256GCM, CipherChaCha20Poly1305} {
		hdr, err := EncodeRespHeader(suite)
		if err != nil {
			t.Fatalf("EncodeRespHeader err: %v", err)
		}
		if hdr != [4]byte{ProtocolVersion, RespStatusOK, suite, 0x00} {
			t.Fatalf("unexpected hdr %x", hdr)
		}
		if err := DecodeAndValidateRespHeader(hdr[:], suite); err != nil {
			t.Fatalf("DecodeAndValidateRespHeader err: %v", err)
		}
		otherSuite := CipherChaCha20Poly1305
		if suite == CipherChaCha20Poly1305 {
			otherSuite = CipherAES256GCM
		}
		if err := DecodeAndValidateRespHeader(hdr[:], otherSuite); !errors.Is(err, ErrInvalidRespHeader) {
			t.Fatalf("suite mismatch err = %v, want ErrInvalidRespHeader", err)
		}
	}

	badResp := [][4]byte{
		{0x01, 0x00, CipherAES256GCM, 0x00},
		{ProtocolVersion, 0x01, CipherAES256GCM, 0x00},
		{ProtocolVersion, 0x00, CipherAES256GCM, 0x01},
	}
	for _, r := range badResp {
		if err := DecodeAndValidateRespHeader(r[:], CipherAES256GCM); !errors.Is(err, ErrInvalidRespHeader) {
			t.Fatalf("badResp %x err = %v, want ErrInvalidRespHeader", r, err)
		}
	}
}

func TestFrameBodyEncodeParseAndRejections(t *testing.T) {
	// Valid FrameData with 0B, normal, and max 16384B payload + max 255B pad.
	for _, dataLen := range []int{0, 1, 500, MaxFrameDataSize} {
		for _, padLen := range []uint8{0, 16, 255} {
			payload := bytes.Repeat([]byte{0xab}, dataLen)
			body, err := AppendFrameBody(nil, FrameData, padLen, payload)
			if err != nil {
				t.Fatalf("AppendFrameBody(data=%d, pad=%d) err: %v", dataLen, padLen, err)
			}
			ft, gotData, err := ParseFrameBody(body)
			if err != nil {
				t.Fatalf("ParseFrameBody err: %v", err)
			}
			if ft != FrameData || !bytes.Equal(gotData, payload) {
				t.Fatalf("parsed type=0x%02x dataLen=%d, want type=0x01 dataLen=%d", ft, len(gotData), dataLen)
			}
		}
	}

	// Valid Ping, Pong, CloseWrite.
	for _, ft := range []uint8{FramePing, FramePong} {
		for _, padLen := range []uint8{MinPingPadLen, 100, MaxPingPadLen} {
			body, err := AppendFrameBody(nil, ft, padLen, nil)
			if err != nil {
				t.Fatalf("AppendFrameBody(ft=0x%02x, pad=%d) err: %v", ft, padLen, err)
			}
			gotFT, gotData, err := ParseFrameBody(body)
			if err != nil || gotFT != ft || len(gotData) != 0 {
				t.Fatalf("ParseFrameBody control err=%v ft=0x%02x len=%d", err, gotFT, len(gotData))
			}
		}
	}
	cwBody, err := AppendFrameBody(nil, FrameCloseWrite, 0, nil)
	if err != nil {
		t.Fatalf("AppendFrameBody FrameCloseWrite err: %v", err)
	}
	if ft, data, err := ParseFrameBody(cwBody); err != nil || ft != FrameCloseWrite || len(data) != 0 {
		t.Fatalf("ParseFrameBody CloseWrite err=%v ft=0x%02x len=%d", err, ft, len(data))
	}

	// Strict rejection: FrameType 0x00 and >= 0x05, truncated / OOB PadLen, malformed control frames.
	rejectBodies := []struct {
		name string
		raw  []byte
		want error
	}{
		{"empty_body", []byte{0x01}, ErrInvalidFrameLength},
		{"frame_type_0x00", []byte{0x00, 0x00, 0x01}, ErrInvalidFrameType},
		{"frame_type_0x05", []byte{0x05, 0x00, 0x01}, ErrInvalidFrameType},
		{"frame_type_0xff", []byte{0xff, 0x00}, ErrInvalidFrameType},
		{"padlen_oob_slice_guard", []byte{FrameData, 0xff, 0xaa, 0xbb}, ErrInvalidFramePadding},
		{"padlen_exact_oob_2", []byte{FrameData, 0x01}, ErrInvalidFramePadding},
		{"ping_pad_too_small", append([]byte{FramePing, 31}, make([]byte, 31)...), ErrMalformedControlFrame},
		{"ping_pad_too_large", append([]byte{FramePing, 225}, make([]byte, 225)...), ErrMalformedControlFrame},
		{"pong_with_data", append([]byte{FramePong, 32}, make([]byte, 33)...), ErrMalformedControlFrame},
		{"close_write_with_data", []byte{FrameCloseWrite, 0, 0x01}, ErrMalformedControlFrame},
		{"data_too_large", append([]byte{FrameData, 0}, make([]byte, MaxFrameDataSize+1)...), ErrInvalidFrameDataLen},
	}

	for _, tc := range rejectBodies {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := ParseFrameBody(tc.raw); !errors.Is(err, tc.want) {
				t.Fatalf("ParseFrameBody err = %v, want %v", err, tc.want)
			}
		})
	}

	// Zero allocation verification when caller supplies capacity.
	dst := make([]byte, 0, MaxFramePlainSize)
	src := make([]byte, 1400)
	allocs := testing.AllocsPerRun(20, func() {
		out, err := AppendFrameBody(dst[:0], FrameData, 0, src)
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 2+len(src) {
			t.Fatalf("unexpected len %d", len(out))
		}
	})
	if allocs != 0 {
		t.Fatalf("AppendFrameBody allocs = %v, want 0", allocs)
	}
}

func TestHeadOnlyShapingBoundaries(t *testing.T) {
	// Frames 0..5 with shaping enabled.
	for idx := uint64(0); idx < ShapingFrameLimit; idx++ {
		for trial := 0; trial < 20; trial++ {
			chunkLen, padLen, err := NextDataChunk(5000, idx, false)
			if err != nil {
				t.Fatal(err)
			}
			if padLen < ShapingPadMin || padLen > ShapingPadMax {
				t.Fatalf("idx=%d padLen=%d outside [16,255]", idx, padLen)
			}
			if chunkLen < ShapingSplitMin || chunkLen > ShapingSplitMax {
				t.Fatalf("idx=%d chunkLen=%d outside [512,1100]", idx, chunkLen)
			}

			smallLen, smallPad, err := NextDataChunk(1200, idx, false)
			if err != nil {
				t.Fatal(err)
			}
			if smallLen != 1200 || smallPad < ShapingPadMin || smallPad > ShapingPadMax {
				t.Fatalf("idx=%d <=1200 split unexpected: len=%d pad=%d", idx, smallLen, smallPad)
			}
		}
	}

	// Frame 6+ unpadded, up to 16384.
	chunkLen, padLen, err := NextDataChunk(20000, ShapingFrameLimit, false)
	if err != nil {
		t.Fatal(err)
	}
	if padLen != 0 || chunkLen != MaxFrameDataSize {
		t.Fatalf("frame 6 got (len=%d, pad=%d), want (%d, 0)", chunkLen, padLen, MaxFrameDataSize)
	}

	// DisableShaping=true unpadded from frame 0.
	chunkLen, padLen, err = NextDataChunk(20000, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if padLen != 0 || chunkLen != MaxFrameDataSize {
		t.Fatalf("disabled shaping got (len=%d, pad=%d), want (%d, 0)", chunkLen, padLen, MaxFrameDataSize)
	}
}
