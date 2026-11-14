package aether

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

type fuzzReadConn struct {
	reader io.Reader
}

func (c *fuzzReadConn) Read(p []byte) (int, error)       { return c.reader.Read(p) }
func (c *fuzzReadConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *fuzzReadConn) Close() error                     { return nil }
func (c *fuzzReadConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *fuzzReadConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *fuzzReadConn) SetDeadline(time.Time) error      { return nil }
func (c *fuzzReadConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fuzzReadConn) SetWriteDeadline(time.Time) error { return nil }

func buildFuzzValidHandshakeBytes(t testing.TB, opts option.AetherInboundOptions, cmd uint8) []byte {
	t.Helper()
	var creds ClientCredentials
	var err error
	if opts.Password != "" {
		creds, err = ParseOutboundCredentials(opts.Password)
	} else {
		creds, err = ParseOutboundCredentials(opts.Users[0].Password)
	}
	require.NoError(t, err)

	a, b := net.Pipe()
	var captured bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&captured, b)
	}()

	cliConn, err := DialEarlyConnContext(context.Background(), a, ClientConnOptions{
		Credentials: creds,
		Command:     cmd,
		CipherSuite: CipherAES256GCM,
		TargetAddr:  M.ParseSocksaddrHostPort("1.1.1.1", 443),
	})
	require.NoError(t, err)
	_, err = cliConn.Write([]byte("ping"))
	require.NoError(t, err)
	_ = a.Close()
	wg.Wait()
	_ = b.Close()
	_ = cliConn.Close()
	return captured.Bytes()
}

func FuzzHandshake(f *testing.F) {
	singleOpts := option.AetherInboundOptions{Password: "fuzz-single-secret"}
	multiOpts := option.AetherInboundOptions{
		Users: []option.AetherUser{{Name: "alice", Password: "fuzz-user-secret"}},
	}

	validSingle := buildFuzzValidHandshakeBytes(f, singleOpts, CommandTCP)
	validMulti := buildFuzzValidHandshakeBytes(f, multiOpts, CommandUDP)

	f.Add(validSingle)
	f.Add(validMulti)
	f.Add([]byte{})
	f.Add(make([]byte, 95))
	f.Add(make([]byte, 111))
	f.Add([]byte("\x16\x03\x01\x02\x00TLS-probe-client-hello"))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))

	corrupted := append([]byte(nil), validSingle...)
	if len(corrupted) > 80 {
		corrupted[64] ^= 0xff
		f.Add(corrupted)
	}

	singleAuth, err := NewServerAuthenticatorFromOptions(singleOpts)
	require.NoError(f, err)
	multiAuth, err := NewServerAuthenticatorFromOptions(multiOpts)
	require.NoError(f, err)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			data = data[:65536]
		}

		// Direct fixed-prefix decode fuzzing across both single-key and EIH authenticators.
		for _, auth := range []*ServerAuthenticator{singleAuth, multiAuth} {
			if len(data) >= auth.ClientPrefixSize() {
				if hs, encHdr, err := auth.OpenClientFixedPrefix(data[:auth.ClientPrefixSize()]); err == nil {
					_, _ = DecodeFixedHeader(encHdr[:])
					_ = hs
				}
			}

			rf := NewSlidingBloomFilter(DefaultTimeWindow, time.Now)
			res, err := AcceptServerConn(context.Background(), &fuzzReadConn{reader: bytes.NewReader(data)}, ServerConnOptions{
				Authenticator: auth,
				ReplayFilter:  rf,
			})
			if res != nil && res.Conn != nil {
				_ = res.Conn.Close()
			}
			_, _ = ClassifyHandshakeFailure(err)
		}
	})
}

func FuzzFrameStream(f *testing.F) {
	auth, err := NewServerAuthenticatorFromOptions(option.AetherInboundOptions{
		Password: "fuzz-frame-stream-secret",
	})
	require.NoError(f, err)

	clientWire := buildFuzzValidHandshakeBytes(f, option.AetherInboundOptions{Password: "fuzz-frame-stream-secret"}, CommandTCP)
	f.Add(clientWire)
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18})
	f.Add(bytes.Repeat([]byte{0xff}, 64))
	f.Add(bytes.Repeat([]byte{0x00}, 128))

	// Valid handshake prefix size + corrupted trailing frames.
	if len(clientWire) > 120 {
		prefixOnly := append([]byte(nil), clientWire...)
		prefixOnly[len(prefixOnly)-1] ^= 0x80
		f.Add(prefixOnly)
	}

	var zeroSalt [HandshakeSaltSize]byte
	_, _ = rand.Read(zeroSalt[:])

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 65536 {
			raw = raw[:65536]
		}

		// 1) Fuzz VarHeader plaintext parser directly.
		if len(raw) >= 1 {
			_, _, _ = DecodeVarHeader(raw[1:], uint16(raw[0]))
		} else {
			_, _, _ = DecodeVarHeader(raw, 0)
		}

		// 2) Fuzz FixedHeader plaintext parser directly.
		if len(raw) >= FixedHeaderPlainSize {
			_, _ = DecodeFixedHeader(raw[:FixedHeaderPlainSize])
		}

		// 3) Fuzz NextDataChunk chunker against arbitrary lengths and shaping flags.
		if len(raw) >= 4 {
			disableShaping := raw[0]&1 == 1
			rem := int(binary.BigEndian.Uint16(raw[1:3]))
			_, _, _ = NextDataChunk(rem, 0, disableShaping)
			_, _, _ = NextDataChunk(rem, 7, disableShaping)
		}

		// 4) Fuzz encrypted Conn.Read over bounded stream.
		rf := NewSlidingBloomFilter(DefaultTimeWindow, time.Now)
		res, err := AcceptServerConn(context.Background(), &fuzzReadConn{reader: bytes.NewReader(raw)}, ServerConnOptions{
			Authenticator: auth,
			ReplayFilter:  rf,
		})
		if err == nil && res != nil && res.Conn != nil {
			defer res.Conn.Close()
			buf := make([]byte, 4096)
			for i := 0; i < 4; i++ {
				if _, rErr := res.Conn.Read(buf); rErr != nil {
					break
				}
			}
		}
	})
}
