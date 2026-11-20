package aether

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

type pcapWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
	seq uint32
}

func newPCAPWriter() *pcapWriter {
	w := &pcapWriter{}
	// Standard libpcap global header (little-endian magic, v2.4, DLT_RAW=101 or Ethernet=1).
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[8:12], 0)
	binary.LittleEndian.PutUint32(hdr[12:16], 0)
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)
	binary.LittleEndian.PutUint32(hdr[20:24], 101) // LINKTYPE_RAW (IPv4)
	w.buf.Write(hdr[:])
	w.seq = 1
	return w
}

func (w *pcapWriter) writeTCPSegment(payload []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()

	const ipHdrLen = 20
	const tcpHdrLen = 20
	totalLen := ipHdrLen + tcpHdrLen + len(payload)

	pkt := make([]byte, totalLen)
	// Minimal IPv4 header
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = 6 // TCP
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})

	// Minimal TCP header
	binary.BigEndian.PutUint16(pkt[20:22], 51234)
	binary.BigEndian.PutUint16(pkt[22:24], 443)
	binary.BigEndian.PutUint32(pkt[24:28], w.seq)
	w.seq += uint32(len(payload))
	pkt[32] = 0x50 // 20B TCP header
	pkt[33] = 0x18 // PSH|ACK
	binary.BigEndian.PutUint16(pkt[34:36], 65535)

	copy(pkt[40:], payload)

	now := time.Now()
	var recHdr [16]byte
	binary.LittleEndian.PutUint32(recHdr[0:4], uint32(now.Unix()))
	binary.LittleEndian.PutUint32(recHdr[4:8], uint32(now.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(recHdr[8:12], uint32(len(pkt)))
	binary.LittleEndian.PutUint32(recHdr[12:16], uint32(len(pkt)))
	w.buf.Write(recHdr[:])
	w.buf.Write(pkt)
}

func (w *pcapWriter) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]byte, w.buf.Len())
	copy(out, w.buf.Bytes())
	return out
}

type captureConn struct {
	net.Conn
	mu       sync.Mutex
	segments [][]byte
	pcap     *pcapWriter
}

func (c *captureConn) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	c.mu.Lock()
	c.segments = append(c.segments, cp)
	c.mu.Unlock()
	if c.pcap != nil {
		c.pcap.writeTCPSegment(cp)
	}
	return c.Conn.Write(p)
}

func (c *captureConn) snapshotSegments() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.segments))
	copy(out, c.segments)
	return out
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func TestPCAPWireCoalescingOverheadAndEntropy(t *testing.T) {
	t.Parallel()

	creds, err := ParseOutboundCredentials("pcap-wire-secret")
	require.NoError(t, err)
	auth, err := NewServerAuthenticatorFromOptions(option.AetherInboundOptions{
		Password: "pcap-wire-secret",
	})
	require.NoError(t, err)
	rf := NewSlidingBloomFilter(DefaultTimeWindow, time.Now)

	cPipe, sPipe := net.Pipe()
	pw := newPCAPWriter()
	capClient := &captureConn{Conn: cPipe, pcap: pw}

	type srvResult struct {
		conn *Conn
		err  error
	}
	srvCh := make(chan srvResult, 1)
	go func() {
		res, aErr := AcceptServerConn(context.Background(), sPipe, ServerConnOptions{
			Authenticator:     auth,
			ReplayFilter:      rf,
			HeartbeatInterval: -1,
		})
		if aErr != nil {
			srvCh <- srvResult{err: aErr}
			return
		}
		srvCh <- srvResult{conn: res.Conn}
	}()

	cliConn, err := DialEarlyConnContext(context.Background(), capClient, ClientConnOptions{
		Credentials:       creds,
		Command:           CommandTCP,
		CipherSuite:       CipherAES256GCM,
		TargetAddr:        M.ParseSocksaddrHostPort("pcap.example", 443),
		HeartbeatInterval: -1,
	})
	require.NoError(t, err)
	defer cliConn.Close()

	// Send initial 7 chunks: chunk 0 enters EncryptedVarHeader InitialPayload, chunks 1..6
	// exercise Data Frame 0..5 head shaping, so bulk 512 KiB starts cleanly at Data Frame 6
	// (32 x 16384B unpadded frames, overhead 36/16384 = 0.2197% <= 0.22%).
	const headMsgSize = 64
	const headCount = 7
	const bulkSize = 512 * 1024

	readDone := make(chan int, 1)
	go func() {
		srvRes := <-srvCh
		if srvRes.err != nil {
			readDone <- -1
			return
		}
		srvConn := srvRes.conn
		defer srvConn.Close()
		if _, wErr := srvConn.Write([]byte("R")); wErr != nil {
			readDone <- -1
			return
		}
		buf := make([]byte, 32768)
		total := 0
		for {
			n, rErr := srvConn.Read(buf)
			total += n
			if rErr != nil {
				readDone <- total
				return
			}
		}
	}()

	totalPlain := 0
	for i := 0; i < headCount; i++ {
		chunk := make([]byte, headMsgSize)
		_, err = rand.Read(chunk)
		require.NoError(t, err)
		_, err = cliConn.Write(chunk)
		require.NoError(t, err)
		totalPlain += len(chunk)
		if i == 0 {
			ack := make([]byte, 1)
			_, err = io.ReadFull(cliConn, ack)
			require.NoError(t, err)
		}
	}
	headSegCount := len(capClient.snapshotSegments())

	bulk := make([]byte, bulkSize)
	_, err = rand.Read(bulk)
	require.NoError(t, err)

	_, err = cliConn.Write(bulk)
	require.NoError(t, err)
	totalPlain += len(bulk)
	require.NoError(t, cliConn.CloseWrite())
	_ = cliConn.Close()
	srvReceived := <-readDone
	require.Equal(t, totalPlain, srvReceived)

	// Persist PCAP file into TempDir and verify PCAP header + record structure.
	pcapPath := filepath.Join(t.TempDir(), "aether_capture.pcap")
	pcapBytes := pw.bytes()
	require.NoError(t, os.WriteFile(pcapPath, pcapBytes, 0600))
	require.Greater(t, len(pcapBytes), 24+40)
	require.Equal(t, uint32(0xa1b2c3d4), binary.LittleEndian.Uint32(pcapBytes[0:4]))

	segs := capClient.snapshotSegments()
	require.Greater(t, len(segs), headSegCount)

	var allWire bytes.Buffer
	var bulkWireBytes int
	for idx, seg := range segs {
		allWire.Write(seg)
		if idx == 0 {
			// Segment 0 is the 0-RTT client burst (FixedPrefix + EncVarHeader + initial frame if queued).
			require.GreaterOrEqual(t, len(seg), ClientPrefixNoEIHSize+EncryptedLengthSize)
			continue
		}
		// Never split 2B or 18B standalone header writes!
		require.NotEqual(t, 2, len(seg), "2B header split detected at segment %d", idx)
		require.NotEqual(t, 18, len(seg), "18B encrypted-length split detected at segment %d", idx)
		require.GreaterOrEqual(t, len(seg), 36, "every standalone frame segment must be >= 36B")
		if idx >= headSegCount {
			bulkWireBytes += len(seg)
		}
	}

	// Steady-state Frame 6+ overhead over 512 KiB (excluding CloseWrite FIN control frame if separated)
	// converges to 36 / 16384 = 0.2197% (strictly <= 0.22%, allowing the final 36B CloseWrite frame <= 0.23% or subtracting it).
	streamOverhead := float64(bulkWireBytes-bulkSize) / float64(bulkSize)
	require.LessOrEqual(t, streamOverhead, 0.0023, "steady-state frame overhead must stay <= ~0.22%% (got %.6f)", streamOverhead)
	// Pure 32 x 16384B frames contribute 32 * 36 = 1152B (0.2197%) plus at most 1 CloseWrite control frame (36B).
	dataOverhead := float64(bulkWireBytes-bulkSize-36) / float64(bulkSize)
	require.LessOrEqual(t, dataOverhead, 0.0022, "pure Frame 6+ data overhead must be <= 0.22%% (got %.6f)", dataOverhead)

	// High Shannon entropy (> 7.95 bits/byte) across captured encrypted wire stream.
	wireBytes := allWire.Bytes()
	ent := shannonEntropy(wireBytes)
	require.Greater(t, ent, 7.95, "wire Shannon entropy %.4f must exceed 7.95 bits/byte", ent)

	// Zero recognizable TLS / HTTP / target-address plaintext markers on the wire.
	// Note: 3-byte TLS record headers ({0x16, 0x03, 0x01/0x03}) are checked as segment
	// prefixes rather than arbitrary-offset substrings across 528 KiB of uniform random
	// ciphertext, where a random 3-byte match occurs with ~6.1% probability per run.
	require.False(t, bytes.Contains(wireBytes, []byte("pcap.example")))
	require.False(t, bytes.Contains(wireBytes, []byte("HTTP/1.")))
	require.False(t, bytes.Contains(wireBytes, []byte("GET /")))
	for idx, seg := range segs {
		require.False(t, bytes.HasPrefix(seg, []byte{0x16, 0x03, 0x01}), "segment %d began with TLS 1.0 record prefix", idx)
		require.False(t, bytes.HasPrefix(seg, []byte{0x16, 0x03, 0x03}), "segment %d began with TLS 1.2 record prefix", idx)
	}
}

func TestPCAPDisableShapingZeroPaddingHead(t *testing.T) {
	t.Parallel()

	creds, err := ParseOutboundCredentials("noshape-secret-v2")
	require.NoError(t, err)
	auth, err := NewServerAuthenticatorFromOptions(option.AetherInboundOptions{
		Password:       "noshape-secret-v2",
		DisableShaping: true,
	})
	require.NoError(t, err)

	cPipe, sPipe := net.Pipe()
	capClient := &captureConn{Conn: cPipe}

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		res, aErr := AcceptServerConn(context.Background(), sPipe, ServerConnOptions{
			Authenticator:     auth,
			ReplayFilter:      NewSlidingBloomFilter(DefaultTimeWindow, time.Now),
			HeartbeatInterval: -1,
			DisableShaping:    true,
		})
		if aErr == nil && res != nil && res.Conn != nil {
			_, _ = res.Conn.Write([]byte("ok"))
			_, _ = io.Copy(io.Discard, res.Conn)
			_ = res.Conn.Close()
		}
	}()

	cliConn, err := DialEarlyConnContext(context.Background(), capClient, ClientConnOptions{
		Credentials:       creds,
		Command:           CommandTCP,
		CipherSuite:       CipherChaCha20Poly1305,
		TargetAddr:        M.ParseSocksaddrHostPort("noshape.example", 80),
		HeartbeatInterval: -1,
		DisableShaping:    true,
	})
	require.NoError(t, err)
	defer cliConn.Close()

	// Send 100B inside EncVarHeader (chunk 0), read server handshake ACK, then send
	// Data Frames 0..4 (100B each): DisableShaping means zero padding, so every
	// standalone post-handshake frame wire length == 18 (lenHdr) + 2 (frame hdr) + 100 + 16 (tag) = 136B!
	for i := 0; i < 6; i++ {
		_, err = cliConn.Write(bytes.Repeat([]byte{byte('a' + i)}, 100))
		require.NoError(t, err)
		if i == 0 {
			ack := make([]byte, 2)
			_, err = io.ReadFull(cliConn, ack)
			require.NoError(t, err)
		}
	}
	_ = cliConn.CloseWrite()
	_ = cliConn.Close()
	<-srvDone

	segs := capClient.snapshotSegments()
	// Segment 0 is handshake + Frame 0 coalesced burst; segments 1..5 must be exact 136B (0B shaping pad).
	require.GreaterOrEqual(t, len(segs), 6)
	for i := 1; i < 6; i++ {
		require.Equal(t, EncryptedLengthSize+2+100+AEADTagSize, len(segs[i]), "segment %d must have 0B shaping pad", i)
	}
}

func TestPCAPEPKBit255Uniformity(t *testing.T) {
	t.Parallel()

	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	priv := base64.StdEncoding.EncodeToString(privKey.Bytes())
	pub := base64.StdEncoding.EncodeToString(privKey.PublicKey().Bytes())
	staticPub, err := ParseX25519PublicKey(pub)
	require.NoError(t, err)

	creds, err := ParseOutboundCredentials("epk-uniformity-secret")
	require.NoError(t, err)
	auth, err := NewServerAuthenticatorFromOptions(option.AetherInboundOptions{
		Password:         "epk-uniformity-secret",
		ServerPrivateKey: priv,
	})
	require.NoError(t, err)

	const trials = 256
	clientBit1Count := 0
	serverBit1Count := 0

	for i := 0; i < trials; i++ {
		rf := NewSlidingBloomFilter(DefaultTimeWindow, time.Now)
		cPipe, sPipe := net.Pipe()
		capCli := &captureConn{Conn: cPipe}
		capSrv := &captureConn{Conn: sPipe}

		errCh := make(chan error, 1)
		go func() {
			res, aErr := AcceptServerConn(context.Background(), capSrv, ServerConnOptions{
				Authenticator: auth,
				ReplayFilter:  rf,
			})
			if aErr == nil && res != nil && res.Conn != nil {
				// Coalesced 84B ServerResponsePrefix is emitted on server's first write/frame.
				_, _ = res.Conn.Write([]byte("s"))
				_ = res.Conn.CloseWrite()
				_ = res.Conn.Close()
			}
			errCh <- aErr
		}()

		cliConn, dErr := DialEarlyConnContext(context.Background(), capCli, ClientConnOptions{
			Credentials:     creds,
			ServerStaticPub: staticPub,
			Command:         CommandTCP,
			CipherSuite:     CipherAES256GCM,
			TargetAddr:      M.ParseSocksaddrHostPort("epk.example", 443),
		})
		require.NoError(t, dErr)
		_, _ = cliConn.Write([]byte("x"))
		var ack [1]byte
		_, _ = io.ReadFull(cliConn, ack[:])
		_ = cliConn.Close()
		require.NoError(t, <-errCh)

		cliSegs := capCli.snapshotSegments()
		require.NotEmpty(t, cliSegs)
		require.GreaterOrEqual(t, len(cliSegs[0]), HandshakeSaltSize+EPKSize)
		// Client EPK sits at wire bytes [32:64]; bit 255 is MSB of byte[63].
		if cliSegs[0][HandshakeSaltSize+EPKSize-1]&0x80 != 0 {
			clientBit1Count++
		}

		srvSegs := capSrv.snapshotSegments()
		require.NotEmpty(t, srvSegs)
		require.GreaterOrEqual(t, len(srvSegs[0]), HandshakeSaltSize+EPKSize)
		// Server EPK sits at response wire bytes [32:64]; bit 255 is MSB of byte[63].
		if srvSegs[0][HandshakeSaltSize+EPKSize-1]&0x80 != 0 {
			serverBit1Count++
		}
	}

	cliRatio := float64(clientBit1Count) / trials
	srvRatio := float64(serverBit1Count) / trials
	require.InDelta(t, 0.5, cliRatio, 0.15, "client wire EPK bit 255 must be uniformly masked (got %d/%d)", clientBit1Count, trials)
	require.InDelta(t, 0.5, srvRatio, 0.15, "server wire EPK bit 255 must be uniformly masked (got %d/%d)", serverBit1Count, trials)
}
