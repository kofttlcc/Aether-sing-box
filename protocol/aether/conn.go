package aether

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	MaxChunkSize = 16384

	FrameData byte = 0x00
	FramePing byte = 0x01
	FramePong byte = 0x02
)

type Conn struct {
	net.Conn
	session  *CipherSession
	isClient bool

	readBuf []byte
	readPos int

	writeMu sync.Mutex
	readMu  sync.Mutex

	sendSeq uint64
	recvSeq uint64

	lastRead  atomic.Int64
	lastWrite atomic.Int64

	closeOnce sync.Once
	closed    chan struct{}
}

func (c *Conn) touchRead() {
	c.lastRead.Store(time.Now().UnixMilli())
}

func (c *Conn) touchWrite() {
	c.lastWrite.Store(time.Now().UnixMilli())
}

func (c *Conn) startKeepAlive(intervalSec int) {
	if intervalSec <= 0 {
		return
	}
	interval := time.Duration(intervalSec) * time.Second
	go func() {
		ticker := time.NewTicker(interval / 2)
		defer ticker.Stop()

		for {
			select {
			case <-c.closed:
				return
			case <-ticker.C:
				now := time.Now().UnixMilli()
				lastW := c.lastWrite.Load()
				if now-lastW >= interval.Milliseconds() {
					_ = c.sendControlFrame(FramePing)
				}
			}
		}
	}()
}

func (c *Conn) sendControlFrame(frameType byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	payload := []byte{frameType}
	encrypted := c.session.EncryptChunk(nil, payload)

	chunkLen := uint16(len(encrypted))
	maskedLen := MaskLength(chunkLen, c.session.MaskKey(), c.sendSeq)
	c.sendSeq++

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], maskedLen)

	if _, err := c.Conn.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := c.Conn.Write(encrypted); err != nil {
		return err
	}

	c.touchWrite()
	return nil
}

func NewClientConn(rawConn net.Conn, psk [KeySize]byte, targetAddr string, initialData []byte, heartbeatSec int) (*Conn, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}

	session, err := NewCipherSession(psk, salt, true)
	if err != nil {
		return nil, err
	}

	noise, err := GenerateRandomNoise(MinNoisePadding, MaxNoisePadding)
	if err != nil {
		return nil, err
	}

	var nonceBuf [8]byte
	if _, err := rand.Read(nonceBuf[:]); err != nil {
		return nil, err
	}
	nonce := binary.BigEndian.Uint64(nonceBuf[:])

	timestamp := time.Now().UnixMilli()

	headerBytes, err := PackHeader(timestamp, nonce, noise, targetAddr, initialData)
	if err != nil {
		return nil, err
	}

	c := &Conn{
		Conn:     rawConn,
		session:  session,
		isClient: true,
		closed:   make(chan struct{}),
	}
	c.touchRead()
	c.touchWrite()

	encryptedHeader := session.EncryptChunk(nil, headerBytes)
	chunkLen := uint16(len(encryptedHeader))
	maskedLen := MaskLength(chunkLen, session.MaskKey(), c.sendSeq)
	c.sendSeq++

	wireBuf := make([]byte, SaltSize+2+len(encryptedHeader))
	copy(wireBuf[0:SaltSize], salt[:])
	binary.BigEndian.PutUint16(wireBuf[SaltSize:SaltSize+2], maskedLen)
	copy(wireBuf[SaltSize+2:], encryptedHeader)

	if _, err := rawConn.Write(wireBuf); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	c.startKeepAlive(heartbeatSec)
	return c, nil
}

func NewServerConn(rawConn net.Conn, psk [KeySize]byte, replayFilter *ReplayFilter, heartbeatSec int) (*Conn, *Header, error) {
	var salt [SaltSize]byte
	if _, err := io.ReadFull(rawConn, salt[:]); err != nil {
		HandleProbe(rawConn)
		return nil, nil, err
	}

	session, err := NewCipherSession(psk, salt, false)
	if err != nil {
		HandleProbe(rawConn)
		return nil, nil, err
	}

	c := &Conn{
		Conn:     rawConn,
		session:  session,
		isClient: false,
		closed:   make(chan struct{}),
	}
	c.touchRead()
	c.touchWrite()

	var lenBuf [2]byte
	if _, err := io.ReadFull(rawConn, lenBuf[:]); err != nil {
		HandleProbe(rawConn)
		return nil, nil, err
	}

	maskedLen := binary.BigEndian.Uint16(lenBuf[:])
	chunkLen := UnmaskLength(maskedLen, session.MaskKey(), c.recvSeq)
	c.recvSeq++

	if chunkLen > MaxChunkSize+TagSize {
		HandleProbe(rawConn)
		return nil, nil, ErrInvalidHeader
	}

	encryptedHeader := make([]byte, chunkLen)
	if _, err := io.ReadFull(rawConn, encryptedHeader); err != nil {
		HandleProbe(rawConn)
		return nil, nil, err
	}

	headerBytes, err := session.DecryptChunk(nil, encryptedHeader)
	if err != nil {
		HandleProbe(rawConn)
		return nil, nil, err
	}

	header, err := UnpackHeader(headerBytes)
	if err != nil {
		HandleProbe(rawConn)
		return nil, nil, err
	}

	if replayFilter != nil {
		if !replayFilter.CheckAndAdd(header.Timestamp, header.Nonce) {
			HandleProbe(rawConn)
			return nil, nil, ErrReplayDetected
		}
	}

	c.startKeepAlive(heartbeatSec)
	return c, header, nil
}

func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for {
		if c.readPos < len(c.readBuf) {
			n := copy(b, c.readBuf[c.readPos:])
			c.readPos += n
			return n, nil
		}

		var lenBuf [2]byte
		if _, err := io.ReadFull(c.Conn, lenBuf[:]); err != nil {
			return 0, err
		}

		maskedLen := binary.BigEndian.Uint16(lenBuf[:])
		chunkLen := UnmaskLength(maskedLen, c.session.MaskKey(), c.recvSeq)
		c.recvSeq++

		if chunkLen > MaxChunkSize+TagSize {
			return 0, ErrInvalidHeader
		}

		encrypted := make([]byte, chunkLen)
		if _, err := io.ReadFull(c.Conn, encrypted); err != nil {
			return 0, err
		}

		plaintext, err := c.session.DecryptChunk(nil, encrypted)
		if err != nil {
			return 0, err
		}
		c.touchRead()

		if len(plaintext) > 0 {
			switch plaintext[0] {
			case FramePing:
				_ = c.sendControlFrame(FramePong)
				continue
			case FramePong:
				continue
			case FrameData:
				data := plaintext[1:]
				n := copy(b, data)
				if n < len(data) {
					c.readBuf = data
					c.readPos = n
				} else {
					c.readBuf = nil
					c.readPos = 0
				}
				return n, nil
			default:
				// 向下兼容：如果不含帧标记
				n := copy(b, plaintext)
				if n < len(plaintext) {
					c.readBuf = plaintext
					c.readPos = n
				} else {
					c.readBuf = nil
					c.readPos = 0
				}
				return n, nil
			}
		}
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := len(b)
	written := 0

	for written < total {
		chunkSize := total - written
		if chunkSize > MaxChunkSize-1 {
			chunkSize = MaxChunkSize - 1
		}

		chunk := make([]byte, 1+chunkSize)
		chunk[0] = FrameData
		copy(chunk[1:], b[written:written+chunkSize])

		encrypted := c.session.EncryptChunk(nil, chunk)

		chunkLen := uint16(len(encrypted))
		maskedLen := MaskLength(chunkLen, c.session.MaskKey(), c.sendSeq)
		c.sendSeq++

		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], maskedLen)

		if _, err := c.Conn.Write(lenBuf[:]); err != nil {
			return written, err
		}
		if _, err := c.Conn.Write(encrypted); err != nil {
			return written, err
		}

		c.touchWrite()
		written += chunkSize
	}

	return written, nil
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return c.Conn.Close()
}
