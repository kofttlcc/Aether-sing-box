package aether

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

const (
	MaxChunkSize = 16384
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
}

func NewClientConn(rawConn net.Conn, psk [KeySize]byte, targetAddr string, initialData []byte) (*Conn, error) {
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
	}

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

	return c, nil
}

func NewServerConn(rawConn net.Conn, psk [KeySize]byte, replayFilter *ReplayFilter) (*Conn, *Header, error) {
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
	}

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

	return c, header, nil
}

func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

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

func (c *Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := len(b)
	written := 0

	for written < total {
		chunkSize := total - written
		if chunkSize > MaxChunkSize {
			chunkSize = MaxChunkSize
		}

		chunk := b[written : written+chunkSize]
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

		written += chunkSize
	}

	return written, nil
}
