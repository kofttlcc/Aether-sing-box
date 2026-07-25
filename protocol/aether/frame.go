package aether

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

const (
	AtypIPv4   byte = 0x01
	AtypDomain byte = 0x03
	AtypIPv6   byte = 0x04
)

type Header struct {
	Timestamp int64
	Nonce     uint64
	Noise     []byte
	Address   string
	Port      uint16
	Payload   []byte
}

func EncodeAddress(addr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address format: %w", err)
	}

	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port number: %w", err)
	}

	var buf []byte
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, AtypIPv4)
			buf = append(buf, ip4...)
		} else {
			buf = append(buf, AtypIPv6)
			buf = append(buf, ip.To16()...)
		}
	} else {
		buf = append(buf, AtypDomain)
		if len(host) > 255 {
			return nil, errors.New("domain name too long")
		}
		buf = append(buf, byte(len(host)))
		buf = append(buf, []byte(host)...)
	}

	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(portNum))
	buf = append(buf, portBytes[:]...)

	return buf, nil
}

func DecodeAddress(b []byte) (string, int, error) {
	if len(b) < 2 {
		return "", 0, ErrInvalidHeader
	}

	atyp := b[0]
	var host string
	var offset int

	switch atyp {
	case AtypIPv4:
		if len(b) < 1+4+2 {
			return "", 0, ErrShortBuffer
		}
		ip := net.IP(b[1:5])
		host = ip.String()
		offset = 1 + 4
	case AtypIPv6:
		if len(b) < 1+16+2 {
			return "", 0, ErrShortBuffer
		}
		ip := net.IP(b[1:17])
		host = ip.String()
		offset = 1 + 16
	case AtypDomain:
		domainLen := int(b[1])
		if len(b) < 1+1+domainLen+2 {
			return "", 0, ErrShortBuffer
		}
		host = string(b[2 : 2+domainLen])
		offset = 1 + 1 + domainLen
	default:
		return "", 0, ErrInvalidHeader
	}

	port := binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2

	return net.JoinHostPort(host, strconv.Itoa(int(port))), offset, nil
}

func PackHeader(timestamp int64, nonce uint64, noise []byte, targetAddr string, initialData []byte) ([]byte, error) {
	encodedAddr, err := EncodeAddress(targetAddr)
	if err != nil {
		return nil, err
	}

	totalLen := 8 + 8 + 1 + len(noise) + len(encodedAddr) + len(initialData)
	buf := make([]byte, totalLen)

	binary.BigEndian.PutUint64(buf[0:8], uint64(timestamp))
	binary.BigEndian.PutUint64(buf[8:16], nonce)
	buf[16] = byte(len(noise))

	copy(buf[17:17+len(noise)], noise)
	curr := 17 + len(noise)

	copy(buf[curr:curr+len(encodedAddr)], encodedAddr)
	curr += len(encodedAddr)

	if len(initialData) > 0 {
		copy(buf[curr:], initialData)
	}

	return buf, nil
}

func UnpackHeader(b []byte) (*Header, error) {
	if len(b) < 8+8+1 {
		return nil, ErrInvalidHeader
	}

	ts := int64(binary.BigEndian.Uint64(b[0:8]))
	nonce := binary.BigEndian.Uint64(b[8:16])
	noiseLen := int(b[16])

	if len(b) < 17+noiseLen {
		return nil, ErrInvalidHeader
	}

	noise := make([]byte, noiseLen)
	copy(noise, b[17:17+noiseLen])
	rem := b[17+noiseLen:]

	addr, offset, err := DecodeAddress(rem)
	if err != nil {
		return nil, err
	}

	payload := rem[offset:]

	return &Header{
		Timestamp: ts,
		Nonce:     nonce,
		Noise:     noise,
		Address:   addr,
		Payload:   payload,
	}, nil
}
