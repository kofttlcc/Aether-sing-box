package aether

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ErrPacketTooLarge is returned when a UDP datagram payload exceeds uint16 max (65535 bytes).
var ErrPacketTooLarge = errors.New("aether: UDP packet payload exceeds 65535 bytes")

var (
	_ N.PacketConn         = (*ClientPacketConn)(nil)
	_ net.PacketConn       = (*ClientPacketConn)(nil)
	_ N.EarlyWriter        = (*ClientPacketConn)(nil)
	_ N.EarlyReader        = (*ClientPacketConn)(nil)
	_ N.EarlyConn          = (*ClientPacketConn)(nil)
	_ N.FrontHeadroom      = (*ClientPacketConn)(nil)
	_ N.RearHeadroom       = (*ClientPacketConn)(nil)
	_ N.ReaderWithUpstream = (*ClientPacketConn)(nil)
	_ N.WriterWithUpstream = (*ClientPacketConn)(nil)
	_ common.WithUpstream  = (*ClientPacketConn)(nil)

	_ N.PacketConn         = (*ServerPacketConn)(nil)
	_ net.PacketConn       = (*ServerPacketConn)(nil)
	_ N.EarlyWriter        = (*ServerPacketConn)(nil)
	_ N.EarlyReader        = (*ServerPacketConn)(nil)
	_ N.EarlyConn          = (*ServerPacketConn)(nil)
	_ N.FrontHeadroom      = (*ServerPacketConn)(nil)
	_ N.RearHeadroom       = (*ServerPacketConn)(nil)
	_ N.ReaderWithUpstream = (*ServerPacketConn)(nil)
	_ N.WriterWithUpstream = (*ServerPacketConn)(nil)
	_ common.WithUpstream  = (*ServerPacketConn)(nil)
)

type packetConnBase struct {
	conn    *Conn
	writeMu sync.Mutex
	readMu  sync.Mutex
	br      *bufio.Reader

	// Partial datagram header & payload state preserved across SetReadDeadline timeouts.
	hdrBuf        [M.MaxSocksaddrLength + 2]byte
	hdrOff        int
	hasPendingHdr bool
	pendingDest   M.Socksaddr
	pendingLen    int
	partialBuf    []byte
	partialOff    int
}

func newPacketConnBase(conn *Conn) *packetConnBase {
	if conn == nil {
		return &packetConnBase{}
	}
	return &packetConnBase{
		conn: conn,
		br:   bufio.NewReaderSize(conn, MaxFrameDataSize),
	}
}

// ClientPacketConn implements native CommandUDP (0x02) datagram tunneling for Aether clients.
type ClientPacketConn struct {
	*packetConnBase
}

// NewClientPacketConn wraps an Aether v2 client Conn configured for CommandUDP.
func NewClientPacketConn(conn *Conn) *ClientPacketConn {
	return &ClientPacketConn{packetConnBase: newPacketConnBase(conn)}
}

// ServerPacketConn implements native CommandUDP (0x02) datagram tunneling for Aether servers.
type ServerPacketConn struct {
	*packetConnBase
}

// NewServerPacketConn wraps an accepted Aether v2 server Conn configured for CommandUDP.
func NewServerPacketConn(conn *Conn) *ServerPacketConn {
	return &ServerPacketConn{packetConnBase: newPacketConnBase(conn)}
}

func (p *packetConnBase) NeedHandshakeForWrite() bool {
	return p.conn.NeedHandshakeForWrite()
}

func (p *packetConnBase) NeedHandshakeForRead() bool {
	return p.conn.NeedHandshakeForRead()
}

func (p *packetConnBase) NeedHandshake() bool {
	return p.conn.NeedHandshake()
}

func (p *packetConnBase) FrontHeadroom() int {
	return 0
}

func (p *packetConnBase) RearHeadroom() int {
	return 0
}

func (p *packetConnBase) Upstream() any {
	return p.conn
}

func (p *packetConnBase) ReaderReplaceable() bool {
	return false
}

func (p *packetConnBase) WriterReplaceable() bool {
	return false
}

func (p *packetConnBase) Close() error {
	if p.conn == nil {
		return nil
	}
	return p.conn.Close()
}

func (p *packetConnBase) LocalAddr() net.Addr {
	if p.conn == nil {
		return nil
	}
	return p.conn.LocalAddr()
}

func (p *packetConnBase) RemoteAddr() net.Addr {
	if p.conn == nil {
		return nil
	}
	return p.conn.RemoteAddr()
}

func (p *packetConnBase) SetDeadline(t time.Time) error {
	return p.conn.SetDeadline(t)
}

func (p *packetConnBase) SetReadDeadline(t time.Time) error {
	return p.conn.SetReadDeadline(t)
}

func (p *packetConnBase) SetWriteDeadline(t time.Time) error {
	return p.conn.SetWriteDeadline(t)
}

// WritePacket serializes [Socksaddr][PayloadLen uint16 BE][Payload] over the underlying
// Aether Conn, supporting 0..65535 byte payloads across multiple 16384B frames.
// buffer is unconditionally released on every return path.
func (p *packetConnBase) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if buffer != nil {
		defer buffer.Release()
	}
	if p.conn == nil {
		return net.ErrClosed
	}
	if buffer == nil {
		return errors.New("aether: nil packet buffer")
	}
	if !destination.IsValid() {
		return fmt.Errorf("%w: invalid UDP destination", ErrInvalidVarHeader)
	}
	payloadLen := buffer.Len()
	if payloadLen > math.MaxUint16 {
		return fmt.Errorf("%w: %d", ErrPacketTooLarge, payloadLen)
	}

	addrLen := M.SocksaddrSerializer.AddrPortLen(destination)
	totalLen := addrLen + 2 + payloadLen

	pkt := buf.NewSize(totalLen)
	defer pkt.Release()

	if err := M.SocksaddrSerializer.WriteAddrPort(pkt, destination); err != nil {
		return err
	}
	binary.BigEndian.PutUint16(pkt.Extend(2), uint16(payloadLen))
	if payloadLen > 0 {
		if _, err := pkt.Write(buffer.Bytes()); err != nil {
			return err
		}
	}

	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	_, err := p.conn.Write(pkt.Bytes())
	return err
}

func (p *packetConnBase) readHeaderBytesLocked(target int) error {
	for p.hdrOff < target {
		n, err := p.br.Read(p.hdrBuf[p.hdrOff:target])
		if n > 0 {
			p.hdrOff += n
			if p.hdrOff >= target {
				return nil
			}
		}
		if err != nil {
			if isTimeoutError(err) {
				return err
			}
			hadPartial := p.hdrOff > 0
			p.hdrOff = 0
			if errors.Is(err, io.EOF) {
				if hadPartial {
					return io.ErrUnexpectedEOF
				}
				return io.EOF
			}
			return err
		}
	}
	return nil
}

// ReadPacket reassembles the next [Socksaddr][PayloadLen uint16 BE][Payload] datagram
// into buffer without ever calling buffer.Release().
func (p *packetConnBase) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if p.conn == nil {
		return M.Socksaddr{}, net.ErrClosed
	}
	if buffer == nil {
		return M.Socksaddr{}, errors.New("aether: nil packet buffer")
	}

	p.readMu.Lock()
	defer p.readMu.Unlock()

	if !p.hasPendingHdr {
		if err := p.readHeaderBytesLocked(1); err != nil {
			return M.Socksaddr{}, err
		}
		var hdrNeed int
		switch p.hdrBuf[0] {
		case 0x01:
			hdrNeed = 1 + 4 + 2 + 2
		case 0x04:
			hdrNeed = 1 + 16 + 2 + 2
		case 0x03:
			if err := p.readHeaderBytesLocked(2); err != nil {
				return M.Socksaddr{}, err
			}
			fqdnLen := int(p.hdrBuf[1])
			if fqdnLen == 0 {
				p.hdrOff = 0
				return M.Socksaddr{}, fmt.Errorf("%w: empty UDP FQDN", ErrInvalidVarHeader)
			}
			hdrNeed = 1 + 1 + fqdnLen + 2 + 2
		default:
			af := p.hdrBuf[0]
			p.hdrOff = 0
			return M.Socksaddr{}, fmt.Errorf("%w: unknown address family: %d", ErrInvalidVarHeader, af)
		}

		if err := p.readHeaderBytesLocked(hdrNeed); err != nil {
			return M.Socksaddr{}, err
		}

		dest, err := M.SocksaddrSerializer.ReadAddrPort(bytes.NewReader(p.hdrBuf[:hdrNeed-2]))
		if err != nil || !dest.IsValid() {
			p.hdrOff = 0
			if err != nil {
				return M.Socksaddr{}, fmt.Errorf("%w: %v", ErrInvalidVarHeader, err)
			}
			return M.Socksaddr{}, fmt.Errorf("%w: invalid UDP address", ErrInvalidVarHeader)
		}
		payloadLen := int(binary.BigEndian.Uint16(p.hdrBuf[hdrNeed-2 : hdrNeed]))
		p.hdrOff = 0
		p.pendingDest = dest
		p.pendingLen = payloadLen
		p.partialOff = 0
		p.hasPendingHdr = true
	}

	payloadLen := p.pendingLen
	dest := p.pendingDest

	if payloadLen == 0 {
		p.hasPendingHdr = false
		return dest, nil
	}

	if cap(p.partialBuf) < payloadLen {
		p.partialBuf = make([]byte, payloadLen)
	} else {
		p.partialBuf = p.partialBuf[:payloadLen]
	}
	for p.partialOff < payloadLen {
		n, err := p.br.Read(p.partialBuf[p.partialOff:payloadLen])
		if n > 0 {
			p.partialOff += n
			if p.partialOff >= payloadLen {
				break
			}
		}
		if err != nil {
			if isTimeoutError(err) {
				return M.Socksaddr{}, err
			}
			p.hasPendingHdr = false
			p.partialOff = 0
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return M.Socksaddr{}, err
		}
	}

	p.hasPendingHdr = false
	p.partialOff = 0
	if payloadLen > buffer.FreeLen() {
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	if _, err := buffer.Write(p.partialBuf[:payloadLen]); err != nil {
		return M.Socksaddr{}, err
	}
	return dest, nil
}

// ReadFrom implements net.PacketConn.ReadFrom on top of ReadPacket.
func (p *packetConnBase) ReadFrom(b []byte) (int, net.Addr, error) {
	buffer := buf.With(b)
	dest, err := p.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	var addr net.Addr
	if dest.IsIP() {
		addr = dest.UDPAddr()
	} else {
		addr = dest
	}
	return buffer.Len(), addr, nil
}

// WriteTo implements net.PacketConn.WriteTo on top of WritePacket.
func (p *packetConnBase) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, fmt.Errorf("%w: nil destination address", ErrInvalidVarHeader)
	}
	dest := M.SocksaddrFromNet(addr)
	buffer := buf.As(b)
	if err := p.WritePacket(buffer, dest); err != nil {
		return 0, err
	}
	return len(b), nil
}
