package aether

import (
	"net"
	"time"
)

func HandleProbe(conn net.Conn) {
	if conn == nil {
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))

	buf := make([]byte, 1024)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			break
		}
	}

	_ = conn.Close()
}
