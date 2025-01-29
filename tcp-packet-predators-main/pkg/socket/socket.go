package socket

import (
	"net/netip"
)

type (
	

	VTCPListener struct {
	}

	VTCPConn struct {
	}
)

func VListen(port uint16) (*VTCPListener, error)

func (*VTCPListener) VAccept() (*VTCPConn, error)

func (*VTCPListener) VClose() error

func VConnect(addr netip.Addr, port int16) (VTCPConn, error)

func (*VTCPConn) VRead(buf []byte) (int, error)

func (*VTCPConn) VWrite(data []byte) (int, error)

func (*VTCPConn) VClose() error
