package main

import (
	"fmt"
	"bytes"
	"net"
)

type EtherType []byte

func (e EtherType) String() string {
	switch {
	case bytes.Equal(e, []byte{0x08, 0x00}):
		return "IPv4"
	case bytes.Equal(e, []byte{0x08, 0x06}):
		return "ARP"
	case bytes.Equal(e, []byte{0x86, 0xDD}):
		return "IPv6"
	default:
		return "Other: " + fmt.Sprintf("%02X%0X", e[0], e[1])
	}
}

type EtherFrame struct {
	DstMAC net.HardwareAddr
	SrcMAC net.HardwareAddr
	Type EtherType
}

func (e EtherFrame) String() string {
	return fmt.Sprintf("[%s]: %s -> %s", e.Type, e.SrcMAC, e.DstMAC)
}
