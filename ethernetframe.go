package main

import "bytes"

type EtherType int

const (
	ET_ARP EtherType = iota
	ET_IPv4
	ET_IPv6
	ET_Other
)

func (e EtherType) String() string {
	switch e {
	case ET_ARP:
		return "ARP"
	case ET_IPv4:
		return "IPv4"
	case ET_IPv6:
		return "IPv6"
	default:
		return "Other"
	}
}

func BytesToEtherType(e []byte) EtherType {
	switch {
	case bytes.Equal(e, []byte{0x08, 0x06}):
		return ET_ARP
	case bytes.Equal(e, []byte{0x08, 0x00}):
		return ET_IPv4
	case bytes.Equal(e, []byte{0x86, 0xDD}):
		return ET_IPv6
	default:
		return ET_Other
	}
}


type EtherFrame struct {
	DstMAC [6]byte
	SrcMAC [6]byte
	Type EtherType
	RawPayload []byte
	Packet Packet
}

