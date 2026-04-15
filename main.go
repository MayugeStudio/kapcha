package main

import (
	"log"
	"bytes"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	_ "github.com/google/gopacket/layers"
)

type MacAddress []byte

func (m MacAddress) String() string {
	result := ""
	for i := 0; i<6; i++ {
		if (i != 0) {
			result += ":"
		}
		result += fmt.Sprintf("%0X", m[i])
	}
	return result
}

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

func handlePacket(p gopacket.Packet) {
	header := p.LinkLayer().LayerContents()
	etherDstMac := MacAddress(header[0:6])
	etherSrcMac := MacAddress(header[6:12])
	etherType := EtherType(header[12:14])

	fmt.Printf("[%s]: %s -> %s\n", etherType, etherSrcMac.String(), etherDstMac.String())
	//header = header[:8]
}

func main() {
	// eth0
	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Decode a packet
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		handlePacket(packet)  // Do something with each packet.
	}
}

