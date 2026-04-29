package main

import "fmt"

type ArpPacket struct {
	HardwareType 		    [2]byte
	ProtocolType 		    [2]byte
	HardwareLength	    byte
	ProtocolLength 	    byte

  Operation			      [2]byte // opcode (ares_op$REQUEST | ares_op$REPLY)


	SenderHardwareAddr  [6]byte
	SenderProtocolAddr  [4]byte	

	DestHardwareAddr 		[6]byte
	DestProtocolAddr    [4]byte
}

// TODO: Introduce new type for IP address and Hardware address
func IPaddrToString(rawaddr [4]byte) string {
	var result string
	for i := 0; i < 4; i++ {
		if i != 0 {
			result += "."
		}
		result += fmt.Sprintf("%d", rawaddr[i])
	}
	return result
}

func MACaddrToString(rawaddr [6]byte) string {
	var result string
	for i := 0; i < 6; i++ {
		if i != 0 {
			result += ":"
		}
		result += fmt.Sprintf("%X", rawaddr[i])
	}
	return result
}

func (a ArpPacket) String() string {
	opstr := ""
	if a.Operation == [2]byte{0, 1} {
		opstr = "Request"
	} else {
		opstr = "Reply"
	}
	return fmt.Sprintf("%s: MAC: %s / IP: %s -> MAC: %s / IP: %s", 
		opstr,
		MACaddrToString(a.SenderHardwareAddr),
		IPaddrToString(a.SenderProtocolAddr),
		MACaddrToString(a.DestHardwareAddr),
		IPaddrToString(a.DestProtocolAddr),
	)
}

func (a ArpPacket) SenderToString() string {
	return fmt.Sprintf("MAC: %s, IP: %s", 
		MACaddrToString(a.SenderHardwareAddr),
		IPaddrToString(a.SenderProtocolAddr),
	)
}

func (a ArpPacket) DestToString() string {
	return fmt.Sprintf("MAC: %s, IP: %s",
		MACaddrToString(a.DestHardwareAddr),
		IPaddrToString(a.DestProtocolAddr),
	)
}

func (a ArpPacket) Dest() string {
	return MACaddrToString(a.DestHardwareAddr)
}

func (a ArpPacket) Sender() string {
	return MACaddrToString(a.SenderHardwareAddr)
}

func (a ArpPacket) Info() string {
	return a.String()
}

func NewArpPacket(data []byte) ArpPacket {
	// if len(data) < 42 {
	// 	panic("arp packet length is less than 42 bytes")
	// }

	ap := ArpPacket{}

	copy(ap.HardwareType[:], data[0:2])
	copy(ap.ProtocolType[:], data[2:4])
	ap.HardwareLength = data[4]
	ap.ProtocolLength = data[5]
	copy(ap.Operation[:], data[6:8])
	copy(ap.SenderHardwareAddr[:], data[8:14])
	copy(ap.SenderProtocolAddr[:], data[14:18])
	copy(ap.DestHardwareAddr[:], data[18:24])
	copy(ap.DestProtocolAddr[:], data[24:28])

	return ap;
}

