package main

import "fmt"

type ArpPacket struct {
	HardwareType 		    [2]byte
	ProtocolType 		    [2]byte
	HardwareLength	    byte
	ProtocolLength 	    byte
	Operation			      [2]byte

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

func (a ArpPacket) String() string {
	return fmt.Sprintf("MAC: %X / IP: %s -> MAC: %X / IP: %s", 
		a.SenderHardwareAddr,
		IPaddrToString(a.SenderProtocolAddr),
		a.DestHardwareAddr,
		IPaddrToString(a.DestProtocolAddr),
	)
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



