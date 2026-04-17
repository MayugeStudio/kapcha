package main

import (
	"bytes"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	_"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/widget"
	_"image/color"
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

func handlePacket(p gopacket.Packet) EtherFrame {
	header := p.LinkLayer().LayerContents()
	etherDstMAC, _ := net.ParseMAC(fmt.Sprintf("%X", header[0:6]))
	etherSrcMAC, _ := net.ParseMAC(fmt.Sprintf("%X", header[6:12]))
	etherType := EtherType(header[12:14])

	return EtherFrame{
		DstMAC: etherDstMAC,
		SrcMAC: etherSrcMAC,
		Type: etherType,
	}
}

func main() {
	myApp := app.New()
	window := myApp.NewWindow("Hello")
	window.Resize(fyne.NewSize(800, 600))


	// eth0
	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Decode a packet
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	packets := make(chan EtherFrame, 100)

	var data []EtherFrame

	go func() {
		for packet := range packetSource.Packets() {
			packets <- handlePacket(packet)
		}
	}()

	table := widget.NewTable(
		func() (int, int) {
			return len(data)+1, 3
		},

		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},

		func(id widget.TableCellID, obj fyne.CanvasObject) {
			label := obj.(*widget.Label)

			if id.Row == 0 {
				headers := []string{"Type", "Source MAC", "Destination MAC"}
				label.SetText(headers[id.Col])
				return
			}

			p := data[id.Row-1]
			switch id.Col {
			case 0:
				label.SetText(p.Type.String())
			case 1:
				label.SetText(p.SrcMAC.String())
			case 2:
				label.SetText(p.DstMAC.String())
			}
		},
	)
	table.SetColumnWidth(0, 80)
	table.SetColumnWidth(1, 150)
	table.SetColumnWidth(2, 200)

	go func() {
		for p := range packets {
			fyne.Do(func () {
				if len(data) >= 50 {
					data = data[1:]
				}
				data = append(data, p)
				table.Refresh()
			})
		}
	}()
	window.SetContent(table)
	window.ShowAndRun()
}
