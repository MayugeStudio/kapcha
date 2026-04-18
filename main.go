package main

import (
	"fmt"
	"log"
	_"net"

	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	_"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/widget"
	_"image/color"
)

func handlePacket(p gopacket.Packet) EtherFrame {
	contents := p.LinkLayer().LayerContents()
	etherDstMAC := contents[0:6]
	etherSrcMAC := contents[6:12]
	etherType := BytesToEtherType(contents[12:14])
	payload := p.LinkLayer().LayerPayload()
	var packet Packet
	if (etherType == ET_ARP) {
		packet = NewArpPacket(payload)
	}

	ef := EtherFrame{
		Type: etherType,
		RawPayload: payload,
		Packet: packet,
	}
	copy(ef.DstMAC[:], etherDstMAC)
	copy(ef.SrcMAC[:], etherSrcMAC)

	return ef
}

func main() {
	myApp := app.New()
	window := myApp.NewWindow("Hello")
	window.Resize(fyne.NewSize(1000, 800))

	var data []EtherFrame

	table := widget.NewTable(
		func() (int, int) {
			return len(data), 5
		},

		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},

		func(id widget.TableCellID, obj fyne.CanvasObject) {
			label := obj.(*widget.Label)

			if len(data) == 0 {
				return
			}

			p := data[id.Row]
			switch id.Col {
			case 0:
				label.SetText(p.Type.String())
			case 1:
				label.SetText(fmt.Sprintf("%X", p.SrcMAC))
			case 2:
				label.SetText(fmt.Sprintf("%X", p.DstMAC))
			case 3:
				label.SetText(p.Packet.(ArpPacket).SenderToString())
			case 4:
				label.SetText(p.Packet.(ArpPacket).DestToString())
			}
		},
	)
	table.SetColumnWidth(0, 80)
	table.SetColumnWidth(1, 150)
	table.SetColumnWidth(2, 200)
	table.SetColumnWidth(3, 300)
	table.SetColumnWidth(4, 300)

	table.ShowHeaderRow = true;
	table.CreateHeader = func() fyne.CanvasObject {
		return widget.NewLabel("")
	}
	table.UpdateHeader = func(id widget.TableCellID, template fyne.CanvasObject) {
		if id.Row == -1 {
			label := template.(*widget.Label)
			headers := []string{"Type", "Sender MAC", "Destination MAC", "Sender Info", "Destination Info"}
			label.SetText(headers[id.Col])
		}
	}

	window.SetContent(table)

	arpMenuItem := fyne.NewMenuItem("arp", func(){})
	ipv4MenuItem := fyne.NewMenuItem("ipv4", func(){})
	ipv6MenuItem := fyne.NewMenuItem("ipv6", func(){})
	protocolMenu := fyne.NewMenu("Select Protocol", arpMenuItem, ipv4MenuItem, ipv6MenuItem)

	mainmenu := fyne.NewMainMenu(protocolMenu)
	window.SetMainMenu(mainmenu)

	// Create handle from the network interface.
	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Decode a packet
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := make(chan EtherFrame, 100)
	go func() {
		for packet := range packetSource.Packets() {
			etherFrame := handlePacket(packet)
			if (etherFrame.Type == ET_ARP) {
				packets <- etherFrame
			}
		}
	}()

	go func() {
		for p := range packets {
			fyne.Do(func () {
				data = append(data, p)
				table.Refresh()
				table.ScrollToBottom();
			})
		}
	}()

	window.ShowAndRun()
}
