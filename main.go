package main

import (
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

	var data []EtherFrame

	table := widget.NewTable(
		func() (int, int) {
			return len(data), 3
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
				label.SetText(p.SrcMAC.String())
			case 2:
				label.SetText(p.DstMAC.String())
			}
		},
	)
	table.SetColumnWidth(0, 80)
	table.SetColumnWidth(1, 150)
	table.SetColumnWidth(2, 200)
	table.ShowHeaderRow = true;
	table.CreateHeader = func() fyne.CanvasObject {
		return widget.NewLabel("")
	}
	table.UpdateHeader = func(id widget.TableCellID, template fyne.CanvasObject) {
		if id.Row == -1 {
			label := template.(*widget.Label)
			headers := []string{"Type", "Source MAC", "Destination MAC"}
			label.SetText(headers[id.Col])
		}
	}

	// Create handle from the network interface.
	handle, err := pcap.OpenLive("en5", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Decode a packet
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := make(chan EtherFrame, 100)
	go func() {
		for packet := range packetSource.Packets() {
			packets <- handlePacket(packet)
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

	window.SetContent(table)
	window.ShowAndRun()
}
