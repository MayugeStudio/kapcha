package main

import (
	"fmt"
	"log"
	_"net"
	"context"

	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	_"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	_"image/color"
)


// Captured etherFrame
var dataForDisplay []EtherFrame
var packets chan EtherFrame

func createEtherframeFromPacket(p gopacket.Packet) EtherFrame {
	contents := p.LinkLayer().LayerContents()
	etherDstMAC := contents[0:6]
	etherSrcMAC := contents[6:12]
	etherType := BytesToEtherType(contents[12:14])
	payload := p.LinkLayer().LayerPayload()
	var packet Packet
	if (etherType == ET_ARP) {
		packet = NewArpPacket(payload)
	}

	fmt.Println(packet)

	ef := EtherFrame{
		Type: etherType,
		RawPayload: payload,
		Packet: packet,
	}
	copy(ef.DstMAC[:], etherDstMAC)
	copy(ef.SrcMAC[:], etherSrcMAC)

	return ef
}

func startCapture(ctx context.Context, interfaceName string) {
	// Create handle from the network interface.
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	// Decode a packet
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("startCapture was called")
	fmt.Println(handle)
	fmt.Println(packetSource)
	go func() {
		defer handle.Close()

		for {
			select {
			case <-ctx.Done():
				return
			case packet, ok := <-packetSource.Packets():
				fmt.Println(packet)
				if !ok {
					return
				}
				etherFrame := createEtherframeFromPacket(packet)
				if (etherFrame.Type == ET_ARP) {
					packets <- etherFrame
				}
			}
		}
	}()
}

func main() {
	packets = make(chan EtherFrame, 100)

	myApp := app.New()
	window := myApp.NewWindow("Hello")
	window.Resize(fyne.NewSize(1000, 800))

	interfaceName := "en0"

	ctx, captureCancel := context.WithCancel(context.Background())
	startCapture(ctx, interfaceName)

	startButton := widget.NewButton("Start", func() {
		if captureCancel != nil {
			captureCancel()
		}
		ctx, c := context.WithCancel(context.Background())
		captureCancel = c
		startCapture(ctx, interfaceName)
	})
	stopButton := widget.NewButton("Stop", func() {
		if captureCancel != nil {
			captureCancel()
		}
	})
	toolbar := container.NewHBox(startButton, stopButton)

	table := widget.NewTable(
		func() (int, int) {
			return len(dataForDisplay), 4
		},

		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},

		func(id widget.TableCellID, obj fyne.CanvasObject) {
			label := obj.(*widget.Label)

			if len(dataForDisplay) == 0 {
				return
			}

			p := dataForDisplay[id.Row]
			switch id.Col {
			case 0:
				label.SetText(p.Type.String())
			case 1:
				label.SetText(p.Packet.Sender())
			case 2:
				label.SetText(p.Packet.Dest())
			case 3:
				label.SetText(p.Packet.Info())
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
			headers := []string{"Type", "Sender", "Destination", "Info"}
			label.SetText(headers[id.Col])
		}
	}

	window.SetContent(container.NewBorder(toolbar, nil, nil, nil, table))

	// main menu
	arpMenuItem := fyne.NewMenuItem("arp", func(){})
	ipv4MenuItem := fyne.NewMenuItem("ipv4", func(){})
	ipv6MenuItem := fyne.NewMenuItem("ipv6", func(){})
	protocolMenu := fyne.NewMenu("Select Protocol", arpMenuItem, ipv4MenuItem, ipv6MenuItem)

	mainmenu := fyne.NewMainMenu(protocolMenu)
	window.SetMainMenu(mainmenu)

	go func() {
		for p := range packets {
			fyne.Do(func () {
				dataForDisplay = append(dataForDisplay, p)
				table.Refresh()
				table.ScrollToBottom();
			})
		}
	}()


	window.ShowAndRun()
}
