package main

import (
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/mdlayher/raw"
	"golang.org/x/net/bpf"
	"log"
	"net"
)

const (
	DeviceName = ""
)

func main() {
	//ShowDevice()
	//capturePackets()
	rawExample()
	//names, _ := net.Interfaces()
	//for _, name := range names {
	//  fmt.Println(name.Name)
	//}
}
func rawExample() {

	iface, err := net.InterfaceByName("")
	if err != nil {
		log.Fatal(err)
	}

	// Создаём RAW-сокет
	conn, err := raw.ListenPacket(iface, uint16(0x0800), nil) // 0x0800 = IPv4 EtherType
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// Пример фильтра BPF (подобно tcpdump)
	// Допустим, хотим пропустить только IPv4-пакеты.
	filter, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2}, // EtherType offset
		bpf.JumpIf{Val: 0x0800, Cond: bpf.JumpEqual, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 65535},
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := conn.SetBPF(filter); err != nil {
		log.Fatal(err)
	}

	// Чтение данных
	buf := make([]byte, 1500)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		log.Fatal(err)
	}
	data := buf[:n]
	log.Printf("Получили %d байт от %v: %s", n, addr, hex.Dump(data))

	// Отправка данных
	// ... формируем Ethernet-фрейм в dataOut ...
	// _, err = conn.WriteTo(dataOut, &raw.Addr{HardwareAddr: dstMAC})
	// if err != nil {
	//     log.Fatal(err)
	// }
}
func capturePackets() {
	handle, err := pcap.OpenLive(DeviceName, 160000, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	//err = handle.SetBPFFilter("tcp and port 80")
	//if err != nil {
	//  log.Fatal(err)
	//}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		packet.ApplicationLayer().Payload()
		// Обработка пакета
		fmt.Println(packet)
	}
}

func ShowDevice() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for _, device := range devices {
		fmt.Printf("Name: %v, Description: %v\n", device.Name, device.Description)
		// Если нужны адреса:
		for _, address := range device.Addresses {
			fmt.Printf(" IP: %v, Mask: %v\n", address.IP, address.Netmask)
		}
		fmt.Println()
	}

}
