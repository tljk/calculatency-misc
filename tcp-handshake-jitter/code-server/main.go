package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	errHandshakeIncomplete = errors.New("TCP handshake incomplete")
	errNoFourTuple         = errors.New("failed to extract TCP four-tuple")
	errNonHandshakeAck     = errors.New("ignoring ACK that's not part of handshake")
	errNoSynAck            = errors.New("got ACK for non-existing SYN/ACK")
	errNoSyn               = errors.New("got SYN/ACK for non-existing SYN")
	errIPHasNoTCP          = errors.New("IP packet does not carry TCP segment")
	errNoIPPkt             = errors.New("not an IPv4 or IPv6 packet")
)

// filter returns the pcap filter that we use to capture TCP handshakes for the
// given port.
func filter(port int) string {
	return fmt.Sprintf("tcp[tcpflags] == tcp-syn or "+
		"tcp[tcpflags] == tcp-ack or "+
		"tcp[tcpflags] == tcp-syn|tcp-ack and "+
		"port %d", port)
}

// pktToTuple extracts the four-tuple from the given packet: source IP address,
// source port, destination IP address, destination port.
func pktToTuple(p gopacket.Packet) (*fourTuple, error) {
	var srcAddr, dstAddr net.IP

	// Are we dealing with IPv4 or IPv6?
	if p.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
		v4 := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		srcAddr = v4.SrcIP
		dstAddr = v4.DstIP
		if v4.Protocol != layers.IPProtocolTCP {
			return nil, errIPHasNoTCP
		}
	} else if p.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		// IPv6
		v6 := p.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		srcAddr = v6.SrcIP
		dstAddr = v6.DstIP
		if v6.NextHeader != layers.IPProtocolTCP {
			return nil, errIPHasNoTCP
		}
	} else {
		return nil, errNoIPPkt
	}

	tcp := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	return newFourTuple(
		srcAddr, uint16(tcp.SrcPort),
		dstAddr, uint16(tcp.DstPort),
	), nil
}

func areHandshakeFlagsSet(syn, ack bool, p gopacket.Packet) bool {
	var tcp *layers.TCP
	if p.TransportLayer().LayerType() == layers.LayerTypeTCP {
		tcp = p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	} else {
		return false
	}
	// The following flags must not be set.
	if tcp.FIN || tcp.RST || tcp.PSH || tcp.URG || tcp.ECE || tcp.CWR || tcp.NS {
		return false
	}
	// The following flags must match what we're given.
	return tcp.SYN == syn && tcp.ACK == ack
}

// isSynSegment returns true if the given packet is a TCP segment that has only
// its SYN flag set.
func isSynSegment(p gopacket.Packet) bool {
	syn, ack := true, false
	return areHandshakeFlagsSet(syn, ack, p)
}

// isSynAckSegment returns true if the given packet is a TCP segment that has
// only its SYN and ACK flags set.
func isSynAckSegment(p gopacket.Packet) bool {
	syn, ack := true, true
	return areHandshakeFlagsSet(syn, ack, p)
}

// isAckSegment returns true if the given packet is a TCP segment that has only
// its ACK flag set.
func isAckSegment(p gopacket.Packet) bool {
	syn, ack := false, true
	return areHandshakeFlagsSet(syn, ack, p)
}

// pktsShareHandshake returns true if the given TCP handshake segment
// acknowledges the preceding segment, i.e., the two given packets are part of
// the same TCP three-way handshake.  The function accepts either a SYN and
// SYN/ACK pair or a SYN/ACK and ACK pair.
func pktsShareHandshake(p1, p2 gopacket.Packet) bool {
	var t1, t2 *layers.TCP

	if p1.TransportLayer().LayerType() == layers.LayerTypeTCP {
		t1 = p1.Layer(layers.LayerTypeTCP).(*layers.TCP)
	} else {
		return false
	}
	if p2.TransportLayer().LayerType() == layers.LayerTypeTCP {
		t2 = p2.Layer(layers.LayerTypeTCP).(*layers.TCP)
	} else {
		return false
	}

	// The second packet (either a SYN/ACK or an ACK) must acknowledge
	// receipt of the first packet (either a SYN or a SYN/ACK).
	return t1.Seq == (t2.Ack - 1)
}

func processPkts(handle *pcap.Handle, s *stateMachine) {
	log.Println("Beginning pcap packet processing loop.")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		_ = s.add(packet)
	}
}

func writeToFile(s *stateMachine) {
	s.RLock()
	defer s.RLock()

	fd, err := os.CreateTemp(".", "rtts-")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintln(fd, "us")
	for _, rtt := range s.rtts {
		fmt.Fprintln(fd, rtt.Microseconds())
	}
	log.Printf("Wrote %d RTTs to: %s", len(s.rtts), fd.Name())
}

func startWebServer(port int) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello world!")
	})
	addr := fmt.Sprintf(":%d", port)
	log.Printf("Starting Web server at %s.", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func main() {
	var srvPort int
	var iface string
	var runSrv, clientSide bool

	flag.BoolVar(&runSrv, "run-server", false,
		"Spin up Web server to facilitate measurements")
	flag.BoolVar(&clientSide, "client-side", false,
		"This program runs on the side of the initiator of the TCP handshake")
	flag.StringVar(&iface, "iface", "eth0",
		"Networking interface to monitor")
	flag.IntVar(&srvPort, "port", 443,
		"Port to monitor for TCP handshakes")
	flag.Parse()

	if runSrv {
		go startWebServer(srvPort)
	}
	state := &stateMachine{
		clientSide: clientSide,
		m:          make(map[fourTuple]*handshake),
	}

	// Upon receiving ctrl+c, we write our data to a file and exit.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		writeToFile(state)
		os.Exit(0)
	}()

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to create pcap handle: %v", err)
	}
	if err = handle.SetBPFFilter(filter(srvPort)); err != nil {
		log.Fatalf("Failed to set pcap filter: %v", err)
	}
	processPkts(handle, state)
}
