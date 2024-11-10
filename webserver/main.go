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
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	// The number of application-layer pings that we use to determine the round
	// trip time to the client.
	numAppLayerPings = 10
	numNetLayerPings = 10
)

var (
	errHandshakeIncomplete = errors.New("TCP handshake incomplete")
	errNoFourTuple         = errors.New("failed to extract TCP four-tuple")
	errNonHandshakeAck     = errors.New("ignoring ACK that's not part of handshake")
	errNoSynAck            = errors.New("got ACK for non-existing SYN/ACK")
	errNoSyn               = errors.New("got SYN/ACK for non-existing SYN")
	errIPHasNoTCP          = errors.New("IP packet does not carry TCP segment")
	errNoIPPkt             = errors.New("not an IPv4 or IPv6 packet")
	srvPort                int
	iface                  string
	certPath               string
	keyPath                string
	filePath               string
)

// filter returns the pcap filter that we use to capture TCP handshakes for the
// given port.
func filter(port int) string {
	return fmt.Sprintf("tcp[tcpflags] == tcp-syn or "+
		"tcp[tcpflags] == tcp-ack or "+
		"tcp[tcpflags] == tcp-syn|tcp-ack and "+
		"port %d", port)
}

func processPkts(handle *pcap.Handle, s *stateMachine) {
	log.Println("Beginning pcap packet processing loop.")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		_ = s.add(packet)
	}
}

func startWebServer(port int, certPath string, keyPath string) {
	http.HandleFunc("/", indexHandler)
	addr := fmt.Sprintf(":%d", port)
	log.Printf("Starting Web server at %s.", addr)
	log.Fatal(http.ListenAndServeTLS(addr, certPath, keyPath, nil))
}

func webSocketHandler(w http.ResponseWriter, r *http.Request) {
	var ms []time.Duration

	// Upgrade the connection to WebSocket.
	u := websocket.Upgrader{}
	c, err := u.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer c.Close()

	srcAddr := c.RemoteAddr().String()
	destAddr := c.LocalAddr().String()

	// Use the WebSocket connection to send application-layer pings to the
	// client and determine the round trip time.
	for i := 0; i < numAppLayerPings; i++ {
		if i%100 == 0 {
			fmt.Print(".")
		}
		then := time.Now()
		err = c.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("%d", then.Unix())))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, _, err := c.ReadMessage()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		now := time.Now()
		ms = append(ms, now.Sub(then))
		log.Printf("Websocket ping RTT: %s", now.Sub(then))
		time.Sleep(time.Millisecond * 100)
	}

	file, err := os.OpenFile(filePath+"results/websocket_rtt.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer file.Close()
		for _, rtt := range ms {
			logEntry := fmt.Sprintf("%d, %s, %s, %v\n", time.Now().Unix(), srcAddr, destAddr, rtt.Microseconds())
			if _, err := file.WriteString(logEntry); err != nil {
				log.Fatalf("Failed to write to file: %v", err)
			}
		}
	} else {
		log.Fatalf("Failed to open file: %v", err)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if websocket.IsWebSocketUpgrade(r) {
		sendICMPPing(r.RemoteAddr)
		webSocketHandler(w, r)
		return
	}

	buf, err := os.ReadFile(filePath + "index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, string(buf))
}

func sendICMPPing(srcAddr string) {
	var rtts []time.Duration
	clientIP, _, err := net.SplitHostPort(srcAddr)
	if err != nil {
		log.Printf("Failed to split host and port: %v", err)
	}

	for i := 0; i < numNetLayerPings; i++ {
		rtt, err := ping(clientIP)
		if err != nil {
			log.Printf("Ping %d failed: %v", i+1, err)
			continue
		}
		rtts = append(rtts, rtt)
		log.Printf("Ping %d: RTT = %v", i+1, rtt)
		time.Sleep(time.Millisecond * 100)
	}

	if len(rtts) == 0 {
		log.Println("All pings failed.")
		return
	}

	file, err := os.OpenFile(filePath+"results/icmp_rtt.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer file.Close()
		for _, rtt := range rtts {
			logEntry := fmt.Sprintf("%d, %s, %v\n", time.Now().Unix(), clientIP, rtt.Microseconds())
			if _, err := file.WriteString(logEntry); err != nil {
				log.Fatalf("Failed to write to file: %v", err)
			}
		}
	} else {
		log.Fatalf("Failed to open file: %v", err)
	}
}

func ping(addr string) (time.Duration, error) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return 0, err
	}
	defer c.Close()

	dst, err := net.ResolveIPAddr("ip4", addr)
	if err != nil {
		return 0, err
	}

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte(" "),
		},
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}

	start := time.Now()
	_, err = c.WriteTo(msgBytes, dst)
	if err != nil {
		return 0, err
	}

	reply := make([]byte, 1500)
	err = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		return 0, err
	}

	n, _, err := c.ReadFrom(reply)
	if err != nil {
		return 0, err
	}
	duration := time.Since(start)

	rm, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return 0, err
	}

	switch rm.Type {
	case ipv4.ICMPTypeEcho:
		return duration, nil
	case ipv4.ICMPTypeEchoReply:
		return duration, nil
	default:
		return 0, fmt.Errorf("got %+v from %v", rm, addr)
	}
}

func main() {
	flag.StringVar(&iface, "iface", "",
		"Networking interface to monitor")
	flag.IntVar(&srvPort, "port", 443,
		"Port to monitor for TCP handshakes")
	flag.StringVar(&certPath, "cert", "cert.pem", "Path to TLS certificate")
	flag.StringVar(&keyPath, "key", "key.pem", "Path to TLS private key")
	flag.StringVar(&filePath, "path", "./", "Path to save results")
	flag.Parse()

	if iface == "" {
		ifaces, err := net.Interfaces()
		if err != nil {
			log.Fatalf("Failed to list network interfaces: %v", err)
		}

		for _, i := range ifaces {
			if i.Flags&net.FlagLoopback == 0 && i.Flags&net.FlagUp != 0 {
				iface = i.Name
				log.Printf("Using network interface: %s", iface)
				break
			}
		}

		if iface == "" {
			log.Fatal("No suitable network interface found")
		}
	}

	if _, err := os.Stat(filePath + "results"); os.IsNotExist(err) {
		_ = os.Mkdir(filePath+"results", 0755)
	}

	go startWebServer(srvPort, certPath, keyPath)

	state := &stateMachine{
		clientSide: false,
		m:          make(map[fourTuple]*handshake),
	}

	// Upon receiving ctrl+c, we write our data to a file and exit.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
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
