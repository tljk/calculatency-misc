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
)

const (
	// The number of application-layer pings that we use to determine the round
	// trip time to the client.
	numAppLayerPings = 10
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

func processPkts(handle *pcap.Handle, s *stateMachine) {
	log.Println("Beginning pcap packet processing loop.")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		_ = s.add(packet)
	}
}

func writeToFile(s *stateMachine) {
	s.Lock()
	defer s.Unlock()

	fd, err := os.CreateTemp("./results", "rtts-")
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
	http.HandleFunc("/", indexHandler)
	addr := fmt.Sprintf(":%d", port)
	log.Printf("Starting Web server at %s.", addr)
	log.Fatal(http.ListenAndServeTLS(addr, "cert.pem", "key.pem", nil))
}

func writeStats(ms []time.Duration) {
	fd, err := os.CreateTemp("./results", "websocket-rtt-")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintln(fd, "us")
	for _, m := range ms {
		fmt.Fprintln(fd, m.Microseconds())
	}
	log.Printf("Wrote results to: %s", fd.Name())
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

	// Use the WebSocket connection to send application-layer pings to the
	// client and determine the round trip time.
	for i := 0; i < numAppLayerPings; i++ {
		if i%100 == 0 {
			fmt.Print(".")
		}
		then := time.Now().UTC()
		err = c.WriteMessage(websocket.TextMessage, []byte(then.String()))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, _, err := c.ReadMessage()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		now := time.Now().UTC()
		ms = append(ms, now.Sub(then))
		log.Printf("Websocket ping RTT: %s", now.Sub(then))
		time.Sleep(time.Millisecond * 200)
	}

	writeStats(ms)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if websocket.IsWebSocketUpgrade(r) {
		webSocketHandler(w, r)
		return
	}

	buf, err := os.ReadFile("index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, string(buf))
}

func main() {
	var srvPort int
	var iface string

	flag.StringVar(&iface, "iface", "",
		"Networking interface to monitor")
	flag.IntVar(&srvPort, "port", 443,
		"Port to monitor for TCP handshakes")
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

	if _, err := os.Stat("./results"); os.IsNotExist(err) {
		_ = os.Mkdir("./results", 0755)
	}

	go startWebServer(srvPort)

	state := &stateMachine{
		clientSide: false,
		m:          make(map[fourTuple]*handshake),
	}

	// Upon receiving ctrl+c, we write our data to a file and exit.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		if len(state.rtts) != 0 {
			writeToFile(state)
		}
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
