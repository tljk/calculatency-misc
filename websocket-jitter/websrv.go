package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"sort"
	"text/template"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// The number of application-layer pings that we use to determine the round
	// trip time to the client.
	numAppLayerPings = 10000
)

func mean(ms []time.Duration) time.Duration {
	var t time.Duration

	for _, m := range ms {
		t += m
	}

	return t / time.Duration(len(ms))
}

func median(ms []time.Duration) time.Duration {
	if len(ms)%2 == 1 {
		return ms[len(ms)/2+1]
	}
	a := ms[len(ms)/2-1]
	b := ms[len(ms)/2]
	return a + b/2
}

func calcStats(ms []time.Duration) {
	less := func(i, j int) bool {
		return ms[i] < ms[j]
	}
	sort.Slice(ms, less)

	fmt.Printf("%d measurements.\n", len(ms))
	fmt.Printf("Min    RTT: %s\n", ms[0])
	fmt.Printf("Max    RTT: %s\n", ms[len(ms)-1])
	fmt.Printf("Mean   RTT: %s\n", mean(ms))
	fmt.Printf("Median RTT: %s\n", median(ms))
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
		time.Sleep(time.Millisecond * 200)
	}

	calcStats(ms)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	t, err := template.New("latency").Parse(LatencyTemplate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	endpoint := "wss://example.com:8443/websocket"
	buf := new(bytes.Buffer)
	if err := t.Execute(buf, struct {
		WebSocketEndpoint string
	}{
		endpoint,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, string(buf.Bytes()))
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/websocket", webSocketHandler)
	log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil))
}
