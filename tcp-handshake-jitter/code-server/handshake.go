package main

import (
	"time"

	"github.com/google/gopacket"
)

// handshake contains the SYN, SYN/ACK, and ACK segments of a TCP
// handshake.
type handshake struct {
	syn, synAck, ack gopacket.Packet
	lastPkt          time.Time
}

// rtt returns the round trip time between the SYN/ACK and the ACK segment.
func (s *handshake) rtt(clientSide bool) (time.Duration, error) {
	if !s.complete() {
		return time.Duration(0), errHandshakeIncomplete
	}

	var t1, t2 time.Time
	if clientSide {
		t1 = s.syn.Metadata().Timestamp
		t2 = s.synAck.Metadata().Timestamp
	} else {
		t1 = s.synAck.Metadata().Timestamp
		t2 = s.ack.Metadata().Timestamp
	}
	return t2.Sub(t1), nil
}

// complete returns true if we have all three segments of TCP's three-way
// handshake.
func (s *handshake) complete() bool {
	return s.syn != nil && s.synAck != nil && s.ack != nil
}

// heartbeat updates the timestamp that keeps track of when we last observed a
// packet for this TCP connection.  This matters for pruning expired
// connections.
func (s *handshake) heartbeat(p gopacket.Packet) {
	s.lastPkt = p.Metadata().Timestamp
}
