package main

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type stateMachine struct {
	sync.RWMutex
	clientSide bool
	m          map[fourTuple]*handshake
	rtts       []time.Duration
}

func (s *stateMachine) prune() int {
	s.Lock()
	defer s.Unlock()

	now := time.Now()
	deleted := 0
	for t, connState := range s.m {
		// Consider a TCP connection timed out after 30 seconds.  Note
		// that it's fine to be strict here because we only care about
		// the TCP handshake.  Subsequent data packets don't matter.
		if now.Sub(connState.lastPkt) > (30 * time.Second) {
			delete(s.m, t)
			deleted += 1
		}
	}
	return deleted
}

func (s *stateMachine) stateForPkt(p gopacket.Packet) (*handshake, error) {
	s.RLock()
	defer s.RUnlock()

	tuple, err := pktToTuple(p)
	if err != nil {
		return nil, errNoFourTuple
	}

	// Look up connection state or create it if it does not exist.
	connState, exists := s.m[*tuple]
	if !exists {
		log.Printf("Creating new connection state for %s.", tuple)
		connState = &handshake{
			lastPkt: p.Metadata().Timestamp,
		}
		s.m[*tuple] = connState
	} else if exists && connState.complete() {
		return nil, errNonHandshakeAck
	}

	return connState, nil
}

func (s *stateMachine) add(p gopacket.Packet) error {
	// Prune expired TCP connections before potentially adding new ones.
	if pruned := s.prune(); pruned > 0 {
		log.Printf("Pruned %d connections from state machine; %d remaining", pruned, len(s.m))
	}

	connState, err := s.stateForPkt(p)
	if err != nil {
		return err
	}
	// This packet is part of an existing connection.  Reset the expiry
	// timer.
	connState.heartbeat(p)

	if isSynSegment(p) {
		log.Println("Adding SYN segment to connection state.")
		connState.syn = p
	} else if isSynAckSegment(p) {
		if connState.syn == nil {
			return errNoSyn
		}
		if !pktsShareHandshake(connState.syn, p) {
			return errNonHandshakeAck
		}
		log.Println("Adding SYN/ACK segment to connection state.")
		connState.synAck = p
	} else if isAckSegment(p) {
		// Is this ACK in response to the SYN/ACK or is it acknowledging payload?
		if connState.synAck == nil {
			return errNoSynAck
		}
		if !pktsShareHandshake(connState.synAck, p) {
			return errNonHandshakeAck
		}
		log.Println("Adding ACK segment to connection state.")
		connState.ack = p
	} else {
		log.Println("INVARIANT: Ignoring TCP segment that's neither SYN/ACK nor ACK.")
	}

	if connState.complete() {
		s.RLock()
		rtt, err := connState.rtt(s.clientSide)
		s.RUnlock()
		if err != nil {
			log.Printf("Failed to determine RTT of completed handshake: %v", err)
		} else {
			s.Lock()
			s.rtts = append(s.rtts, rtt)
			s.Unlock()
			_ = s.deleteStateForPkt(p)
			log.Printf("TCP handshake RTT: %v", rtt)
		}
	}

	return nil
}

// deleteStateForPkt deletes the state (if any) we maintain for the given
// packet.
func (s *stateMachine) deleteStateForPkt(p gopacket.Packet) error {
	tuple, err := pktToTuple(p)
	if err != nil {
		return errNoFourTuple
	}
	s.Lock()
	delete(s.m, *tuple)
	s.Unlock()

	return nil
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
