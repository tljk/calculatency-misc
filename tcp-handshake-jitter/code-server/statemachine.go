package main

import (
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
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
