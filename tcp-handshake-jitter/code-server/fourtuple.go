package main

import (
	"bytes"
	"fmt"
	"net"
)

type fourTuple struct {
	srcPort, dstPort uint16
	srcAddr, dstAddr string
}

func newFourTuple(srcAddr net.IP, srcPort uint16, dstAddr net.IP, dstPort uint16) *fourTuple {
	if srcPort == dstPort {
		if bytes.Compare(srcAddr, dstAddr) < 0 {
			srcPort, dstPort = dstPort, srcPort
			srcAddr, dstAddr = dstAddr, srcAddr
		}
	} else if srcPort < dstPort {
		srcPort, dstPort = dstPort, srcPort
		srcAddr, dstAddr = dstAddr, srcAddr
	}

	return &fourTuple{
		srcAddr: srcAddr.String(),
		srcPort: srcPort,
		dstAddr: dstAddr.String(),
		dstPort: dstPort,
	}
}

func (f *fourTuple) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d",
		f.srcAddr, f.srcPort, f.dstAddr, f.dstPort)
}
