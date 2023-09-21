# RIPE Atlas tooling

This directory contains tooling for the RIPE Atlas-based latency measurements
in the CalcuLatency research paper.

The directory tls-service/ contains a Go service that exposes a TCP/TLS service
that initiates 0trace scans upon receiving incoming connections.

The directory probe-selector/ contains Python code that selects RIPE Atlas
probes that are eligible for our latency measurements.

The directory probe-scheduler/ contains a Shell script that coordinates the
latency measurements.  This shell script expects as input a CSV-formatted list
of Atlas probes that was generated using the Python code in probe-selector/.
