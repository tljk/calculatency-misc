# TCP Handshake Jitter

This directory contains code and plotting scripts to visualize the latency
jitter of TCP handshakes.  The experiment runs on a client and server.  On the
server, first compile the executable and then run:

    ./tcp-rtt-srv -port 8443 -run-server

On the client, adjust the hostname in send-pings.sh, and run:

    ./send-pings.sh 8443

After the experiment ends, the server is writing its results to a CSV file like
rtts-086184856.  You can then plot this file using the R scripts in the data
directory.
