#!/bin/bash

num_pings=$((60*60*24))
interval=$((60*15))

if [ $# -ne 1 ]
then
	>&2 echo "Usage: $0 TCP_PORT"
	exit 1
fi
port="$1"

echo "Sending $num_pings HTTP pings."

for ((i=0; i<"$num_pings"; i++))
do
	if [ $(($i % $interval)) -eq 0 ]
	then
		echo "${i}/${num_pings} pings sent."
	fi
	curl -i "http://nymity.ch:$port" >>curl.log 2>>curl.err
	sleep 1
done
