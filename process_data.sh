#!/bin/bash

values=(5 10 15 20 25 30)

for i in "${values[@]}"
do
	#echo "File $i"
	tshark -r ./captures/capture_osre_${i}.pcap -Y "tcp && ip.dst == 172.28.0.4" -T fields -e frame.len | awk '{s+=$1} END {print s}'

done
