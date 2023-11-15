#!/bin/bash

if [ -z "$1" ]; then
    echo "Error: Missing argument. Please provide client pod name as command line argument."
    exit 1
fi

CLIENT="$1"

# Loop 100 times
for i in {1..100}; do
    echo "This is iteration $i"
    kubectl exec "$CLIENT" -- iperf -c iperf-server-tcp -p 5201 -t 2
done
