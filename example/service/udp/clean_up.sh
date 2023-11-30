#!/usr/bin/env bash
set -eu

kubectl delete --cascade -f iperf_udp.yaml 
