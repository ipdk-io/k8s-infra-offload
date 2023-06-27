#!/bin/bash -x

ip netns del pod0 > /dev/null 2>&1
ip netns add pod0
ip link set $IFACE  netns pod0
ip netns exec pod0 ifconfig $IFACE 169.254.1.1/16 up
ip netns exec pod0 ip route add default dev $IFACE scope link

export ARP_PROXY_IF=$IFACE
ip netns exec pod0 ./bin/arp-proxy &> /dev/null &
