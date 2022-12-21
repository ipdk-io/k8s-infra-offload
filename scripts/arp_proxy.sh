#!/bin/bash -x

ip netns del pod0 > /dev/null 2>&1
ip netns add pod0
ip link set P4TAP_0 netns pod0
ip netns exec pod0 ifconfig P4TAP_0 169.254.1.1/16 up
ip netns exec pod0 ip route add default dev P4TAP_0 scope link
ip netns exec pod0 /bin/bash
