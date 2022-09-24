#!/bin/bash
#Copyright (C) 2021 Intel Corporation
#SPDX-License-Identifier: Apache-2.0

# This script starts p4ovs and creates TAP interfaces with a prefix of "P4TAP_".
# This prefix is needed for interfaces to be discovered by plugin.
# Total number of interfaces configured should be a power of 2.
# This is a DPDK requirement. IF_MAX can be 8, 16, 32, 64 ....
set -e

if [ "$#" -ne 1 ]; then
    echo " "
    echo "Usage: $0 < max_ifs > [OVS_DEP_INSTALL_PATH]"
    echo "max_ifs: Total number of interfaces to be created"
    echo "         Valid arguments are 2^n. For instance - 8, 16, 32, 64 etc" 
    echo " "
	 
fi

IF_MAX=$1

function set_hugepages () {

    #...Setting Hugepages...#
    mkdir -p /mnt/huge
    if [ "$(mount | grep hugetlbfs)" == "" ]
    then
	mount -t hugetlbfs nodev /mnt/huge
    fi

    if [ -e /etc/fstab ]; then
        if [ "$(grep huge < /etc/fstab)" == "" ]
        then
                echo -e "nodev /mnt/huge hugetlbfs\n" >> /etc/fstab
        fi
    fi

    # Get pagesize in MegaBytes, take only 1st result (head -1):
    pagesizeM=$(grep hugetlbfs < /proc/mounts | head -1)
    # Remove Prefix of = from: hugetlbfs /dev/hugepages hugetlbfs rw,relatime,pagesize=512M 0 0
    pagesizeM=${pagesizeM#*=}
    # Remove Suffix of M from: hugetlbfs /dev/hugepages hugetlbfs rw,relatime,pagesize=512M 0 0
    pagesizeM=${pagesizeM%M*}

    # 2 GB Total size
    total_sizeM=2048
    num_pages=$(( "$total_sizeM" / "$pagesizeM" ))
    pagesizeKB=$(( "$pagesizeM" * 1024 ))

    if [ "$(grep nr_hugepages < /etc/sysctl.conf)" == "" ]
    then
        echo "vm.nr_hugepages = ${num_pages}" >> /etc/sysctl.conf
        #sysctl -p /etc/sysctl.conf
    fi

    #
    # Check if the kernel/mm version of hugepages exists, and set hugepages if so.
    #
    if [ -d "/sys/kernel/mm/hugepages/hugepages-${pagesizeKB}kB" ] ; then
        echo "${num_pages}" | tee "/sys/kernel/mm/hugepages/hugepages-${pagesizeKB}kB/nr_hugepages"
    fi

    #
    # Check if the node version of hugepages exists, and set hugepages if so.
    #
    if [ -d "/sys/devices/system/node/node0/hugepages/hugepages-${pagesizeKB}kB" ] ; then
        echo "${num_pages}" | sudo tee "/sys/devices/system/node/node0/hugepages/hugepages-${pagesizeKB}kB/nr_hugepages"
    fi
    if [ -d "/sys/devices/system/node/node1/hugepages/hugepages-${pagesizeKB}kB" ] ; then
        echo "${num_pages}" | sudo tee "/sys/devices/system/node/node1/hugepages/hugepages-${pagesizeKB}kB/nr_hugepages"
    fi
}

function is_power_of_two () {
    declare -i n=($IF_MAX)
    (( n > 0 && (n & (n - 1)) == 0 ))
}

if is_power_of_two; then
    echo "configuring $1 interfaces"
else
    echo "wrong number of interfaces"
    exit 1
fi

OVS_DEP_INSTALL_PATH=$2
if [[ -z "${SDE_INSTALL}" ]]; then
    echo "SDE_INSTALL env is undefined" && exit 1
fi

if [[ -z "${OVS_INSTALL}" ]]; then
    echo "OVS_INSTALL env is undefined" && exit 1
fi

set_hugepages

cd $OVS_INSTALL
source ./p4ovs_env_setup.sh $SDE_INSTALL $OVS_DEP_INSTALL_PATH
if [ ! -f /usr/share/stratum/dpdk_port_config.pb.txt ]
then
    echo "Missing DPDK port config file"
else
    sed -i 's/\bTAP/P4TAP_/g' /usr/share/stratum/dpdk_port_config.pb.txt
fi

# Run p4ovs
pkill ovs
sleep 1
./run_ovs.sh $OVS_DEP_INSTALL_PATH
sleep 1

max=$(($IF_MAX - 1))
for i in $(seq 0 $max);
do
    echo "creating P4TAP_$i"
   gnmi-cli set "device:virtual-device,name:P4TAP_$i,pipeline-name:pipe,mempool-name:MEMPOOL0,mtu:1500,port-type:TAP"
done
