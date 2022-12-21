#!/bin/bash

#Copyright (C) 2021 Intel Corporation
#SPDX-License-Identifier: Apache-2.0

# This script starts p4ovs and creates TAP interfaces with a prefix of "P4TAP_".
# This prefix is needed for interfaces to be discovered by plugin.
# Total number of interfaces configured should be a power of 2.
# This is a DPDK requirement. IF_MAX can be 8, 16, 32, 64 ....

set -e

check_infrap4d_env()
{
  var_names=("$@")
  for var_name in "${var_names[@]}"; do
    [ -z "${!var_name}" ] && echo "Please refer to ipdk networking recipe and set $var_name." && var_unset=true
  done
  if [[ -n "$var_unset" ]];
  then 
    echo "All following env variables must be set - "
    echo "SDE_INSTALL - Path to SDE install"
    echo "IPDK_RECIPE - Path to IPDK networking recipe source"
    echo "DEPEND_INSTALL - Path to IPDK networking dependencies install"
    exit 1
  fi
}

function set_env () {
  if [ -f "$IPDK_RECIPE/scripts/dpdk/setup_env.sh" ]; then
    source $IPDK_RECIPE/scripts/dpdk/setup_env.sh $IPDK_RECIPE $SDE_INSTALL $DEPEND_INSTALL
    export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:$IPDK_RECIPE/install/lib64
  else
    echo "Missing set_env script"
    exit 1
  fi
}

function setup_run_env () {
  $IPDK_RECIPE/scripts/dpdk/copy_config_files.sh $IPDK_RECIPE $SDE_INSTALL $DEPEND_INSTALL
  $IPDK_RECIPE/scripts/dpdk/set_hugepages.sh
}

function run_infrap4d () {
  getPid=$(pgrep -f infrap4d)  #  kill if already runnning
  [[ $getPid ]] && kill $getPid
  sleep 1
  $IPDK_RECIPE/install/sbin/infrap4d
}

function is_power_of_two () {
  declare -i n=($IF_MAX)
  (( n > 0 && (n & (n - 1)) == 0 ))
}

if [ "$#" -lt 1 ]; then
  echo " "
  echo "Usage: $0 <max_ifs>"
  echo "max_ifs: Total number of interfaces to be created"
  echo "         Valid arguments are 2^n. For instance - 8, 16, 32, 64 etc" 
  echo " "
  exit 1
fi

IF_MAX=$1
if is_power_of_two; then
  echo "configuring $1 interfaces"
else
  echo "wrong number of interfaces"
  exit 1
fi

check_infrap4d_env SDE_INSTALL IPDK_RECIPE DEPEND_INSTALL
set_env
setup_run_env

if [ ! -f /usr/share/stratum/dpdk/dpdk_port_config.pb.txt ];
then
  echo "Missing DPDK port config file"
  exit 1
else
  sed -i 's/\bTAP/P4TAP_/g' /usr/share/stratum/dpdk/dpdk_port_config.pb.txt
fi

# Run infrap4d
run_infrap4d
sleep 3

max=$(($IF_MAX - 1))
for i in $(seq 0 $max);
do
  echo "creating P4TAP_$i"
  $IPDK_RECIPE/install/bin/gnmi-ctl set "device:virtual-device,name:P4TAP_$i,pipeline-name:pipe,mempool-name:MEMPOOL0,mtu:1500,port-type:TAP"
  ifconfig P4TAP_$i mtu 1280 up
done
