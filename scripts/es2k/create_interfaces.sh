#!/bin/bash

#Copyright (C) 2021 Intel Corporation
#SPDX-License-Identifier: Apache-2.0

set -o pipefail

set -e

STRATUM_DIR="/usr/share/stratum"

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

function setup_dep_env () {
  if [ -f "$IPDK_RECIPE/scripts/dpdk/setup_env.sh" ]; then
    source $IPDK_RECIPE/scripts/es2k/setup_env.sh $IPDK_RECIPE $SDE_INSTALL $DEPEND_INSTALL
  else
    echo "Missing set_env script"
    exit 1
  fi
}

function install_drivers () {
  modprobe mdev
  modprobe vfio-pci
  modprobe vfio_iommu_type1
  #change this to insmod for installing private idpf build
  modprobe idpf
}

function create_arp_interface () {
  DEVICE=$((devlink dev show) 2> /dev/null)
  echo "$DEVICE"
  input_string=$((devlink port add $DEVICE flavour pcisf pfnum 0 sfnum 101) 2> /dev/null)
  # split the input string into an array of words
  IFS=' ' read -r -a words <<< "$input_string"
  PORT="${words[0]%:}"
  #read the response and parse pci/0000:af:00.0/1 to set active
  devlink port func set $PORT state active
}

function create_pod_interfaces () {
  DEVICE=$((devlink dev show) 2> /dev/null)                                                                  echo "$DEVICE"
  for (( i=2; i<=$IF_MAX; i++ ))
  do
    let "num = $i + 100"
    input_string=$((devlink port add $DEVICE flavour pcisf pfnum 0 sfnum $num) 2> /dev/null)
    # split the input string into n array of words
    IFS=' ' read -r -a words <<< "$input_string"
    PORT="${words[0]%:}"
    #read t{e response}and parse pci/0000:af:00.0/1 to set active
    devlink port func set $PORT state active
  done
}

function copy_certs() {
  if [ -d "./scripts/tls/certs/infrap4d/certs" ]; then
    if [ ! -d $STRATUM_DIR ]; then
        echo "stratum directory not found."
        exit 1
    fi
    mkdir -p $STRATUM_DIR/certs
    rm -rf $STRATUM_DIR/certs/ca.crt
    rm -rf $STRATUM_DIR/certs/client.crt
    rm -rf $STRATUM_DIR/certs/client.key
    rm -rf $STRATUM_DIR/certs/stratum.crt
    rm -rf $STRATUM_DIR/certs/stratum.key
    cp -r ./scripts/tls/certs/infrap4d/certs/* /usr/share/stratum/certs
  else
    echo "Missing infrap4d certificates. Run \"make gen-certs\" and try again."
    exit 1
  fi
}

function setup_run_env () {
  $IPDK_RECIPE/scripts/es2k/copy_config_files.sh $IPDK_RECIPE $SDE_INSTALL
  $IPDK_RECIPE/scripts/es2k/set_hugepages.sh
  GROUP=$((${SDE_INSTALL}/bin/vfio_bind.sh 8086:1453) 2> /dev/null)
  GROUP_ID=$(echo "$GROUP" | grep -o "Group = [0-9]*" | awk '{print $3}')

  file="/usr/share/stratum/es2k/es2k_skip_p4.conf"
  cp $file $file.bkup
  sed -i "s/\"iommu_grp_num\": *[0-9][0-9]*/\"iommu_grp_num\": $GROUP_ID/g" "$file"
  sed -i "s/\"program-name\": *\"dummy\"/\"program-name\": \"k8s_dp\"/g" "$file"
  sed -i "s/\"p4_pipeline_name\": *\"dummy\"/\"p4_pipeline_name\": \"main\"/g" "$file"
}

function run_infrap4d () {
  getPid=$(pgrep -f infrap4d)  #  kill if already runnning
  [[ $getPid ]] && kill $getPid
  sleep 1
  #for running infrap4d in foreground to debug
  #gdb --args $IPDK_RECIPE/install/sbin/infrap4d -grpc_open_insecure_mode=true --nodetach
  $IPDK_RECIPE/install/sbin/infrap4d
}

#############################################
##### main ##################################
#############################################

if [ "$#" -lt 1 ]; then
  echo " "
  echo "Usage: $0 <max_ifs>"
  echo "max_ifs: Total number of interfaces to be created"
  echo "Minimum of 8 interfaces are needed"
  echo " "
  exit 1
fi

IF_MAX=$1

if [ $IF_MAX -lt 8 ]; then
  echo "Wrong number of interfaces"
  exit 1
fi

check_infrap4d_env SDE_INSTALL IPDK_RECIPE DEPEND_INSTALL
setup_dep_env
setup_run_env
install_drivers
sleep 3
copy_certs
create_arp_interface
create_pod_interfaces
# Run infrap4d
run_infrap4d
