#!/bin/bash

#Copyright (C) 2023 Intel Corporation
#SPDX-License-Identifier: Apache-2.0

###########################
# Globals
###########################
P4K8S_INSTALL=/opt/p4/k8s/opt/infra
P4CP=/opt/p4/p4-cp-nws

# Check the status of a command and return
function check_status () {
  local status=$1
  local command="$2"
  if [ $status -ne 0 ]; then
    echo "Error executing command: $command"
    exit $status
  fi
}

# Run Inframanager as standalone process
function run_inframgr () {
  NODE_IP=$1
  getPid=$(pgrep -f inframanager)  # kill if already runnning
  [[ $getPid ]] && kill $getPid
  sleep 1
  NODE_IP=$NODE $P4K8S_INSTALL/inframanager 1>&2> /dev/null &
  check_status $? "$P4K8S_INSTALL/inframanager"
  echo "Press [^c] to exit"
  return 0
}

# Run Infrap4d as standalone process
function run_infrap4d () {
  getPid=$(pgrep -f infrap4d)  # kill if already runnning
  [[ $getPid ]] && kill $getPid
  sleep 1
  export STRATUM_DIR=/usr/share/stratum
  export P4CP_INSTALL=$P4CP
  export PATH=$P4CP_INSTALL/bin:$P4CP_INSTALL/sbin:$PATH
  export SDE_INSTALL=/opt/p4/p4sde
  export LD_LIBRARY_PATH=$P4CP_INSTALL/lib:$P4CP_INSTALL/lib64:$SDE_INSTALL/lib64:$SDE_INSTALL/lib:/usr/lib64:/usr/lib:/usr/local/lib64:/usr/local/lib
  $P4CP_INSTALL/sbin/infrap4d
  check_status $? "sbin/infrap4d"
}

# Create missing rootfs dir
function setup_inframgr (){
  mkdir -p /var/log
}

# Setup infrap4d config file with K8S attributes
function setup_p4cp_file () {
  modprobe vfio-pci
  export SDE_INSTALL=/opt/p4/p4sde
  echo "SDE_INSTALL is ${SDE_INSTALL}"
  export P4CP_INSTALL=$P4CP
  echo 512 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
  $P4CP_INSTALL/sbin/copy_config_files.sh $P4CP_INSTALL $SDE_INSTALL
  dev_id=$(lspci | grep 1453 | cut -d ' ' -f 1)

  # unbind if bound
  $SDE_INSTALL/bin/dpdk-devbind.py -u 0000:$dev_id >/dev/null
  #bind to vfio
  GROUP=$(${SDE_INSTALL}/bin/vfio_bind.sh 8086:1453)
  GROUP_ID=$(echo "$GROUP" | grep -o "Group = [0-9]*" | awk '{print $3}')
  echo "IOMMU Group ID: $GROUP_ID dev_id: $dev_id"

  file="/usr/share/stratum/es2k/es2k_skip_p4.conf"
  cp $file $file.bkup
  replacement=$(lspci | grep 1453 | cut -d ' ' -f 1)
  orig_string=$(grep -Eo -- '-a [a-z]+\:[0-9]+\.[0-9]' "$file")
  mod_string=$(echo "$orig_string" | sed -E "s/-a [a-z]+\:[0-9]+\.[0-9]/-a $replacement/")
  sed -i "s@$orig_string@$mod_string@" "$file"
  sed -i "s/\"iommu_grp_num\": *[0-9][0-9]*/\"iommu_grp_num\": $GROUP_ID/g" "$file"
  sed -i "s/\"cfgqs-idx\": \"[0-9]-15\"/\"cfgqs-idx\": \"2-15\"/g" "$file"
  sed -i "s/\(\"pcie_bdf\": \)\"[^\"]*\"/\1\"0000:$dev_id\"/" $file
  sed -i "s/\(\"program-name\": \)\"[^\"]*\"/\1\"k8s_dp\"/" $file
  sed -i "s/\(\"bfrt-config\": \)\"[^\"]*\"/\1\"\/share\/infra\/k8s_dp\/bf-rt.json\"/" $file
  sed -i "s/\(\"p4_pipeline_name\": \)\"[^\"]*\"/\1\"main\"/" $file
  sed -i "s/\(\"context\": \)\"[^\"]*\"/\1\"\/share\/infra\/k8s_dp\/context.json\"/" $file
  sed -i "s/\(\"config\": \)\"[^\"]*\"/\1\"\/share\/infra\/k8s_dp\/tofino.bin\"/" $file
  sed -i "s/\(\"path\": \)\"[^\"]*\"/\1\"\/share\/infra\/k8s_dp\"/" $file
}

NODE=$1
echo "Host Node IP: \"$NODE\""
setup_inframgr
setup_p4cp_file
run_infrap4d
echo "This may take a while ..."
run_infrap4d
sleep 15
run_inframgr $NODE
exit 0
