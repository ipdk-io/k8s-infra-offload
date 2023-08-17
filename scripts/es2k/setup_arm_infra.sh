#!/bin/bash

#Copyright (C) 2023 Intel Corporation
#SPDX-License-Identifier: Apache-2.0

P4K8S_INSTALL=/opt/p4/k8s

function check_status () {
  local status=$1
  local command="$2"
  if [ $status -ne 0 ]; then
    echo "Error executing command: $command"
    exit $status
  fi
}

function run_inframgr () {
  getPid=$(pgrep -f inframanager)  # kill if already runnning
  [[ $getPid ]] && kill $getPid
  sleep 1
  $P4K8S_INSTALL/inframanager &
  check_status $? "$P4K8S_INSTALL/inframanager"
}

function run_infrap4d () {
  getPid=$(pgrep -f infrap4d)  # kill if already runnning
  [[ $getPid ]] && kill $getPid
  sleep 1
  export STRATUM_DIR=/usr/share/stratum
  export P4CP_INSTALL=/opt/p4/p4-cp-nws
  export PATH=$P4CP_INSTALL/bin:$P4CP_INSTALL/sbin:$PATH
  export SDE_INSTALL=/opt/p4/p4sde
  export LD_LIBRARY_PATH=$P4CP_INSTALL/lib:$P4CP_INSTALL/lib64:$SDE_INSTALL/lib64:$SDE_INSTALL/lib:/usr/lib64:/usr/lib:/usr/local/lib64:/usr/local/lib
  # workaround for a bug in p4cp
  cp $STRATUM_DIR/es2k/certs/* $STRATUM_DIR/certs
  # export-n -  unset DEBUGINFOD_URLS
  #gdb --args $P4CP_INSTALL/install/sbin/infrap4d -grpc_open_insecure_mode=true --nodetach
  $P4CP_INSTALL/sbin/infrap4d
  check_status $? "sbin/infrap4d"
}

function setup_p4cp_file () {
  modprobe vfio-pci
  export SDE_INSTALL=/opt/p4/p4sde
  echo "SDE_INSTALL is ${SDE_INSTALL}"
  echo 512 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
  GROUP=$((${SDE_INSTALL}/bin/vfio_bind.sh 8086:1453) 2> /dev/null)
  GROUP_ID=$(echo "$GROUP" | grep -o "Group = [0-9]*" | awk '{print $3}')

  file="/usr/share/stratum/es2k/es2k_skip_p4.conf"
  cp $file $file.bkup
  sed -i "s/\"iommu_grp_num\": *[0-9][0-9]*/\"iommu_grp_num\": $GROUP_ID/g" "$file"
  sed -i "s/\(\"program-name\": \)\"[^\"]*\"/\1\"k8s_dp\"/" $file
  sed -i "s/\(\"bfrt-config\": \)\"[^\"]*\"/\1\"\/share\/infra\/k8s_dp\/bf-rt.json\"/" $file
  sed -i "s/\(\"p4_pipeline_name\": \)\"[^\"]*\"/\1\"main\"/" $file
  sed -i "s/\(\"context\": \)\"[^\"]*\"/\1\"\/share\/infra\/k8s_dp\/context.json\"/" $file
  sed -i "s/\(\"config\": \)\"[^\"]*\"/\1\"\/share\/infra\/k8s_dp\/tofino.bin\"/" $file
  sed -i "s/\(\"path\": \)\"[^\"]*\"/\1\"\/share\/infra\/k8s_dp\"/" $file

}

NODE_IP=$1
echo "Node IP is \"$NODE_IP\""
export NODE_IP
setup_p4cp_file
run_infrap4d
# wait for grpc sockets to be open
sleep 8
run_inframgr
