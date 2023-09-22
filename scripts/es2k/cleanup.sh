#!/bin/bash -x

#Copyright (C) 2023 Intel Corporation
#SPDX-License-Identifier: Apache-2.0

function check_host_env() {
  var_names=("$@")
  for var_name in "${var_names[@]}"; do
    [ -z "${!var_name}" ] && echo "Please refer to p4cp recipe and set $var_name." && var_unset=true
  done
  if [[ -n "$var_unset" ]];
  then
    echo "Please setup following env variable"
    echo "K8S_RECIPE - Path to K8S recipe"
    echo "SDE_INSTALL - Path to P4 SDE install directory"
    exit 1
  fi
}

# unbind drivers
function unbind_driver () {
  echo "unbinding vfio driver"
  dev_id=$(lspci | grep 1453 | cut -d ' ' -f 1)
  $SDE_INSTALL/bin/dpdk-devbind.py -u 0000:$dev_id >/dev/null
}

# Remove installed drivers
function uninstall_drivers () {
  echo "uninstalling drivers"
  rmmod idpf
  rmmod mdev
}

# Reset kubernetes
function reset_all () {
  echo "resetting Kubernetes and infra settings"
  docker container stop registry && docker container rm -v registry
  systemctl restart containerd 2> /dev/null
  kubeadm reset -f &&
  rm -rf /var/lib/cni/ &&
  rm -rf /etc/cni/ &&
  rm -rf /var/run/kubernetes &&
  rm -rf /var/lib/etcd &&
  rm -rf /var/lib/kubelet &&
  rm -rf /etc/kubernetes/* &&
  rm -rf $HOME/.kube &&
  rm -rf /etc/pki/inframanager &&
  rm -rf /etc/pki/infraagent &&
  rm -rf /usr/share/stratum/certs &&
  rm -rf /usr/share/stratum/es2k/certs &&
  rm -rf /var/lib/dockershim &&
  rm -rf /etc/cni/net.d/* &&
  rm -rf /etc/stratum &&
  rm -rf /run/stratum
}

# Clean kubernetes pods created in default namespace
function clean_k8s_pods () {
  echo "clean k8s pods in default namespace"
  kubectl delete pods --all -n default
}

# Delete the leftover namespaces created
function clean_ns () {
  echo "deleting network namespaces"
  ns_filter=$(ip netns show | grep -v '^("cni-"|"pod0")')

  for ns in $ns_filter; do
    ip netns delete "$ns" 2> /dev/null
  done
}

# Kill processes started for k8s infra offload
function pkill_infrap4d_arp () {
  echo "killing infrap4d & arp-proxy processes"
  getPid=$(pgrep -f infrap4d)  #  kill if already runnning
  [[ $getPid ]] && kill $getPid
  getPid=$(pgrep -f arp-proxy)  #  kill if already runnning
  [[ $getPid ]] && kill $getPid
}

#############################################
##### main ##################################
#############################################

echo "Cleaning up deployment on the host"
check_host_env K8S_RECIPE SDE_INSTALL
clean_k8s_pods
cd $K8S_RECIPE && make undeploy-calico && make undeploy 2> /dev/null
pkill_infrap4d_arp
reset_all
unbind_driver
uninstall_drivers
clean_ns
