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
    exit 1
  fi
}

function uninstall_drivers () {
  rmmod idpf
  rmmod mdev
}

function reset_all () {
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
  rm -rf /var/lib/cni &&
  rm -rf /var/lib/etcd &&
  rm -rf /etc/kubernetes/* &&
  rm -rf /etc/pki/inframanager &&
  rm -rf /etc/pki/infraagent &&
  rm -rf /usr/share/stratum/certs &&
  rm -rf /usr/share/stratum/es2k/certs &&
  rm -rf /var/lib/kubelet &&
  rm -rf /var/lib/dockershim &&
  rm -rf /var/lib/etcd &&
  rm -rf /var/lib/cni &&
  rm -rf /etc/cni/net.d/* &&
  rm -rf /etc/stratum &&
  rm -rf /run/stratum
}

function clean_k8s_pods () {
  kubectl delete pods --all -A
}

function clean_ns () {
  ip -all netns delete
}

function pkill_infrap4d_arp () {
  getPid=$(pgrep -f infrap4d)  #  kill if already runnning
  [[ $getPid ]] && kill $getPid
  getPid=$(pgrep -f arp)  #  kill if already runnning
  [[ $getPid ]] && kill $getPid
}

#############################################
##### main ##################################
#############################################

echo "Cleaning up deployment on the host"
check_host_env K8S_RECIPE
pkill_infrap4d_arp
cd $K8S_RECIPE && make undeploy-calico && make undeploy 2> /dev/null
clean_k8s_pods
uninstall_drivers
reset_all
clean_ns
