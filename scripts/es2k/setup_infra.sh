#!/bin/bash

#Copyright (C) 2023 Intel Corporation
#SPDX-License-Identifier: Apache-2.0

STRATUM_DIR="/usr/share/stratum"
MODE="host"
ARM_SCRIPT="setup_arm_infra.sh"
K8S_REMOTE="/opt/p4/k8s"

# Check the status of a command and return
function check_status () {
  local status=$1
  local command="$2"
  if [ $status -ne 0 ]; then
    echo "Error executing command: $command"
    exit $status
  fi
}

function launch_on_remote {
    local script="$1"
    local arg="$2"

    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $REMOTE_HOST "$script $arg"
    check_status $? "ssh $REMOTE_HOST \"$script\" \"$arg\""
}

function check_host_env() {
  var_names=("$@")
  for var_name in "${var_names[@]}"; do
    [ -z "${!var_name}" ] && echo "Please refer to p4cp recipe and set $var_name." && var_unset=true
  done
  if [[ -n "$var_unset" ]];
  then
    echo "All following env variables must be set - "
    echo "SDE_INSTALL - Path to SDE install"
    echo "P4CP_INSTALL - Path to P4CP install"
    echo "DEPEND_INSTALL - Path to installed P4CP dependencies"
    echo "K8S_RECIPE - Path to K8S recipe"
    exit 1
  fi
}

# Function to get the system's IP address
get_system_ip() {
  local ip=$(hostname -I | awk '{print $1}')
}

# Setup system environment for dependency resolution
function setup_host_dep_env () {
  if [ -f "$P4CP_INSTALL/sbin/setup_env.sh" ]; then
    source $P4CP_INSTALL/sbin/setup_env.sh $P4CP_INSTALL $SDE_INSTALL $DEPEND_INSTALL
  else
    echo "Missing set_env script on host"
    exit 1
  fi
}

# Install host drivers
function install_drivers () {
  modprobe mdev
  modprobe vfio-pci
  modprobe vfio_iommu_type1
  # change this with insmod in case of new idpf driver
  modprobe idpf
}

# Get PCI device ID for es2k
function get_device_id () {
  dev_id=$(lspci | grep 1453 | cut -d ':' -f 1)
  if [ -z "$dev_id" ]; then
    echo "No matching dev_id found."
    exit 1
  fi

  devlink_output=$(devlink dev show)
  DEV_BUS=$(echo "$devlink_output" | grep "$dev_id\:")
}

# Create an interface for arp-proxy
function create_arp_interface () {
  DEVICE=$((devlink dev show| grep $DEV_BUS) 2> /dev/null)
  echo "$DEVICE"
  input_string=$((devlink port add $DEVICE flavour pcisf pfnum 0 sfnum 101) 2> /dev/null)
  IFS=' ' read -r -a words <<< "$input_string"
  PORT="${words[0]%:}"
  devlink port func set $PORT state active
  check_status $? "arp proxy port creation"

}

# Create interfaces for the interface pool
function create_pod_interfaces () {
  DEVICE=$((devlink dev show| grep $DEV_BUS) 2> /dev/null)
  echo "$DEVICE"
  for (( i=2; i<=$IF_MAX; i++ ))
  do
    let "num = $i + 100"
    input_string=$((devlink port add $DEVICE flavour pcisf pfnum 0 sfnum $num) 2> /dev/null)
    IFS=' ' read -r -a words <<< "$input_string"
    PORT="${words[0]%:}"
    devlink port func set $PORT state active
  done
}

# Copy certificates for mTLS in relevant directories
function copy_certs() {
  if [ -d "$BASE_DIR/tls/certs/infrap4d" ]; then
    if [ ! -d $STRATUM_DIR ]; then
        echo "stratum directory not found."
        exit 1
    fi
    mkdir -p $STRATUM_DIR/es2k/certs
    rm -rf $STRATUM_DIR/certs/ca.crt
    rm -rf $STRATUM_DIR/certs/client.crt
    rm -rf $STRATUM_DIR/certs/client.key
    rm -rf $STRATUM_DIR/certs/stratum.crt
    rm -rf $STRATUM_DIR/certs/stratum.key
    cp $BASE_DIR/tls/certs/infrap4d/* /usr/share/stratum/es2k/certs/.
    mkdir -p /usr/share/stratum/certs
    cp $BASE_DIR/tls/certs/infrap4d/* /usr/share/stratum/certs/.
  else
    echo "Missing infrap4d certificates. Run \"make gen-certs\" and try again."
    exit 1
  fi
}

# Copy certificates for mTLS in relevant directories
function copy_cert_to_remote() {
  if [ -d "$BASE_DIR/tls/certs/infrap4d" ]; then
    # copy certs to remote infrap4d dir
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $BASE_DIR/tls/certs/infrap4d/* $REMOTE_HOST:/usr/share/stratum/es2k/certs
    check_status $? "scp infrap4d/certs/* root@$REMOTE_HOST:/usr/share/stratum/certs"

    # copy certs to remote inframanager dir
    scp -r -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $BASE_DIR/tls/certs/inframanager/* $REMOTE_HOST:/etc/pki/inframanager/certs
    check_status $? "scp inframanager/certs/* root@$REMOTE_HOST:/etc/pki/inframanager/certs"
  else
    echo "Missing infrap4d certificates. Run \"make gen-certs\" and try again."
    exit 1
  fi
}

# Copy remote execution script to arm acc
function copy_script_to_remote() {
  if [ -f "$BASE_DIR/$ARM_SCRIPT" ]; then
    # copy acc setup script to k8s dir
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $BASE_DIR/$ARM_SCRIPT $REMOTE_HOST:/opt/p4/k8s/.
    check_status $? "scp scripts/setup_arm_infra.sh/* root@$REMOTE_HOST:/opt/p4/k8s"
  else
    echo "Missing arm script"
    exit 1
    fi
}

# Setup infrap4d config file with K8S attributes
function setup_run_env () {
  $P4CP_INSTALL/sbin/copy_config_files.sh $P4CP_INSTALL $SDE_INSTALL
  dev_id=$(lspci | grep 1453 | cut -d ' ' -f 1)
  string=$(find /sys/kernel/iommu_groups/ -type l | sort -n -k5 -t/ | grep $dev_id)
  GROUP_ID=$(echo "$string" | sed -n 's/.*\/iommu_groups\/\([0-9]*\)\/devices.*/\1/p')
  if [ -n "$GROUP_ID" ]; then
    echo "Extracted iommu value: $GROUP_ID"
  else
    GROUP=$((${SDE_INSTALL}/bin/vfio_bind.sh 8086:1453) 2> /dev/null)
    GROUP_ID=$(echo "$GROUP" | grep -o "Group = [0-9]*" | awk '{print $3}')
  fi

  file="/usr/share/stratum/es2k/es2k_skip_p4.conf"
  cp $file $file.bkup
  replacement=$(lspci | grep 1453 | cut -d ' ' -f 1)
  orig_string=$(grep -Eo -- '-a [a-z]+\:[0-9]+\.[0-9]' "$file")
  mod_string=$(echo "$orig_string" | sed -E "s/-a [a-z]+\:[0-9]+\.[0-9]/-a $replacement/")
  sed -i "s@$orig_string@$mod_string@" "$file"
  sed -i "s/\"iommu_grp_num\": *[0-9][0-9]*/\"iommu_grp_num\": $GROUP_ID/g" "$file"
  sed -i "s/\(\"pcie_bdf\": \)\"[^\"]*\"/\1\"0000:$dev_id\"/" $file
  sed -i "s/\(\"program-name\": \)\"[^\"]*\"/\1\"k8s_dp\"/" $file
  sed -i "s/\(\"bfrt-config\": \)\"[^\"]*\"/\1\"\/share\/infra\/k8s_dp\/bf-rt.json\"/" $file
  sed -i "s/\(\"p4_pipeline_name\": \)\"[^\"]*\"/\1\"main\"/" $file
  sed -i "s/\(\"context\": \)\"[^\"]*\"/\1\"\/share\/infra\/k8s_dp\/context.json\"/" $file
  sed -i "s/\(\"config\": \)\"[^\"]*\"/\1\"\/share\/infra\/k8s_dp\/tofino.bin\"/" $file
  sed -i "s/\(\"path\": \)\"[^\"]*\"/\1\"\/share\/infra\/k8s_dp\"/" $file
}

# Launch infrap4d
function run_infrap4d () {
  getPid=$(pgrep -f infrap4d)  #  kill if already runnning
  [[ $getPid ]] && kill $getPid
  sleep 1
  #for running infrap4d in foreground to debug
  #gdb --args $P4CP_INSTALL/sbin/infrap4d -grpc_open_insecure_mode=true --nodetach
  #gdb --args $P4CP_INSTALL/sbin/infrap4d --nodetach
  $P4CP_INSTALL/sbin/infrap4d
  check_status $? "sbin/infrap4d"
}

#############################################
##### main ##################################
#############################################

#BASE_DIR="$(dirname "$(readlink -f "$0")")"
BASE_DIR="$K8S_RECIPE/scripts"
IF_MAX=8
MODE="host"
REMOTE_HOST="10.10.0.2"

# Displays help text
usage() {
  echo ""
  echo "Usage: $0 < -i 8|16|.. > < -m host|split > < -r 10.10.0.2 >" 1>&2;
  echo ""
  echo "Configure and setup k8s infrastructure for deployment"
  echo ""
  echo "Options:"
  echo "  -i  Num interfaces to configure for deployment"
  echo "  -m  Mode host or split, depending on where Inframanager is configured to run"
  echo "  -r  IP address configured by the user on the ACC-ARM complex for
    connectivity to the Host. This is provisioned using Node Policy - comms
    channel "[[0,3],[4,2]]". This must be specified in split mode. Script will assign
    an IP addresss from the same subnet on the Host side for connectivity."
  echo ""
  echo " Please set following env variables for host deployment:"
  echo "  SDE_INSTALL - Default SDE install directory"
  echo "  P4CP_INSTALL - Default p4cp install directory"
  echo "  DEPEND_INSTALL - Default target dependencies directory"
  echo "  K8S_RECIPE - Path to K8S recipe on the host"
  echo ""
  exit 1
}


while getopts ":i:m:r:" o; do
  case "${o}" in
      i)
          i=${OPTARG}
          ((i > 7)) || usage
          ;;
      m)
          m=${OPTARG}
          if [[ "$m" != "host" && "$m" != "split" ]]; then
            usage
          fi
          ;;
      r)
          r=${OPTARG}
          ;;
      *)
          usage
          ;;
  esac
done

shift $((OPTIND-1))

if [ -z "${i}" ] || [ -z "${m}" ]; then
  usage
fi

if [[ "$m" == "split" &&  -z "${r}" ]]; then
  echo "Host-Arm connectivity IP is empty"
  exit 1
elif [[ "$m" == "split" ]]; then
  if ! [[ "$r" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "Error: Invalid IP address format."
    exit 1
  fi
fi

IF_MAX=$i
MODE=$m
REMOTE_HOST=$r
DEV_BUS=""
echo "User entered - $IF_MAX $MODE $REMOTE_HOST"

if [ $MODE = "host" ]; then
  echo "Setting up p4k8s on host"
  check_host_env SDE_INSTALL P4CP_INSTALL DEPEND_INSTALL K8S_RECIPE
  setup_host_dep_env
  setup_run_env
  install_drivers
  sleep 4
  copy_certs
  get_device_id
  create_arp_interface
  create_pod_interfaces
  # Run infrap4d
  run_infrap4d
  echo "running host"
else
  LAST_OCTET="${REMOTE_HOST##*.}"
  NEW_OCTET=$((LAST_OCTET + 1))
  NEW_IP="${REMOTE_HOST%.*}.$NEW_OCTET"
  echo "Setting up p4k8s in split mode. Manager runs on arm"
  install_drivers
  sleep 3
  ifconfig ens801f0d3 $NEW_IP/16 up
  sleep 1
  copy_script_to_remote
  launch_on_remote "/usr/share/stratum/es2k/generate-certs.sh" ""
  copy_cert_to_remote
  SYSTEM_IP=$(get_system_ip)
  launch_on_remote "$K8S_REMOTE/$ARM_SCRIPT" "$SYSTEM_IP"
  create_arp_interface
  create_pod_interfaces
  echo "Remote script launched successfully!"
fi
