#!/bin/bash

#Copyright (C) 2023 Intel Corporation
#SPDX-License-Identifier: Apache-2.0

# Check the status of a command and return
function check_status () {
  local status=$1
  local command="$2"
  if [ $status -ne 0 ]; then
    echo "Error executing command: $command"
    exit $status
  fi
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

# Setup system environment for dependency resolution
function setup_host_dep_env () {
  if [ -f "$P4CP_INSTALL/sbin/setup_env.sh" ]; then
    source $P4CP_INSTALL/sbin/setup_env.sh $P4CP_INSTALL $SDE_INSTALL $DEPEND_INSTALL
  else
    echo "Error: Missing set_env script on host"
    exit 1
  fi
}

# Install host drivers
function install_drivers () {
  modprobe mdev
  modprobe vfio-pci
  modprobe vfio_iommu_type1
  # change this to insmod & the path where idpf is built from source
  modprobe idpf
  sleep 1
  # change this with insmod in case of new idpf host driver
  dev_id=$(lspci | grep 1452 | cut -d ':' -f 1)
  echo $1 > /sys/class/pci_bus/0000:af/device/0000:$dev_id:00.0/sriov_numvfs
  #sriov vf devices take a long time to come up
  sleep 10
}

# Copy certificates for mTLS in relevant directories
function copy_certs() {
  mkdir -p $CERT_DIR/inframanager/client
  mkdir -p $CERT_DIR/inframanager/server
  mkdir -p $CERT_DIR/infraagent/client

  if [ -d "$BASE_DIR/scripts/tls/certs/inframanager/server" ]; then
    cp -r  $BASE_DIR/scripts/tls/certs/inframanager/* $CERT_DIR/inframanager/.
  fi
  if [ -d "$BASE_DIR/scripts/tls/certs/infraagent/client" ]; then
    cp $BASE_DIR/scripts/tls/certs/infraagent/client/* $CERT_DIR/infraagent/client/.
  fi

  if [ -d "$BASE_DIR/scripts/tls/certs/infrap4d" ]; then
    if [ ! -d $STRATUM_DIR ]; then
        echo "Error: Stratum directory not found."
        exit 1
    fi
    rm -rf $STRATUM_DIR/certs/ca.crt
    rm -rf $STRATUM_DIR/certs/client.crt
    rm -rf $STRATUM_DIR/certs/client.key
    rm -rf $STRATUM_DIR/certs/stratum.crt
    rm -rf $STRATUM_DIR/certs/stratum.key
    # infrap4d bug workaround
    mkdir -p /usr/share/stratum/certs
    cp $BASE_DIR/scripts/tls/certs/infrap4d/* /usr/share/stratum/certs/.
  else
    echo "Error: Missing infrap4d certificates. Run \"make gen-certs\" and try again."
    exit 1
  fi
}

# Setup infrap4d config file with K8S attributes
function setup_run_env () {
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

# Launch infrap4d
function run_infrap4d () {
  getPid=$(pgrep -f infrap4d)  #  kill if already runnning
  [[ $getPid ]] && kill $getPid
  sleep 1
  #for running infrap4d in foreground to debug
  #gdb --args $P4CP_INSTALL/sbin/infrap4d -grpc_open_insecure_mode=true --nodetach
  #gdb --args $P4CP_INSTALL/sbin/infrap4d --nodetach
  $P4CP_INSTALL/sbin/infrap4d
  sleep 1
  getPid=$(pgrep -f infrap4d)
  if [ $getPid ]; then
    echo "infrap4d is running"
  else
    echo "failed to run infrap4d"
  fi
}

#############################################
##### main ##################################
#############################################

# Globals
BASE_DIR="$K8S_RECIPE"
IF_MAX=8
MODE="host"

STRATUM_DIR="/usr/share/stratum"
CERT_DIR="/etc/pki"
DEV_BUS=""

# Displays help text
usage() {
  echo ""
  echo "*****************************************************************"
  echo "Usage: $0 < -i 8|16|.. > < -m host >" 1>&2;
  echo ""
  echo "Configure and setup k8s infrastructure for deployment"
  echo ""
  echo "Options:"
  echo "  -i  Num interfaces to configure for the deployment.
      The max limit depends on IPU configuration setting for this host.
      Recommended min is 8."
  echo "  -m  Mode host or split, depending on where Inframanager is configured
      to run. Split mode for sriov is not supported."
  echo " Please set following env variables to setup paths prior to executing
      the script:"
  echo "  SDE_INSTALL - Default SDE install directory"
  echo "  P4CP_INSTALL - Default p4cp install directory"
  echo "  DEPEND_INSTALL - Default target dependencies directory"
  echo "  K8S_RECIPE - Path to K8S recipe on the host"
  echo ""
  echo " If idpf is being built from source, please replace modprobe with
 insmod and the path to driver kernel module ko"
  echo "*****************************************************************"
  exit 1
}


while getopts ":i:m:" o; do
  case "${o}" in
      i)
          i=${OPTARG}
          ((i > 7)) || usage
          ;;
      m)
          m=${OPTARG}
          if [[ "$m" != "host" ]]; then
            usage
          fi
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

IF_MAX=$i
MODE=$m

echo "User entered - $IF_MAX $MODE $REMOTE_HOST"

if [ $MODE = "host" ]; then
  echo "Setting up p4k8s on host"
  check_host_env SDE_INSTALL P4CP_INSTALL DEPEND_INSTALL K8S_RECIPE
  setup_host_dep_env
  setup_run_env
  install_drivers $IF_MAX
  #Wait for driver initialization to happen
  sleep 6
  copy_certs
  #Run infrap4d
  run_infrap4d
  exit 0
fi
