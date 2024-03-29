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

function launch_on_remote {
    local script="$1"
    local arg="$2"

    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $REMOTE_HOST "$script $arg"
    check_status $? "ssh $REMOTE_HOST \"$script\" \"$arg\""
    return 0
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
  # change this with insmod in case of new idpf host driver
  modprobe idpf
  if [[ "$1" == "sriov" ]]; then
    sleep 1
    # change this with insmod in case of new idpf host driver
    dev_id=$(lspci | grep 1452 | cut -d ':' -f 1)
    echo $2 > /sys/class/pci_bus/0000:$dev_id/device/0000:$dev_id:00.0/sriov_numvfs
    #sriov vf devices take a long time to come up
    sleep 10
  fi
}

function generate_config() {
  if [ -f "$BASE_DIR/bin/generate-config" ]; then
      echo "Generating inframanager and agent config"
      $BASE_DIR/bin/generate-config
      check_status $? "$BASE_DIR/bin/generate-config"
  else
      echo "Error: Missing $BASE_DIR/bin/generate-config"
      exit 1
  fi
}

# Get PCI device ID for IDPF
function get_device_id () {
  dev_id=$(lspci | grep 1452 | cut -d ':' -f 1)
  if [ -z "$dev_id" ]; then
    echo "No matching dev_id found."
    exit 1
  fi

  devlink_output=$(devlink dev show)
  DEV_BUS=$(echo "$devlink_output" | grep "$dev_id\:")
}

# Config comms channel on host side
function config_comms_channel_host () {
  IP_ADDR=$1
  pf_id=$(lspci | grep 1452 | cut -d ':' -f 1)
  HCOMM_IFACE=$(grep PCI_SLOT_NAME /sys/class/net/*/device/uevent | grep $pf_id |  grep  -E "d3\b" | cut -d'/' -f5)
  echo "$HCOMM_IFACE"
  ifconfig $HCOMM_IFACE $IP_ADDR/16 up
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

# Copy certificates for mTLS in relevant directories
function copy_cert_to_remote() {
  mkdir -p $CERT_DIR/infraagent/client
  if [ -d "$BASE_DIR/scripts/tls/certs/infraagent/client" ]; then
    cp $BASE_DIR/scripts/tls/certs/infraagent/client/* $CERT_DIR/infraagent/client/.
  fi

  # setup directory structure on ACC for p4infrad and manager certs
  #launch_on_remote "/usr/share/stratum/es2k/generate-certs.sh" ""
  launch_on_remote "mkdir -p /usr/share/stratum/certs" ""
  launch_on_remote "mkdir -p /etc/pki/inframanager" ""

  if [ -d "$BASE_DIR/scripts/tls/certs/infrap4d" ]; then
    # copy certs to remote infrap4d dir
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $BASE_DIR/scripts/tls/certs/infrap4d/* $REMOTE_HOST:/usr/share/stratum/certs
    check_status $? "scp infrap4d/certs/* root@$REMOTE_HOST:/usr/share/stratum/certs"

    # copy certs to remote inframanager dir
    scp -r -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $BASE_DIR/scripts/tls/certs/inframanager/* $REMOTE_HOST:/etc/pki/inframanager/.
    check_status $? "scp $BASE_DIR/scripts/tls/certs/inframanager/* root@$REMOTE_HOST:/etc/pki/inframanager/"
  else
    echo "Error: Missing infrap4d certificates. Run \"make gen-certs\" and try again."
    exit 1
  fi
}

# Copy Artifacts to Remote
function copy_artifacts_to_remote() {
  if [ -f "$BASE_DIR/k8s_dp/es2k/k8s_dp.pb.bin" ]; then
    launch_on_remote "mkdir -p /share/infra/k8s_dp" ""
    scp -r -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $BASE_DIR/k8s_dp/es2k/* $REMOTE_HOST:/share/infra/k8s_dp/.
    check_status $? "scp $BASE_DIR/k8s_dp/es2k/* root@$REMOTE_HOST:/share/infra/k8s_dp/"
  else
    echo "Error: Missing compiler artifacts and proto file. Please compile p4 program and generate."
    exit 1
  fi
}

# Copy Config file to Remote
function copy_config_to_remote() {
  if [ -f "$BASE_DIR/deploy/inframanager-config.yaml" ]; then
    launch_on_remote "mkdir -p /etc/infra" ""
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $BASE_DIR/deploy/inframanager-config.yaml $REMOTE_HOST:/etc/infra/.
    check_status $? "scp $BASE_DIR/deploy/inframanager-config.yaml root@$REMOTE_HOST:/etc/infra/"
  else
    echo "Error: Missing InfraManager config file."
    exit 1
  fi

  launch_on_remote "mkdir -p /share/infra/jsonfiles" ""
  scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $BASE_DIR/pkg/inframanager/p4/*.json $REMOTE_HOST:/share/infra/jsonfiles/.
  check_status $? "scp $BASE_DIR/pkg/inframanager/p4/*.json root@$REMOTE_HOST:/share/infra/jsonfiles"
}

# Copy remote execution script to arm acc
function copy_script_to_remote() {
  if [ -f "$BASE_DIR/scripts/$ARM_SCRIPT" ]; then
    # copy acc setup script to k8s dir
    scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $BASE_DIR/scripts/$ARM_SCRIPT $REMOTE_HOST:/opt/p4/k8s/.
    check_status $? "scp scripts/setup_arm_infra.sh/* root@$REMOTE_HOST:/opt/p4/k8s"
  else
    echo "Error: Missing arm script"
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
  sed -i "s/\"cfgqs-idx\": \"[0-9]-15\"/\"cfgqs-idx\": \"0-15\"/g" "$file"
  if ! grep -q "disable-tblsz-check" "$file"; then
    sed -i '/"cfgqs-idx"/a \    "disable-tblsz-check": 1,' "$file"
  fi
  sed -i "s/\(\"pcie_bdf\": \)\"[^\"]*\"/\1\"0000:$dev_id\"/" $file
  sed -i "s/\(\"program-name\": \)\"[^\"]*\"/\1\"k8s_dp\"/" $file
  sed -i "s/\(\"tdi-config\": \)\"[^\"]*\"/\1\"\/share\/infra\/k8s_dp\/tdi.json\"/" $file
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
REMOTE_HOST="10.10.0.2"

STRATUM_DIR="/usr/share/stratum"
ARM_SCRIPT="setup_arm_infra.sh"
K8S_REMOTE="/opt/p4/k8s"
CERT_DIR="/etc/pki"
DEV_BUS=""
TYPE="cdq"

# Displays help text
usage() {
  echo ""
  echo "*****************************************************************"
  echo "Usage: $0 < -i 8|16|.. > < -m host|split > < -r 10.10.0.2 > [ -t cdq|sriov ]" 1>&2;
  echo ""
  echo "Configure and setup k8s infrastructure for deployment"
  echo ""
  echo "Options:"
  echo "  -i  Num interfaces to configure for the deployment.
      The max limit depends on IPU configuration setting for this host.
      Recommended min is 8."
  echo "  -m  Mode host or split, depending on where Inframanager is configured
      to run"
  echo "  -r  IP address configured by the user on the ACC-ARM complex for
      connectivity to the Host. This is provisioned using Node Policy -
      comms channel \"([5,0],[4,0]),([4,2],[0,3])\". This must be specified
      in split mode. Script will assign an IP addresss from the same subnet
      on the Host side for connectivity."
  echo "  -t  Type of the device interface. Default - cdq"
  echo ""
  echo " Please set following env variables to setup paths prior to executing
      the script:"
  echo "  SDE_INSTALL - Default SDE install directory"
  echo "  P4CP_INSTALL - Default p4cp install directory"
  echo "  DEPEND_INSTALL - Default target dependencies directory"
  echo "  K8S_RECIPE - Path to K8S recipe on the host"
  echo ""
  echo " If idpf is being built from source, please replace modprobe with
 insmod and the path to driver kernel module ko."
  echo "*****************************************************************"
  exit 1
}


while getopts ":i:m:r:t:" o; do
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
      t)
          t=${OPTARG}
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

if [[ "$m" == "split" ]] && [ -z "${r}" ]; then
  echo "Error: Missing Host-Arm connectivity information - \"remote IP Address\"."
  usage
fi

if [[ "$m" == "split" ]]; then
  if ! [[ "$r" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "Error: Invalid IP address format."
    exit 1
  fi
fi

if [[ "$t" == "sriov" ]]; then
    echo "Creating interfaces of type sriov"
    TYPE="sriov"
else
    TYPE="cdq"
    echo "Creating interfaces of type cdq"
fi

IF_MAX=$i
MODE=$m
REMOTE_HOST=$r

echo "User entered - $IF_MAX $MODE $REMOTE_HOST $TYPE"

if [[ "$MODE" == "host" ]]; then
  echo "Setting up p4k8s on host"
  check_host_env SDE_INSTALL P4CP_INSTALL DEPEND_INSTALL K8S_RECIPE
  setup_host_dep_env
  setup_run_env
  install_drivers $TYPE $IF_MAX
  generate_config
  #Wait for driver initialization to happen
  sleep 6
  copy_certs
  if [[ "$TYPE" == "cdq" ]]; then
    get_device_id
    create_arp_interface
    create_pod_interfaces
  fi
  #Run infrap4d
  run_infrap4d
else
  echo "Setting up p4k8s in split mode. Manager runs on arm"
  check_host_env SDE_INSTALL P4CP_INSTALL DEPEND_INSTALL K8S_RECIPE
  LAST_OCTET="${REMOTE_HOST##*.}"
  NEW_OCTET=$((LAST_OCTET + 1))
  NEW_IP="${REMOTE_HOST%.*}.$NEW_OCTET"
  install_drivers $TYPE $IF_MAX
  generate_config
  #Wait for driver initialization to happen
  sleep 6
  config_comms_channel_host $NEW_IP
  sleep 1
  copy_script_to_remote
  copy_cert_to_remote
  copy_artifacts_to_remote
  copy_config_to_remote
  SYSTEM_IP=$(hostname -I | awk '{print $1}')
  if [[ "$TYPE" == "cdq" ]]; then
    get_device_id
    create_arp_interface
    create_pod_interfaces
  fi
  launch_on_remote "$K8S_REMOTE/$ARM_SCRIPT" "$SYSTEM_IP"
  echo "Remote script launched successfully!"
  exit 0
fi
