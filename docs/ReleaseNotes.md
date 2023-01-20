# Release Notes: IPDK 23.01 K8s Infra Offload

## Overview

This is part of IPDK 23.01 release for end users and the validation team
to use latest K8s offload features enabled by the IPDK K8S-Infra-Offload
recipe.

## What's Supported

### Highlights

- Support for Kubernetes Container Network Interface (CNI) to enable pods to
  send/receive traffic.
- Intra Node L3 Forwarding to enable pod to pod communication, on the same node,
  via CNI interfaces.
- Service Load Balancing within the node to allow multiple pods on same node to
  act as end points providing any application service.
- Bi-directional Auto Learning and Flow Pinning (a.k.a Connection Tracking),
  used with load balancing, to allow consistent end point pod selection, once it
  has been selected for the first packet.
- DNS service provided by Core DNS pods to other pods.
- Support for TLS traffic between DNS server pods and Kube API.

## K8s Infra Components

The following are the main components of K8s Infra Offload software.

### K8s Infra Manager
- The Infra Manager is deployed as a core kube-system pod along with other
  kube-system pods.
- This components acts as a gRPC server for K8s Infra Agent and receives K8s
  configurations from the Infra Agent over the gRPC channel.
- It acts as a client for the P4 Runtime Server (infrap4d) and updates the
  K8s Pipeline tables (Data Plane), over another gRPC channel, to apply K8s
  configurations.

### K8s Infra Agent
- The Infra Agent is also deployed as a core kube-system pod along with other
  kube-system pods.
- It receives all CNI requests from the Calico plug-in, configures pod system
  files and adds interaces to be pods. And finally, it relays these
  configurations to the Infra Manager.
- It also acts as a K8s client for K8s API server and receives all configuration
  changes and passes them on to the Infra Manager component.
- It interacts with Infra Manager over gRPC channel to pass all the
  configurations.

### K8s P4 Pipeline
- The K8s P4 pipeline is a pre-built component that can be loaded on the P4-DPDK
  dataplane.
- It comes along with the source P4 code for user to understand the packet
  processing pipeline.
- Offloading kube-proxy functionality, providing pod to pod L3 connectivity,
  local node gateway routing, load balancing & connection tracking, is all
  implemented within this pipeline.
- It exposes p4 tables that can be modified at runtime with packet processing
  rules. These rules are for managing pkt forwarding, service groups, service
  end points, etc.

## Debugging

- The k8s-infra-offload software provides logging capabilities. The logs are
  dumped in temporary log file e.g. /var/log/inframanager.log. These logs can
  be inspected using kubectl as below:
  kubectl exec -n kube-system -it inframanager-xx-xxxx -- cat /var/log/inframanager.log
  kubectl exec -n kube-system -it infraagent-xx-xxxx -- cat /var/log/infraagent/infraagent.log
- Logs can also be captured via kubectl using following commands:
  kubectl logs inframanager-xx-xxxxx -n kube-system
- The overall health of the InfraAgent or InfraManager can be inspected from K8s e.g.
  kubectl describe pod inframanager-xx-xxxxx -n kube-system
  

## Directories

- arp-proxy: This contains source code for the ARP Proxy
- bin: This contains all the binaries of the executables created by the
  Makefile
- deploy: This has all the YAML files for deploying kubernetes components
- example: This has example YAML files to deploy test pods, etc.
- hack: This has scripts for CI/CD
- images: This has the Dockerfiles for Infra Agent and Infra Manager
- infraagent: This has the source Go code of Infra Agent
- inframanager: This has the source Go code of Infra Manager
- k8s_dp: This has the P4 source code and the pre-built P4 pipeline
- pkg: This has all the supporting Go source code for Infra Manager and
  Infra Agent.
- proto: This has all the protobuf files for gRPC messaging and the
  corresponding Go code.
- scripts: This has all the setup scripts

## Setup scripts

- The script ./script/create_interfaces.sh sets up huge pages required by
  P4-DPDK platform, launches infrap4d (P4 OVS/SDE) and finally, creates all
  TAP interfaces (with P4TAP_ prefix) for use as CNIs for the pods.

- The script arp_proxy.sh creates a separate namespace for ARP proxy, assigns
  the first TAP interface (i.e. P4TAP_0) to it and then launches ARP proxy
  within the isolated namespace.

## Documentation

- The [Kubernetes Infra Offload Usage Guide](https://github.com/ipdk-io/k8s-infra-offload/blob/main/README.md) provides the installation and deployment instructions.

## Security Domain

This release does not support multi-tenant or multi-node deployments. At
present, the underlying IPDK networking recipe needs to be run on bare metal.
The entire node, used for deployment, is assumed to be within the trusted zone
and hence, gRPC/gNMI channels for communication is not secured using TLS. When
running infrap4d or gnmi-ctl, the "grpc_open_insecure_mode" option is set to
true.

## Bug Fixes

- Added test pod remains in pending state

- Need support to set log-level in Infra Manager

- Need ability to run ARP proxy setup in a script

- Unable to create pods after add/delete a few times

- Unable to start service after start/delete a few times

- /var/log/inframanager.log is not deleted after "make undeploy"

- Unused params in "inframanager/config.yaml" should be removed from input file

## Known Issues

- The LogLevel configuration option in the config.yaml file does not apply in
  a consistent manner. For example, the logs generated at some places may be
  more than configured level.

## Coming Attractions

- Support for TLS protected gRPC channels used for communication

- Support for multi-tenancy (multiple VMs) on single node

- Support for multi-node deployment with inter node L3 forwarding

- Support for K8s Network Policy
