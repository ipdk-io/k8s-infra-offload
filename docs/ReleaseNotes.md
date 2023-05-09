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
