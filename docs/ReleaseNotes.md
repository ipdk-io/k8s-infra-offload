# IPDK Kubernetes* Infrastructure Offload Release Notes

## What's New in This Release

### IPDK 23.07 K8s-Infra-Offload Component

- This is the release of K8s-Infra-Offload recipe for ES2K and DPDK targets.
This is the first release that supports both these targets.

### Highlights

#### DPDK and ES2K targets
- Support for Kubernetes Container Network Interface (CNI) to enable pods to
  send/receive traffic.
- Intra Node L3 Forwarding to enable pod to pod communication, on the same node,
  via CNI interfaces.

#### DPDK target
- Service Load Balancing within the node to allow multiple pods on same node to
  act as end points providing any application service.
- Bi-directional Auto Learning and Flow Pinning (a.k.a Connection Tracking),
  used with load balancing, to allow consistent end point pod selection, once it
  has been selected for the first packet.
- DNS service provided by Core DNS pods to other pods.

### Security Domain

This release does not support multi-tenant or multi-node deployments. At
present, the underlying IPDK networking recipe needs to be run on bare metal
on host CPU cores. The entire node, used for deployment, is assumed to be a
trusted zone. However, gRPC/gNMI channels for communications are still
secured using TLS. For that, the user should create the TLS keys and
certificates and install them as per the steps given in the README.

### Bug Fixes


### Known Issues


### Coming Attractions

- Support for Service and Load balancing on ES2K target.

- Support for Kubernetes Network Policy feature.

- Support for multi-node deployment with inter node L3 forwarding

## Installation and Build Instructions

See the following for more information:
- [Kubernetes*, Docker*, and containerd* Installation](k8s-docker-containerd-install.md) 
- [Kubernetes* Infrastructure Offload Readme](IPDK_K8s_Recipe_Readme.md)

## License, Notices, & Disclaimers

### Licensing

For licensing information, see the file "LICENSE" in the root folder of the
repository.
