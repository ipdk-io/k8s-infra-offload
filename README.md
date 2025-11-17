# THIS PROJECT IS ARCHIVED
Intel will not provide or guarantee development of or support for this project, including but not limited to, maintenance, bug fixes, new releases or updates.
Patches to this project are no longer accepted by Intel.  
If you have an ongoing need to use this project, are interested in independently developing it, or would like to maintain patches for the community, please create your own fork of the project. 

# Kubernetes* Infrastructure Offload Readme

  - [Overview](#overview)
  - [Motivation for Offload](#motivation-for-offload)
  - [Related Documentation](#related-documentation)
  - [Kubernetes Infrastructure Offload Components](#kubernetes-infrastructure-offload-components)
  - [Installation, Setup, and Deployment](#installation-setup-and-deployment)
  - [License, Notices, & Disclaimers](#license-notices--disclaimers)

## Overview

This repository contains the source for Calico p4 dataplane integration.
It is still in early phases with new offload features under development.

Kubernetes* (k8s) is an open-source container orchestration system for
automating deployment, scaling, and management of containerized applications
Kubernetes uses a Container Network Interface (CNI) for setting up pod-to-pod
connectivity, network policies for enforcing pod traffic isolation, and
KubeProxy for service load balancing.

The Kubernetes Infrastructure Offload project uses P4 dataplane plugin
that helps offload the networking rules from Calico* CNI to P4
target devices like IPU/DPU and FPGAs.

This readme describes the components of Kubernetes Infrastructure Offload
software and how to install and set up these components.

## Motivation for Offload

The Kubernetes architecture requires Kubernetes networking for connectivity
of the pods within a cluster be delegated to a CNI. For this, on each worker node,
Kubelet works with the co-located CNI and device plugin to assign interfaces and
configure networking rules. These include pod-to-pod connectivity, service
implementation and load-balancing, network policies (filtering)
on the traffic being sent/received by the pods etc.

![Kubernetes Architecture](docs/images/Kube-Arch.png "Kubernetes
Worker Node Architecture Without Any Offloads")

Management of these configurations and all the required packet processing,
requires significant CPU core utilization on the worker node. That takes
away significant amount of CPU cycles which could have been used for running
the actual application workload.

Additionally, this typical deployment model may not provide desired isolation
between the service provider components and the tenant's application workload.

The K8s-infra-offload software resolves both the above deficiencies.
That is, it provides means to accelerate the networking of k8s clusters by
offloading packet processing to P4 pipeline as well as, it allows the
cluster configurations to be applied from the secure IPU/DPU Infrastructure,
away from the worker node CPU cores where tenant pods run.

This integration aims to be as transparent as possible. In particular,
the p4 dataplane does not require additional deployment changes compared to
regular Calico or modifying any of the calico components.
All the networking configuration is done through regular Calico means. This
means that it is possible to have a cluster with a mix of regular Calico
nodes (linux dataplane) and P4 enabled nodes for Network intensive
endpoint applications.

The docs in this repository will only describe the p4 dataplane specific elements.

For the P4 pipeline-based packet processing, p4 artifacts specific to a
p4 target are required. This repository provides target specific
P4 pipeline artifacts as part of the K8s-Infra-Offload package.
This repository includes P4-DPDK specific p4 pipeline package.
The ES2K pipeline artifacts are available as a part of ES2K software release drops.

The p4 dataplane components interact with Kubelet and Kubernetes API server
for functionality offload. The secure split grpc design between the dataplane
components allows for secure rule configuration from the Infrastructure cores
and a clean split between the p4 dataplane Host component and the Infrastructure
offload component.

![Infra Offload Architecture](docs/images/K8s-Infra-Offload-Arch.png "Kubernetes
Worker Node Architecture With P4 Dataplane Offload")

## Related Documentation

- [IPDK Documentation](https://ipdk.io/documentation/)

## Kubernetes Infrastructure Offload Components

The following are the main components of Kubernetes Infrastructure Offload
software.

### Kubernetes Infra Manager

- The Infra Manager is deployed as a Daemonset with inframanager cluster role.
- This components acts as a gRPC server for Kubernetes Infra Agent and receives
  Kubernetes configurations from the Infra Agent over the secure gRPC channel.
- It acts as a client for the P4 Runtime Server (infrap4d) and updates the
  Kubernetes Pipeline tables (p4 dataplane) to apply runtime configurations.

### Kubernetes Infra Agent

- The Infra Agent is also deployed as a Daemonset with infragent cluster role.
- It discovers and creates an interface pool of supported device interfaces based on
  the user configuration.
- It receives CNI requests from the Calico plug-in, adds interfaces to the
  pods, and configures pod system files. And finally, it relays these configurations
  to the Infra Manager for p4 pipeline rule offload.
- It also acts as a Kubernetes client for the Kubernetes API server and receives
  notifications because of watch on Service object resources. It passes any incremental
  changes to the Infra Manager component.
- It interfaces with Infra Manager over the secure gRPC channel to pass all the
  configurations.

### Kubernetes ARP Proxy

- This process runs standalone within a separate and isolated namespace with
  one interface from the interface pool assigned to it. It resolves arp requests
  for the pipeline internal gateway IP address.
- As the name suggests, it responds to ARP requests sent by the pods, seeking
  the MAC address of the common gateway. It responds with its interface's MAC
  address.

### Kubernetes P4 Pipeline

- The Kubernetes P4 pipeline is a compiled p4 program that can be loaded on
  the P4 pipeline (i.e., P4 data plane).
- It comes along with the source P4 code for a user to understand the packet
  processing pipeline.
- It exposes P4 tables that can be modified at runtime with packet processing
  rules. These rules are for managing packet forwarding.

### Directories

- arp-proxy : Contains source code for the ARP Proxy
- bin : Contains all the binaries of the executables created by the Makefile
- deploy : Contains all the YAML files for deploying Kubernetes components
- example : Contains example YAML files to deploy test pods, etc.
- hack : Contains scripts for CI/CD
- images : Contains the Dockerfiles for Infra Agent and Infra Manager
- infraagent : Contains the source Go code of Infra Agent
- inframanager : Contains the source Go code of Infra Manager
- k8s_dp : Contains the P4 source code and the prebuilt P4 pipeline
- pkg : Contains all the supporting Go source code for Infra Manager and
  Infra Agent.
- proto : Contains all the protobuf files for gRPC messaging and the
  corresponding Go code.
- scripts : Contains all the setup scripts.


## Installation, Setup, and Deployment

Please refer to [Setup instructions](docs/Setup.md)

## License, Notices, & Disclaimers

### Licensing

For licensing information, see the file "LICENSE" in the root folder.

### Notices & Disclaimers

No product or component can be absolutely secure.

Your costs and results may vary.

Kubernetes is a registered trademark of the Linux Foundation in the United
States and other countries.
