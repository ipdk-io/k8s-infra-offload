# IPDK Kubernetes* Infrastructure Offload Release Notes

## Releases

### IPDK 23.07

- This is the first release of K8s-Infra-Offload recipe that supports ES2K and DPDK targets.

### Highlights

#### ES2K target

- Support for Kubernetes Container Network Interface (CNI) to deploy pods and
  enable pod-to-pod connectivity on a P4 target using hardware device interfaces.
- Use of internal gateway with dummy MAC to enable layer-3 connectivity on the same node.
- Support for dynamic Subfunctions on ES2K.
  Subfunction is a lightweight function that has a parent PCI function on which it is
  deployed. It is created and deployed in a unit of 1. Unlike SRIOV VFs, a subfunction
  doesn't require its own PCI virtual function. A subfunction communicates with the
  hardware through the parent PCI function.
- Infra Manager build support on ARM cores.

#### DPDK target

- Support for internal gateway with dummy MAC to enable layer-3 connectivity on the
  same node.
- service of type=ClusterIP support.
  Service Load Balancing within the node to allow multiple pods on same node to
  act as end points providing any application service.
- Bi-directional Auto Learning and Flow Pinning (a.k.a Connection Tracking),
  used with load balancing, to allow consistent end point pod selection, once it
  has been selected for the first packet.
- DNS service provided by Core DNS pods to other pods.

### Common Changes

- Makefile target to support tls-secrets and certificate generation
- Automatated build & integration test on each commit
- Felix integration and communication with Infrastructure Offload Components.
- Addition of DB to store state information.
- Support for Fedora33
- Support for Go version 1.20.5
- Support for logging per feature in components
- Configurable MTU using config file

### Bug Fixes

- "make undeploy" fails as a non-root user
- Unable to deploy services after deploy/undeploy a few times
- Infra manager restarts on sending "Empty CNI Add request"
- Infra manager restarts on running anamoly test cases on fuzz testing using
  defensics
- Persistent /var/log/inframanager.log is not deleted after "make undeploy"
- conf and few other params in "inframanager/config.yaml" are not used,
  should be removed from input file
- Unable to create pods after add/delete a few times

### Known Issues

- This release does not support multi-tenant or multi-node deployments. At
  present, the underlying IPDK networking recipe needs to be run on bare metal
  on host CPU cores. The entire node, used for deployment, is assumed to be a
  trusted zone. However, gRPC/gNMI channels for communications are still
  secured using TLS.
- ES2K feature set is limited to pod-to-pod connectivity.
- Incomplete integration for Network Policies.
- Infra agent fails to come up if interface name is not correct
- Less than expected number of PODs are in Running state
- Infrap4d is not started by create_interfaces.sh script due to incorrect
  BDF in es2k_skip_p4.conf
- Inframanger crashes with error on sending invalid grpc messages from
  Defensics for fuzz testing
- Script create_interfaces.sh should report the status of the actions performed
- Inframanager log level setting and some cleanup
- Need support to set log level for all modules under Inframanager
  from the config setting

### Coming Attractions

- ``[ES2K]`` Support for Service and Load balancing.

- Support for Kubernetes Network Policy feature on both targets.

- Support for Calico BGP and basic control plane API interfaces.

- Support for natOutgoing for services with backends outside of the cluster.

- ``[ES2K]`` support for Device creation and queue allocation on ARM

- ``[ES2K]`` Infra Manager on ARM support

## Installation and Build Instructions

See the following for more information:
- [Kubernetes*, Docker*, and containerd* Installation](k8s-docker-containerd-install.md)
- [Kubernetes* Infrastructure Offload Readme](IPDK_K8s_Recipe_Readme.md)

## License, Notices, & Disclaimers

### Licensing

For licensing information, see the file "LICENSE" in the root folder of the
repository.
