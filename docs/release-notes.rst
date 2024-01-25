IPDK Kubernetes Infrastructure Offload Release Notes
====================================================

IPDK 24.01
------------

What's new in this Release
~~~~~~~~~~~~~~~~~~~~~~~~~~

- Service Load Balancing: Support for K8s Service of type ClusterIP.
  Kubeproxy implementation is now offloaded to hardware.
  Services can be created and dynamically distributed to endpoints.
  For TCP, only the SYN packet goes through the load-balancing logic.
  Entry is added to hardware CT table for treatment of subsequent packets.
  Support for dynamic scale-up of endpoints.
- Support for Go version 1.21.4
- Support for log level configuration from config files for Infraagent
- SRIOV support for E2100


Component Feature Support
~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1

  * - Feature
    - Description
    - Status
  * - Addition of a P4 Dataplane for offload to IPU
    - Addition of InfraAgent, InfraManager components in a split grpc
      mode for p4 based offloads to IPU pipeline using SDE
    - Production ready
  * - Enabling Secure gRPC
    - mTLS between Inframanager, Infraagent and Infrap4d grpc components
    - Production ready
  * - Proxy Arp Support
    - Proxy ARP implementation using a dummy virtual router gateway
    - Production ready
  * - Pod to pod connectivity using vrouter
    - Each pod is connected to another pod using L3 virtual routing.
      Proxy arp implementation for arp resolution.
    - Production ready
  * - Support for DPDK P4 pipeline for Pod to Pod connectivity
    - A P4 DPDK pipeline for pod to pod connectivity and service load-balancing
      using TAP interfaces and a P4 DPDK pipeline
    - Production ready
  * - Flow connection tracking
    - Connection tracking and NAT implementation using flow 5-tuple for Service Load Balancing.
    - Production ready
  * - Support for Service type “ClusterIP” for UDP and TCP traffic
    - Support for UDP and TCP services. Fully functional DNS and Kubernetes API services.
    - Production ready
  * - Support for Device interfaces like subfunctions and native interfaces like ipvlan and Tap
    - Subfunctions for E2100; Tap for DPDK
    - Production ready
  * - Execution support in Split Mode with Inframanager running on ACC
    - Inframanager running on ACC but infraagent on host
    - Production ready
  * - Automation scripts for cluster deployment
    - Example scripts for cluster deployment of Load balancing and pod scale up
    - Production ready
  * - SRIOV interface support for E2100
    - SRIOV support for E2100 in host mode in addition to CDQ
    - Engineering preview


Resolved Issues
~~~~~~~~~~~~~~~~

- After deleting and creating multiple test pods, multiple times some of the pods are not
  getting created, with error "failed to get a CDQ interface for pod: no free resources left" on infraagent.
- No Readme for TLS certificates and security guide
- Test pods are not coming to running state, as Policy related errors on inframanager
- Infraagent is not coming to running state, with the error "Error while parsing Json file"
- Inframanger restarts/crashes with "Panic occured, runtime error: invalid memory address or nil
  pointer dereference" error on sending invalid grpc messages from Defensics for fuzz testing.
- "/opt/p4/k8s/inframanager": No such file or directory" error when running setup_infra.sh in split mode
- Readme: config-manage for Docker should point to right repo supporting Rocky Linux
- infra-manager pod not coming up due to problem in cleanup of kustomization.yaml after runnning split mode.
- scripts/setup_infra.sh doesn't contain right changes to make in split mode for infraagent, inframanger
  and openssl conf files
- Internal state wasn't being retained earlier for recovery purposes.
- Sanity checks were missing for wrong configuration in case of missing node IP.
- "One or more write operations failed" due to duplicate rules present when inframanager was restarted.
- `setup_infra.sh` has infrap4d start twice in split mode.


Known Issues and Limitations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- The setup_infra.sh automation script, works with the default configuration for certificate paths
  and artifact paths. Any changes in these paths will render the script unusable.
  User may need to manually configure and execute instructions mentioned in the script.
- SRIOV is an experimental feature. The setup_infra_sriov.sh script doesn't support the -r option for remote IP for host IP on ACC. Host mode is supported for this release as an engineering preview.
- Max supported CDQ interfaces are 254 as max vport for host. The default max vport in the cdq use case cp_init file has been provided as 50 which can be configured.
- Service Load Balancing for TCP has few random session resets. Known issue and bugfix to be available in a future minor release.


IPDK 23.07
------------

- This is the first release of K8s-Infra-Offload recipe that supports E2100
  and DPDK targets.

Highlights
~~~~~~~~~~


E2100 Target
^^^^^^^^^^^^^

- Support for Kubernetes Container Network Interface (CNI) to deploy pods and
  enable pod-to-pod connectivity on a P4 target using hardware device interfaces.
- Use of internal gateway with dummy MAC to enable layer-3 connectivity on the same node.
- Support for dynamic Subfunctions on E2100.
  Subfunction is a lightweight function that has a parent PCI function on which it is
  deployed. It is created and deployed in a unit of 1. Unlike SRIOV VFs, a subfunction
  doesn't require its own PCI virtual function. A subfunction communicates with the
  hardware through the parent PCI function.
- Infra Manager build support on ARM cores.


DPDK Target
^^^^^^^^^^^^

- Support for internal gateway with dummy MAC to enable layer-3 connectivity on the
  same node.
- service of type=ClusterIP support.
  Service Load Balancing within the node to allow multiple pods on same node to
  act as end points providing any application service.
- Bi-directional Auto Learning and Flow Pinning (a.k.a Connection Tracking),
  used with load balancing, to allow consistent end point pod selection, once it
  has been selected for the first packet.
- DNS service provided by Core DNS pods to other pods.


Common Changes
~~~~~~~~~~~~~~

- Makefile target to support tls-secrets and certificate generation
- Automatated build & integration test on each commit
- Felix integration and communication with Infrastructure Offload Components.
- Addition of DB to store state information.
- Support for building K8s Offload Recipe for Rocky Linux 9.1
- Support for Go version 1.20.5
- Support for logging per feature in components
- Configurable MTU using config file

Bug Fixes
~~~~~~~~~

- "make undeploy" fails as a non-root user
- Unable to deploy services after deploy/undeploy a few times
- Infra manager restarts on sending "Empty CNI Add request"
- Infra manager restarts on running anamoly test cases on fuzz testing using
  defensics
- Persistent /var/log/inframanager.log is not deleted after "make undeploy"
- conf and few other params in "inframanager/config.yaml" are not used,
  should be removed from input file
- Unable to create pods after add/delete a few times
- Inframanger restarts/crashes with "panic: runtime error
- inframanager coming to running state after corrupting inframanager-server-ca.crt
- dump flow-entries is not decrementing after deleting the test pods
- Setup infra fixes for vfio driver bind

Known Issues
~~~~~~~~~~~~

- This release does not support multi-tenant or multi-node deployments. At
  present, the underlying IPDK networking recipe needs to be run on bare metal
  on host CPU cores. The entire node, used for deployment, is assumed to be a
  trusted zone. However, gRPC/gNMI channels for communications are still
  secured using TLS.
- E2100 feature set is limited to pod-to-pod connectivity.
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
- Split mode feature where manager runs on es2k is experimental

Coming Attractions
~~~~~~~~~~~~~~~~~~

- ``[E2100]`` Support for Service and Load balancing.

- Support for Kubernetes Network Policy feature on both targets.

- Support for Calico BGP and basic control plane API interfaces.

- Support for natOutgoing for services with backends outside of the cluster.

- ``[E2100]`` support for Device creation and queue allocation on ARM

- ``[E2100]`` Infra Manager on ARM support

Installation and Build Instructions
-----------------------------------

See the following for more information:
- [Kubernetes*, Docker*, and containerd* Installation](k8s-docker-containerd-install.md)
- [Kubernetes* Infrastructure Offload Readme](IPDK_K8s_Recipe_Readme.md)

License, Notices, and Disclaimers
---------------------------------

Licensing
~~~~~~~~~

For licensing information, see the file "LICENSE" in the root folder of the
repository.
