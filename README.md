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

### Debugging

- The Kubernetes Infrastructure Offload software provides logging capabilities.
  The logs are dumped in temporary log file. Logs for Infra Manager are put in
  `/var/log/inframanager/inframanager.log` while logs for Infra Agent are put
  in `/var/log/infraagent/infraagent.log`). You can inspect logs emitted to stdout
  and stderr using `"kubectl logs <pod> <namespace>"`.

### Setup Scripts

- The script `./script/create_interfaces.sh` sets up HugePages required by
  DPDK and launches infrap4d (P4 OVS/SDE).

- The script `arp_proxy.sh` creates a separate namespace for the ARP proxy,
  assigns an interface to it, and then launches the ARP proxy within the
  isolated namespace.

## Installation, Setup, and Deployment

### Installing Kubernetes

Kubernetes Infra Offload requires Kubernetes, Docker*, and containerd* to be
installed. See [Kubernetes*, Docker*, and containerd* Installation](docs/k8s-docker-containerd-install.md)
for instructions. If these components are already installed on the machine,
proceed to next step.

### Set Up Target and Dependencies

Kubernetes Infra Offload supports two targets, viz. P4-DPDK and Intel IPU ES2K.
The Intel IPU ES2K target requires proper hardware setup and initialization.
On both these platforms, Kubernetes Infra Offload software depends upon the
daemon InfraP4d of the IPDK networking recipe to be runnning in the background.
Once InfraP4d is running, Kubernetes can load its P4 pipeline and offload
various functionalities on it (i.e. on the P4 data plane).

The instructions to setup the target and install infrap4d and its dependencies,
are different for the two targets.
See [Target Setup for P4-DPDK](docs/target-setup-dpdk.md) for instructions on
installation of SDE and InfraP4d on P4-DPDK target.
See [Target Setup for Intel IPU ES2K](docs/target-setup-es2k.md) for
instructions on hardware setup and installation of SDE and InfraP4d on Intel
IPU ES2K target.

### Set Up P4 Kubernetes

1. Install Go package (go version go1.20.5 linux/amd64), following instruction
   at https://go.dev/doc/install

2. Pull P4-K8s software from the GitHub repository:

   ```bash
   git clone https://github.com/ipdk-io/k8s-infra-offload.git p4-k8s
   cd p4-k8s
   git checkout ipdk_v23.07
   ```

3. Build P4-K8s binaries and container images.

   Notes:
   i) For ES2K target, get the K8s P4 artifacts from ES2K release package and
      copy them into p4-k8s/k8s_dp/es2k/. This must be done before running
      below make commands.
   ii) By default, Makefile is configured to build for ES2K target. To build
      for P4-DPDK target, use "tagname=dpdk" argument for both make targets
      below.

   Build Kubernetes binaries:

   ```bash
   make build
   ```
   Then build the Kubernetes container images:
   ```bash
   make docker-build
   ```

4. Push InfraManager and InfraAgent images into docker private repo either
   manually or through make command, using either of the following:

   ```bash
   make docker-push
   ```
   or
   ```bash
   docker push localhost:5000/infraagent:latest
   docker push localhost:5000/inframanager:latest
   ```

   The docker images should now be listed in the local repository as below.
   ```bash
   docker images
   ```
   ```none
   REPOSITORY                             TAG           IMAGE ID       CREATED         SIZE
   localhost:5000/inframanager            latest        7605ed47e042   5 minutes ago   22.1MB
   <none>                                 <none>        485d7bc6ec38   5 minutes ago   1.38GB
   localhost:5000/infraagent              latest        500075b89922   6 minutes ago   68.7MB
   <none>                                 <none>        dc519d06de56   6 minutes ago   1.68GB
   ...
   ```

5. Pull images for use by Kubernetes Container Runtime Interface (CRI):
   ```bash
   crictl pull localhost:5000/inframanager:latest
   crictl pull localhost:5000/infraagent:latest
   ```

6. Generate the certificates required for the mTLS connection between infraagent,
   inframanager, and infrap4d:
   ```bash
   make gen-certs
   ```
   Note that the above script generates the default keys and certificates and
   uses cipher suites as specified in the `inframanager/config.yaml` file. If you
   do not wish to use these default keys, certificates, and cipher suites, then
   modify the `scripts/mev/tls/gen_certs.sh` script accordingly and modify the
   `inframanager/config.yaml` file with preferred cipher suites.

### Deploy P4 Kubernetes

1. Run the `create_interfaces.sh` script, which, in addition to creating the
   specified number of virtual interfaces (TAP type on DPDK target and IDPF
   Sub-Function type on ES2K), sets up the HugePages and starts infrap4d. The
   script requires the following environment variables to be set:
   `SDE_INSTALL`, `IPDK_RECIPE`, `DEPEND_INSTALL`.

   ```bash
   ./scripts/create_interfaces.sh <8/16/32/...>
   ```

   After running the above script, verify that infrap4d is running.
   ```bash
   ps -ef | grep infrap4d
   ```
   ```none
   root     1254701       1 99 13:34 ?        00:13:10 /host/networking-recipe/install/sbin/infrap4d
   ```

   On ES2K target, this script will also load the IDPF driver. Verify the
   presence of the PF:
   ```bash
   devlink dev show
   ```
   ```none
   pci/0000:af:00.0
   ```

2. Run ARP-Proxy script, which creates a new namespace and assigns an interface
   from the pool of interfaces created in previous step.
   On ES2K target, user needs to explicitly configure the interface to be
   assigned using IFACE environment variable.
   ```bash
   export IFACE=ens801f0d4
   ```

   For DPDK target, change the interfaceType in config.yaml file to "tap".

   The script finally runs the arp-proxy on that assigned interface, within the
   isolated namespace.
   ```bash
   ./scripts/arp_proxy.sh
   ```

3. Initialize and start the core Kubernetes components:
   ```bash
   kubeadm init --pod-network-cidr=<pod-cidr> --service-cidr=<service-cidr>
   ```

4. Once the Kubernetes control plane initialization has completed successfully,
   then do either of the following: 
   - As a non-root user:
     ```bash
     mkdir -p $HOME/.kube
     cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
     chown $(id -u):$(id -g) $HOME/.kube/config
     ```
   - Or as root user:
     ```bash
     export KUBECONFIG=/etc/kubernetes/admin.conf
     ```

5. Remove taints from the node.
   For single node deployment, the node must be untainted to allow worker pods
   to share the node with control plane. The taint to remove is "control-plane"
   or "master" or both. These taints can be removed as shown:
   ```bash
   kubectl taint node <node-name> node-role.kubernetes.io/control-plane-
   kubectl taint node <node-name> node-role.kubernetes.io/master-
   ```

6. Create Kubernetes secrets from the generated certificates. The infraagent and
   inframanager read the certificates from the secrets.
   ```bash
   make tls-secrets
   ```

8. Start the deployments:
   ```bash
   make deploy
   make deploy-calico
   ```

   Check deployment using the following:
   ```bash
   kubectl get pods -A -o wide
   ```

### Pod-to-Pod Ping

  To run a simple ping test from one pod to another, create two test pods. Note
  that, the yaml file in the package is to create a single test pod; you can copy
  and modify it to create pod with different name. For example, copy it as
  `test-pod2.yaml` and change the metadata name and container name to be
  `test-pod2`. The .yaml file for test-pod2 should look as below.
  ```yaml
  apiVersion: v1
  kind: Pod
  metadata:
    name: test-pod2
  spec:
    containers:
    - name: test-pod2
      image: quay.io/quay/busybox:latest
      ...
  ```

  Then, carry out the following steps.

1. Create both the test pods:
   ```bash
   kubectl create -f example/test_pod.yaml
   kubectl create -f example/test_pod2.yaml
   ```

   Check that the two test pods are ready and running:
   ```bash
   kubectl get pods -o wide
   ```
   ```none
   NAME        READY   STATUS    RESTARTS   AGE    IP               NODE    NOMINATED NODE   READINESS GATES
   test-pod    1/1     Running   0          10m    10.244.0.6       ins21   <none>           <none>
   test-pod2   1/1     Running   0          9m33s  10.244.0.7       ins21   <none>           <none>
   ```

2. Use the IP address from above output or `ifconfig` to get the IP address
   assigned to one of the pods. Then, ping that address from the other pod:
   ```bash
   kubectl exec test-pod2 -- ifconfig eth0
   kubectl exec test-pod -- ping 10.244.0.6
   ```
   ```none
   PING 10.244.0.6 (10.244.0.6): 56 data bytes
   64 bytes from 10.244.0.6: seq=0 ttl=64 time=0.112 ms
   64 bytes from 10.244.0.6: seq=1 ttl=64 time=0.098 ms
   64 bytes from 10.244.0.6: seq=2 ttl=64 time=0.102 ms
   64 bytes from 10.244.0.6: seq=3 ttl=64 time=0.112 ms
   ...
   ```

3. To delete above created test pods:
   ```bash
   kubectl delete pod test-pod test-pod2
   ```

### Service Deployment
  
  NOTE: This is currently suported on DPDK target only.
  
  To test simple service deployment, user can use iperf based server available
  in https://github.com/Pharb/kubernetes-iperf3.git repository.

1. Clone this repository and deploy the service as below:
   ```bash
   git clone https://github.com/Pharb/kubernetes-iperf3.git
   cd kubernetes-iperf3
   ./steps/setup.sh
   kubectl get svc -A -o wide
   ```
   ```none
   NAME            TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)    AGE     SELECTOR
   iperf3-server   ClusterIP   10.111.123.3   <none>        5201/TCP   6m56s   app=iperf3-server
   kubernetes      ClusterIP   10.96.0.1      <none>        443/TCP    15m     <none>
   ```
 
   ```bash
   kubectl get ep -A -o wide
   ```
   ```none
   NAMESPACE     NAME            ENDPOINTS                                               AGE
   default       iperf3-server   10.244.0.5:5201,10.244.0.6:5201                         5h22m
   default       kubernetes      10.233.134.119:6443                                     5h35m
   kube-system   kube-dns        10.244.0.3:53,10.244.0.4:53,10.244.0.3:53 + 3 more...   5h35m
   ```

   ```bash
   kubectl get pods -A -o wide
   ```
   ```none
   NAME                                        READY   STATUS    RESTARTS   AGE   IP           NODE    NOMINATED NODE   READINESS GATES
   iperf3-clients-8gkv7                        1/1     Running   0          18m   10.244.0.9   ins21   <none>           <none>
   iperf3-server-deployment-59bf4754f9-4hp4c   1/1     Running   0          18m   10.244.0.8   ins21   <none>           <none>
   ...
   ```
  
2. To test service traffic, iperf3 client can be started as below:
   ```bash
   cd kubernetes-iperf3
   ./steps/run.sh
   ```

   The iperf3 client can also be executed manually inside the iperf client pod
   ```bash
   kubectl exec --stdin --tty <iperf3-clients-xxx> -- /bin/bash
   iperf3 -c iperf3-server
   ```
   ```none
   Connecting to host iperf3-server, port 5201
   [  5] local 10.244.0.7 port 37728 connected to 10.96.186.247 port 5201
   [ ID] Interval           Transfer     Bitrate         Retr  Cwnd
   [  5]   0.00-1.00   sec   107 KBytes   880 Kbits/sec    2   1.41 KBytes
   [  5]   1.00-2.00   sec  0.00 Bytes  0.00 bits/sec    1   1.41 KBytes
   ```

3. The service created above can be removed as below:
   ```bash
   ./steps/cleanup.sh
   ```

### Clean Up All
   Reset kubernetes which would stop and remove all pods. Then, remove all k8s
   runtime configurations and other files. Finally, stop container services.

   Delete all started pods, service deployments and daemonsets
   ```bash
   kubectl delete pod < >
   kubectl delete deployment < >
   make undeploy
   make undeploy-calico
   ```
   Reset Kubernetes and remove all configuration and runtime directories
   associated with Kubernetes.
   ```bash
   kubeadm reset -f
   rm -rf /etc/cni /etc/kubernetes
   rm -rf /var/lib/etcd /var/lib/kubelet /var/lib/cni
   rm -rf /var/run/kubernetes
   rm -rf $HOME/.kube
   ```
   Stop the local container registry and stop container services
   ```bash
   docker container stop registry && docker container rm -v registry
   systemctl stop containerd
   ```

   Stop the ARP proxy and infrap4d processes running. This will also remove all
   the virtual interfaces that were created earlier.
   ```bash
   pkill arp_proxy
   pkill infrap4d
   ```

## License, Notices, & Disclaimers

### Licensing

For licensing information, see the file "LICENSE" in the root folder.

### Notices & Disclaimers

No product or component can be absolutely secure.

Your costs and results may vary.

Kubernetes is a registered trademark of the Linux Foundation in the United
States and other countries.
