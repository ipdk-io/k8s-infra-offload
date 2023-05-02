# Kubernetes Infra Offload Usage Guide
- [Kubernetes Infra Offload Usage Guide](#kubernetes-infra-offload-usage-guide)
  - [Motivation for Offload](#motivation-for-offload)
  - [General requirements](#general-requirements)
  - [Kubernetes installation](#kubernetes-installation)
  - [IPDK Networking recipe install](#ipdk-networking-recipe-install)
  - [Setup P4-K8s](#setup-p4-k8s)
  - [P4-K8s Deployment](#p4-k8s-deployment)
  - [Simple Pod-to-Pod Ping Test](#simple-pod-to-pod-ping-test)
  - [Service deployment Test](#service-deployment-test)
  - [Cleanup All](#cleanup-all)

## Motivation for Offload
The Kubernetes architecture requires Kubernetes networking for connectivity
of the pods within and outside the cluster be delegated to the CNI. For this,
on each worker node, Kubelet works with the co-located CNI to configure and
assign interfaces to the pods created on that worker node. In addition, the
Kube-proxy on each worker node interacts with Kubernetes control plane to
provide support for Services. Without any offloads, both CNI and kube-proxy
typically depend upon Linux kernel to provide these networking and service
support. These include routing of traffic to/from the pods, applying network
policies (filtering) on the traffic being sent/received by the pods, load
balancing and NAT operations on traffic flows belonging to Services, etc.

![Kubernetes Architecture](docs/images/Kube-Arch.png "Kubernetes
Worker Node Architecture Without Any Offloads")

Management of these configurations and all the required packet procesing,
requires significant CPU core utilization on the worker node. That takes away
significant amount of CPU cycles which could have been used for running the
actual application workload.

Additionally, this typical deployment model may not provide desired isolation
between the service provider components and the tenent's application workload.

The K8s-infra-offload software resolves both above deficiencies. That is, it
provides means to offload the packet processing to P4 pipeline as well as, it
allows the CNI and Kube-proxy configurations to be applied from outside the
worker node CPU cores.

For the P4 pipeline based packet processing, it defines and provides target
specific P4 pipeline as part of the K8s-Infra-Offload package. This includes
P4-DPDK target specific P4 pipeline.

For configuration aspects, it interacts with CNI plugin and Kubernetes API
server over secure gRPC channels. This allows the CNI configuration to be
managed from a different CPU complex.

![Infra Offload Architecture](docs/images/K8s-Infra-Offload-Arch.png "Kubernetes
Worker Node Architecture With P4 Dataplane Offload")

## General requirements
- For Infra Agent and Infra Manager to work, Kernel 5.4 or greater is required.
- The recommended OS to be used is Fedora 33
- The recommended Kubernetes version to be used is 1.25.0
- TAP interfaces should be created and available on the host system before Infra Agent is deployed. The default prefix for TAP interfaces names, as required by InfraAgent is "P4TAP_".
- The number of TAP interfaces created must be a power of 2 and more than 4. For example, it can be 8, 16, 32 and so on.
- The P4 data plane program (k8s_dp.p4) and the configuration file (k8s_dp.conf), must not be modified as the k8s control plane software is tightly coupled with the pipeline. The P4 compiler generated artifacts are available in the container and must be used as is.
- The firewall, if enabled in host OS, should either be disabled or configured to allow required traffic to flow through.
- Many steps contained in this README require root permissions, especially the
  ones which install kubernetes and related software and configure system files.
  So, even though many steps can be carried out as non-root user, it is recommended
  to run all the steps as root to avoid any confusion.

## Kubernetes installation
Kubernetes Infra Offload requires Kubernetes, docker and containerd to be
installed. The instructions on how to install these pre-requires, follow
[Kubernetes, Docker, Containerd Installation](docs/k8s-docker-containerd-install.md).

## IPDK Networking recipe install
Kubernetes Infra Offload deployment depends upon the daemon infrap4d of IPDK
networking recipe to be running in the background. Once infrap4d is running,
kubernetes can load its P4 pipeline and offload various functionalities on it
i.e. on P4 data plane. Note that, IPDK infrap4d needs to installed and run on
the host natively. To install infrap4d and P4-SDE (components as per IPDK 23.01
release) individually, follow the instructions listed below. Note that, P4C is
not required as this software includes P4C generated artifacts.
   
  ### P4-SDE
  To install P4-SDE, follow instructions at https://github.com/p4lang/p4-dpdk-target. Make sure to checkout SHA:199d418f5fcfaca7fb7992d4867e72b39ebe6e31 from the main branch. User can also refer to README.md for instructions. The main steps can be summerized as:

  Clone SDE repository, create install directory, setup environment variable and then build
  ```bash
  # git clone https://github.com/p4lang/p4-dpdk-target
  # mkdir install
  # export SDE=$PWD
  # cd p4-dpdk-target
  # git checkout 199d418f5fcfaca7fb7992d4867e72b39ebe6e31
  # git submodule update --init --recursive --force
  # cd ./tools/setup
  # source p4sde_env_setup.sh $SDE
  # cd $SDE/p4-dpdk-target
  # ./build-p4sde.sh -s $SDE_INSTALL
  ```
  
  ### Infrap4d
  To install infrap4d, follow instructions as per the ipdk-dpdk link https://github.com/ipdk-io/networking-recipe/blob/ipdk_v23.01/docs/ipdk-dpdk.md. Note that, for the networking recipe, check out the tip of the ipdk_v23.01 branch. The main steps can be summarized as:
  ```bash
  # git clone https://github.com/ipdk-io/networking-recipe.git ipdk.recipe
  # cd ipdk.recipe
  # git checkout ipdk_v23.01
  # git submodule update --init --recursive
  # export IPDK_RECIPE=$PWD
  # mkdir DEP_LIB
  # export DEPEND_INSTALL=$PWD/DEP_LIB
  # cd $IPDK_RECIPE/setup
  # cmake -B build -DCMAKE_INSTALL_PREFIX=$DEPEND_INSTALL
  # cmake --build build [-j<njobs>]

  # cd $IPDK_RECIPE
  # source ./scripts/dpdk/setup_env.sh $IPDK_RECIPE $SDE_INSTALL $DEPEND_INSTALL
  # ./make-all.sh --target=dpdk
  # ./scripts/dpdk/copy_config_files.sh $IPDK_RECIPE $SDE_INSTALL
  ```

## Setup P4-K8S
  Install Go package (go version go1.19.4 linux/amd64), following instruction
  at https://go.dev/doc/install
 
  Pull P4-K8s and other software
  ```bash
  # git clone https://github.com/ipdk-io/k8s-infra-offload.git p4-k8s
  # cd p4-k8s
  # git checkout ipdk_v23.01
  ```
  
  Build p4-k8s images and other binaries as below
  ```bash
  # make build
  # make docker-build
  ```
  
  Push InfraManager and InfraAgent images into docker private repo either
  manually or through make command.
  
  Either
  ```bash
  # make docker-push
  ```
  Or
  ```bash
  # docker push localhost:5000/infraagent:latest
  # docker push localhost:5000/inframanager:latest
  ```
  
  The docker images should now be listed in the local repository as below.
  ```bash
  # docker images
  REPOSITORY                             TAG           IMAGE ID       CREATED         SIZE
  localhost:5000/inframanager            latest        7605ed47e042   5 minutes ago   22.1MB
  <none>                                 <none>        485d7bc6ec38   5 minutes ago   1.38GB
  localhost:5000/infraagent              latest        500075b89922   6 minutes ago   68.7MB
  <none>                                 <none>        dc519d06de56   6 minutes ago   1.68GB
  ...
  ```
  
  Pull images for use by Kubernetes CRI
  ```bash
  # crictl pull localhost:5000/inframanager:latest
  # crictl pull localhost:5000/infraagent:latest
  ```
 
## P4-K8s Deployment
  Generate the certificates required for mTLS connection between infraagent,
  inframanager and infrap4d
  ```bash
  # make gen-certs
  ```

  Run create_interfaces.sh script which, in addition to creating specified
  number of TAP interfaces, sets up the huge pages and starts infrap4d.
  Scripts requires following env variables to be set - SDE_INSTALL,
  IPDK_RECIPE, DEPEND_INSTALL. These env variables are defined in
  networking-recipe/main/docs/ipdk-dpdk.md

  ```bash
  # ./scripts/create_interfaces.sh <8/16/32/...>
  ```
    
  After running the above script, verify that infrap4d is running.
  ```bash
  # ps -ef | grep infrap4d
  root     1254701       1 99 13:34 ?        00:13:10 /host/networking-recipe/install/sbin/infrap4d
  ```

  Run ARP-Proxy script, which would create a new namespace, assign first tap
  interface i.e. P4TAP_0 to it, and finally run the arp-proxy on that interface.
  ```bash
  ./scripts/arp_proxy.sh
  ```

  Initialize and start the core k8s components as below
  ```bash
  # kubeadm init --pod-network-cidr=<pod-cidr> --service-cidr=<service-cidr>
  ```
    
  Once K8s control plane initialization is complete successfully, then (as
  non-root user)
  ```bash
  # mkdir -p $HOME/.kube
  # cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
  # chown $(id -u):$(id -g) $HOME/.kube/config
  ```
  Or (as root user)
  ```bash
  # export KUBECONFIG=/etc/kubernetes/admin.conf
  ```
    
  Start the deployments
  Note that, for single node deployment, the node must be untainted to allow
  worker pods to share the node with control plane. This can be done as below.
  ```bash
  # kubectl taint node <node-name> node-role.kubernetes.io/control-plane-
  ```
  Create k8s secrets from the generated certificates. The infraagent and the
  manager reads the certificates from the secrets.

  ```bash
  make tls-secrets
  ```

  Start the deployment.
  ```bash
  # make deploy
  # make deploy-calico

  Check deployment using the command below.
  # kubectl get pods -A -o wide
  ```

### Simple Pod-to-Pod Ping Test
  To run a simple ping test from one pod to another, create two test pods. Note
  that, the yaml file in the package is to create a single test pod and so, copy
  and modify it to create pod with different name. For example, copy it as
  test-pod2.yaml and change the metadata name and container name to be test-pod2.
  The .yaml file for test-pod2 should look as below.
  ```bash
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
  Now, create both the test pods
  ```bash
  # kubectl create -f example/test_pod.yaml
  # kubectl create -f example/test_pod2.yaml
  ```
    
  Check that the two test pods are ready and running.
  ```bash
  # kubectl get pods -o wide
  NAME        READY   STATUS    RESTARTS   AGE    IP               NODE    NOMINATED NODE   READINESS GATES
  test-pod    1/1     Running   0          10m    10.244.0.6       ins21   <none>           <none>
  test-pod2   1/1     Running   0          9m33s  10.244.0.7       ins21   <none>           <none>
  ```
    
  Get the IP address assigned to one of the pods using ifconfig. Then, ping that
  address from the other pod.
  ```bash
  # kubectl exec test-pod2 -- ifconfig eth0
  # kubectl exec test-pod -- ping 10.244.0.6
  PING 10.244.0.6 (10.244.0.6): 56 data bytes
  64 bytes from 10.244.0.6: seq=0 ttl=64 time=0.112 ms
  64 bytes from 10.244.0.6: seq=1 ttl=64 time=0.098 ms
  64 bytes from 10.244.0.6: seq=2 ttl=64 time=0.102 ms
  64 bytes from 10.244.0.6: seq=3 ttl=64 time=0.112 ms
  ...
  ```

  To delete above created test pods
  ```bash
  # kubectl delete pod test-pod test-pod2
  ```

### Service deployment Test
  To test simple service deployment, user can use iperf based server available
  in https://github.com/Pharb/kubernetes-iperf3.git repository. Clone this
  repository and deploy the service as below:
  ```bash
  # git clone https://github.com/Pharb/kubernetes-iperf3.git
  # cd kubernetes-iperf3
  # ./steps/setup.sh
  # kubectl get svc -A -o wide
  NAME            TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)    AGE     SELECTOR
  iperf3-server   ClusterIP   10.111.123.3   <none>        5201/TCP   6m56s   app=iperf3-server
  kubernetes      ClusterIP   10.96.0.1      <none>        443/TCP    15m     <none>
 
  # kubectl get ep -A -o wide
  NAMESPACE     NAME            ENDPOINTS                                               AGE
  default       iperf3-server   10.244.0.5:5201,10.244.0.6:5201                         5h22m
  default       kubernetes      10.233.134.119:6443                                     5h35m
  kube-system   kube-dns        10.244.0.3:53,10.244.0.4:53,10.244.0.3:53 + 3 more...   5h35m

  # kubectl get pods -A -o wide
  NAME                                        READY   STATUS    RESTARTS   AGE   IP           NODE    NOMINATED NODE   READINESS GATES
  iperf3-clients-8gkv7                        1/1     Running   0          18m   10.244.0.9   ins21   <none>           <none>
  iperf3-server-deployment-59bf4754f9-4hp4c   1/1     Running   0          18m   10.244.0.8   ins21   <none>           <none>
  ...
  ```
  To test service traffic, iperf3 client can be started as below: 
  ```bash
  # cd kubernetes-iperf3
  # ./steps/run.sh

  The iperf3 client can also be executed manually inside the iperf client pod
  # kubectl exec --stdin --tty <iperf3-clients-xxx> -- /bin/bash
  # iperf3 -c iperf3-server
  Connecting to host iperf3-server, port 5201
  [  5] local 10.244.0.7 port 37728 connected to 10.96.186.247 port 5201
  [ ID] Interval           Transfer     Bitrate         Retr  Cwnd
  [  5]   0.00-1.00   sec   107 KBytes   880 Kbits/sec    2   1.41 KBytes
  [  5]   1.00-2.00   sec  0.00 Bytes  0.00 bits/sec    1   1.41 KBytes
  ```
  To clean up above created services
  ```bash
  # ./steps/cleanup.sh
  ```

## Cleanup All  
  Reset kubernetes which would stop and remove all pods. Then, remove all k8s
  runtime configurations and other files.
  ```bash
  Delete all started pods, service deployments and daemonsets
  # kubectl delete pod < >
  # kubectl delete deployment < >
  # make undeploy
  # make undeploy-calico
  # kubeadm reset -f
  # rm -rf /etc/cni /etc/kubernetes
  # rm -rf /var/lib/etcd /var/lib/kubelet /var/lib/cni
  # rm -rf /var/run/kubernetes
  # rm -rf $HOME/.kube
  # docker container stop registry && docker container rm -v registry
  Stop the system services
  # systemctl stop containerd
  ```

  Stop the ARP proxy and infrap4d processes running. This will also remove all
  the TAP interfaces that were configured earlier.
  ```bash
  # pkill arp_proxy
  # pkill infrap4d
  ```
