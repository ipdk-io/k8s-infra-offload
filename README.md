# Kubernetes Infra Offload Usage Guide
- [Kubernetes Infra Offload Usage Guide](#kubernetes-infra-offload-usage-guide)
  - [General requirements](#general-requirements)
  - [Kubernetes installation](#kubernetes-installation)
    - [Pre-requisites](#pre-requisites)
    - [Kernel modules and kernel settings](#kernel-modules-and-kernel-settings)
    - [Install, configure and run Docker](#install-configure-and-run-docker)
    - [Install, configure and run containerd](#install-configure-and-run-containerd)
    - [Install kubernetes components](#install-kubernetes-components)
  - [IPDK Networking recipe install](#ipdk-networking-recipe-install)
  - [Setup P4-K8s](#setup-p4-k8s)
  - [P4-K8s Deployment](#p4-k8s-deployment)
  - [Simple Pod-to-Pod Ping Test](#simple-pod-to-pod-ping-test)
  - [Service deployment Test](#service-deployment-test)
  - [Cleanup All](#cleanup-all)

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
If Kubernetes and other required components are already installed on the machine, then proceed to [IPDK Networking recipe install](#ipdk-networking-recipe-install)

### Pre-requisites
Kubernetes is known to not work well with Linux swap and hence, it should be turned off.

  ```bash
  # swapoff -a
  ```
 
  For Fedora 33, swapoff doesn't completely turnoff the swap after reboot. Remove the below package.
  ```bash
  # dnf remove zram-generator-defaults
  ```

  Check if the swap is off
  ```bash
  # swapon --show
  ```
  
  There should be no zram device 
  ```bash
  # lsblk
  ```

  Also remove any swap specific entries from /etc/fstab.
  
### Kernel modules and kernel settings
  Load below kernel modules and add them to modules-load for autoload during the reboot
  ```bash
  # modprobe overlay
  # modprobe br_netfilter
  
  # cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
  br_netfilter
  EOF
  ```

  Enable IPvX forwarding
  ```bash
  # sudo tee /etc/sysctl.d/kubernetes.conf<<EOF
  net.bridge.bridge-nf-call-ip6tables = 1
  net.bridge.bridge-nf-call-iptables = 1
  net.ipv4.ip_forward = 1
  EOF
  # sysctl -p
  ```
  
  set SELinux in permissive mode and verify
  ```bash
  # sudo sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config
  # getenforce
  ```

### Install, configure and run Docker
  Install docker, configure associated settings and start it. Docker is required when using older versions of kubernetes (< v1.23) as
  dockerd talks to containerd to pull K8s images. Docker is not required if cri runtime is containerd.
  
  ```bash
  # dnf update -y
  # dnf install -y dnf-plugins-core
  # dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
  # dnf install docker-ce docker-ce-cli containerd.io
  ```
  
  Create or edit /etc/systemd/system/docker.service.d/http-proxy.conf with proxies, if your setup is behind a proxy.
  It should have contents as below
  ```bash
  [Service]
  Environment="HTTPS_PROXY=<proxy-url>"
  Environment="HTTP_PROXY=<proxy-url>"
  Environment="NO_PROXY=localhost,127.0.0.1,::1"
  ```
  
  Set storage driver as overlay2 and use cgroupdriver.
  ```bash
  # mkdir -p /etc/docker
  ```
  
  Create /edit /etc/docker/daemon.json to have contents as below. The registry-mirror setting in this file is needed when user is limited by docker pull cap limits on free user accounts.
  ```bash
  {
  "exec-opts": ["native.cgroupdriver=systemd"],
  "log-driver": "json-file",
  "log-opts": {
  "max-size": "50m"
  },
  "data-root": "/mnt/docker-data",
  "storage-driver": "overlay2",
  "registry-mirrors": ["https://mirror.gcr.io"]
  }
  ```
  
  Create ~/.docker/config.json with following contents:
  ```bash
  {
          "proxies": {
                  "default": {
                          "httpProxy": "<proxy-url>",
                          "httpsProxy": "<proxy-url>",
                          "noProxy": "localhost,127.0.0.1"
                  }
          }
  }
  ```
 
  Start the docker daemon
  ```bash
  # systemctl start docker
  ```
  
  Create a local registry and verify that it is running. Note that, this requires docker login credentials to setup authentication token on local node.
  ```bash
  # docker login
  Authenticating with existing credentials...
  WARNING! Your password will be stored unencrypted in /root/.docker/config.json.
  Configure a credential helper to remove this warning. See
  https://docs.docker.com/engine/reference/commandline/login/#credentials-store

  Login Succeeded

  # docker run -d -p 5000:5000 --restart=always --name registry registry:2
  # docker ps
  CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                    NAMES
   99d9b2ede2ea        registry:2          "/entrypoint.sh /etc…"   36 seconds ago      Up 35 seconds       0.0.0.0:5000->5000/tcp   registry
  ```
  
### Install, configure and run containerd
  Create /etc/crictl.yaml with following contents.
  ```bash
  # cat /etc/crictl.yaml
  runtime-endpoint: unix:///run/containerd/containerd.sock
  image-endpoint: unix:///run/containerd/containerd.sock
  timeout: 10
  debug: true
  ```
  
  Enable containerd services and configure default settings and proxies.
  ```bash
  # systemctl enable containerd.service
  # mkdir -p /etc/containerd
  # containerd config default | tee /etc/containerd/config.toml
  ```
  
  In the /etc/containerd/config.toml file, set SystemCgroup to true under
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]. The file would look as below.
  ```bash
  ...
      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes]
        [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
          runtime_type = "io.containerd.runc.v2"
          runtime_engine = ""
          runtime_root = ""
          privileged_without_host_devices = false
          base_runtime_spec = ""
          [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
            SystemdCgroup = true
  ...
  ```

  Create proxy file and configure proxy settings viz. http_proxy, https_proxy and no_proxy for containerd. Include
  host IP address, pod subnet and service subnet to the no_proxy setting.
  ```bash
  mkdir -p /usr/lib/systemd/system/containerd.service.d
  ```
  
  The /usr/lib/systemd/system/containerd.service.d/proxy.conf should look as below. In this example, pod network is 10.244.0.0/16, service network is 10.96.0.0/16 and API server, local API endpoint, control plane endpoint is 192.168.110.5
  ```bash
  # cat /usr/lib/systemd/system/containerd.service.d/proxy.conf
  [Service]
  Environment="HTTP_PROXY=<proxy-url>"
  Environment="HTTPS_PROXY=<proxy-url>"
  Environment="NO_PROXY=localhost,127.0.0.1,::1,10.244.0.0/16,10.96.0.0/16,192.168.0.0/16,<node-ip>"
  ```
  
  Confiugre following environment variables for proxy settings
  ```bash
  export no_proxy=127.0.0.1,localhost,192.168.0.0/16,<pod-cidr>,<service-cidr>,<host-ip>
  export https_proxy=<proxy-url>
  export http_proxy=<proxy-url>
  ```
  
  Start the containerd services
  ```bash
  # systemctl start containerd.service
  ```

  Check the status and it should show it running as below
  ```bash
  # systemctl status containerd.service
    ● containerd.service - containerd container runtime
         Loaded: loaded (/usr/lib/systemd/system/containerd.service; enabled; vendor preset: disabled)
        Drop-In: /usr/lib/systemd/system/containerd.service.d
                 └─proxy.conf
         Active: active (running) since Thu 2022-07-14 13:29:25 IST; 9min ago
           Docs: https://containerd.io
        Process: 100768 ExecStartPre=/sbin/modprobe overlay (code=exited, status=0/SUCCESS)
       Main PID: 100769 (containerd)
          Tasks: 37
         Memory: 19.8M
            CPU: 663ms
         CGroup: /system.slice/containerd.service
                 └─100769 /usr/bin/containerd

    <...> level=info msg="Start subscribing containerd event"
    <...> level=info msg="Start recovering state"
    <...> level=info msg=serving... address=/run/containerd/container>
    <...> level=info msg=serving... address=/run/containerd/container>
    <...> level=info msg="containerd successfully booted in 0.039112s"
    <...> systemd[1]: Started containerd container runtime.
    <...> level=info msg="Start event monitor"
    <...> level=info msg="Start snapshots syncer"
    <...> level=info msg="Start cni network conf syncer"
    <...> level=info msg="Start streaming server"
  ```
  
### Install kubernetes components
  Setup Kubernetes repo manager (use recommended version 1.25)
  ```bash
  # cat <<EOF | sudo tee /etc/yum.repos.d/kubernetes.repo
  [kubernetes]
  name=Kubernetes
  baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-\$basearch
  enabled=1
  gpgcheck=1
  repo_gpgcheck=1
  gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
  EOF
  # dnf install -y kubelet-1.25.1 kubeadm-1.25.1 kubectl-1.25.1 containernetworking-plugins cri-tools-1.25.0 --disableexcludes=kubernetes
  # dnf list installed | grep kube
  cri-tools.x86_64                                   1.25.0-0                            @kubernetes
  kubeadm.x86_64                                     1.25.0-0                            @kubernetes           
  kubectl.x86_64                                     1.25.0-0                            @kubernetes           
  kubelet.x86_64                                     1.25.0-0                            @kubernetes
  ```
  
  Pull kubernetes images and verify the downloaded images
  ```bash
  # kubeadm config images pull
  
  # crictl images ls
  IMAGE                                TAG                 IMAGE ID            SIZE
  docker.io/calico/cni                      v3.24.1             67fd9ab484510       87.4MB
  docker.io/calico/kube-controllers         v3.24.1             f9c3c1813269c       31.1MB
  docker.io/calico/node                     v3.24.1             75392e3500e36       80.2MB
  localhost:5000/infraagent                 latest              0c33a598fd923       32.2MB
  localhost:5000/inframanager               latest              56f21c0cc91a2       11MB
  quay.io/tigera/operator                   v1.28.1             52468087127eb       18.8MB
  registry.k8s.io/coredns/coredns           v1.9.3              5185b96f0becf       14.8MB
  registry.k8s.io/etcd                      3.5.4-0             a8a176a5d5d69       102MB
  registry.k8s.io/kube-apiserver            v1.25.0             4d2edfd10d3e3       34.2MB
  registry.k8s.io/kube-controller-manager   v1.25.0             1a54c86c03a67       31.3MB
  registry.k8s.io/kube-proxy                v1.25.0             58a9a0c6d96f2       20.3MB
  registry.k8s.io/kube-scheduler            v1.25.0             bef2cf3115095       15.8MB
  registry.k8s.io/pause                     3.8                 4873874c08efc       311kB
 
  # kubeadm config images list
  registry.k8s.io/kube-apiserver:v1.25.0
  registry.k8s.io/kube-controller-manager:v1.25.0
  registry.k8s.io/kube-scheduler:v1.25.0
  registry.k8s.io/kube-proxy:v1.25.0
  registry.k8s.io/pause:3.8
  registry.k8s.io/etcd:3.5.4-0
  registry.k8s.io/coredns/coredns:v1.9.3
  ```
  
  Enable the kubelet services
  ```bash
  # systemctl enable kubelet.service
  ```
  
### IPDK Networking recipe install
  Kubernetes deployment depends upon the daemon infrap4d of IPDK networking recipe to be running in the background. Once infrap4d is running, kubernetes can load its P4 pipeline and offload various functionalities on it i.e. on P4 data plane. Note that, IPDK infrap4d needs to installed and run on the host natively. To install infrap4d and P4-SDE (components as per IPDK 23.01 release) individually, follow the instructions listed below. Note that, P4C is not required as this software includes P4C generated artifacts.
   
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
  Install Go package (go version go1.19.4 linux/amd64), following instructions at https://go.dev/doc/install
 
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
  
  Push InfraManager and InfraAgent images into docker private repo either manually or through make command.
  
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
  Run create_interfaces.sh script which, in addition to creating specified number of TAP interfaces, sets up the huge pages and starts infrap4d.
  Scripts requires following env variables to be set - SDE_INSTALL, IPDK_RECIPE, DEPEND_INSTALL . These env variables are defined in networking-recipe/main/docs/ipdk-dpdk.md

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
    
  Once K8s control plane initialization is complete successfully, then (as non-root user)
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
  Note that, for single node deployment, the node must be untainted to allow worker pods to share the node with control plane. This can be done as below.
  ```bash
  # kubectl taint node <node-name> node-role.kubernetes.io/control-plane-
  ```
  ```bash
  # make deploy
  # make deploy-calico

  Check deployment using the command below.
  # kubectl get pods -A -o wide
  ```

### Simple Pod-to-Pod Ping Test
  To run a simple ping test from one pod to another, create two test pods. Note that, the yaml file in the package is to create a single test pod and so, copy and modify it to create pod with different name. For example, copy it as test-pod2.yaml and change the metadata name and container name to be test-pod2. The .yaml file for test-pod2 should look as below.
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
    
  Get the IP address assigned to one of the pods using ifconfig. Then, ping that address from the other pod.
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
  To test simple service deployment, user can use iperf based server available in https://github.com/Pharb/kubernetes-iperf3.git repository. Clone this repository and deploy the service as below:
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
  Reset kubernetes which would stop and remove all pods. Then, remove all k8s runtime configurations and other files.
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

  Stop the ARP proxy and infrap4d processes running. This will also remove all the TAP interfaces that were configured earlier.
  ```bash
  # pkill arp_proxy
  # pkill infrap4d
  ```
