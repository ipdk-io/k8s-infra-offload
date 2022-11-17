# Kubernetes Infra Offload Usage Guide
- [Kubernetes Infra Offload Usage Guide](#kubernetes-infra-offload-usage-guide)
  - [General requirements](#general-requirements)
  - [Kubernetes installation](#kubernetes-installation)
    - [Pre-requisites](#pre-requisites)
    - [Kernel modules and kernel settings](#kernel-modules-and-kernel-settings)
    - [Install, configure and run Docker](#install-configure-and-run-docker)
    - [Install, configure and run containerd](#install-configure-and-run-containerd)
    - [Install kubernetes components](#install-kubernetes-components)
  - [IPDK OVS Install](#ipdk-ovs-install)
  - [Setup P4-K8s](#setup-p4-k8s)
  - [P4-K8s Deployment](#p4-k8s-deployment)
  - [Simple Pod-to-Pod Ping Test](#simple-pod-to-pod-ping-test)
  - [Cleanup All](#cleanup-all)

## General requirements
- For Infra Agent and Infra Manager to work, Kernel 5.4 or greater is required.
- The recommended OS to be used is Fedora 33
- The recommended Kubernetes version to be used is 1.25.0
- TAP interfaces should be created and available on the host system before Infra Agent is deployed. The default prefix for TAP interfaces names is "P4TAP_".
- The number of TAP interfaces created must be a power of 2. For example, it can be 2, 4, 8, 16, and so on.
- The P4 data plane program (k8s_dp.p4) and the configuration file (k8s_dp.conf), must not be modified as the k8s control plane software is tightly coupled with the pipeline. The P4 compiler generated artifacts are available in the container and must be used as is.
- The firewall, if enabled in host OS, should either be disabled or configured to allow required traffic to flow through.

## Kubernetes installation
If Kubernetes and other required components are already installed on the machine, then proceed to [IPDK OVS Install and Run](#ipdk-ovs-install-and-run)

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
  
  Enable containerd services, configure default settings and proxies and start the containerd services.
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
  Setup Kubernetes repo manager
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
  # sudo dnf install -y kubelet kubeadm kubectl containernetworking-plugins cri-tools --disableexcludes=kubernetes
  # dnf list installed | grep kube
  cri-tools.x86_64                                   1.24.2-0                            @kubernetes
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
  
## IPDK OVS Install
  This kubernetes depends upon the IPDK P4-OVS to be running in the background. Once P4-OVS is running, kubernetes can load its P4 pipeline and offload various functionalities on it i.e. on P4 data plane. Note that, IPDK P4-OVS needs to installed and run on the host natively. To install P4-OVS and P4-SDE (components as per IPDK 22.07 release) individually, follow the instructions listed below. Note that, P4C is not required as this software includes P4C generated artifacts.
   
  ### P4-SDE
  To install P4-SDE, follow instructions at https://github.com/p4lang/p4-dpdk-target. Make sure to checkout using tag v22.07 (for 22.07 release) and build for TDI. User can also refer to the script https://github.com/ipdk-io/ipdk/blob/main/build/networking/scripts/build_p4sde.sh. The main steps can be summerized as:
  ```bash
  git clone https://github.com/p4lang/p4-dpdk-target
  cd p4-dpdk-target
  git checkout v22.07
  git submodule update --init --recursive
  mkdir ./install
  pushd ./tools/setup
  source p4sde_env_setup.sh <path to p4-dpdk-target>
  popd
  ./autogen.sh
  ./configure --prefix=$SDE_INSTALL --with-generic-flags=yes
  make -j
  make install
  ```
  
  ### P4-OVS
  To install P4-OVS, follow instructions as per the script https://github.com/ipdk-io/ipdk/blob/main/build/networking/scripts/get_p4ovs_repo.sh to download the code. Note that, the P4-OVS code is checked out using tag v22.07 (for 22.07 release). In addition, set the OVS_INSTALL env variable to point to this P4-OVS base directory. The main steps can be summarized as:
  ```bash
  git clone https://github.com/ipdk-io/ovs.git -b ovs-with-p4 P4-OVS
  cd P4-OVS
  git checkout v22.07
  git submodule update --init --recursive
  ./install_dep_packages.sh $PWD
  source p4ovs_env_setup.sh $SDE_INSTALL
  ./build-p4ovs.sh $SDE_INSTALL
  export OVS_INSTALL=$PWD
  ```

## Setup P4-K8S
  Install Go package (go version go1.18.6 linux/amd64), following instructions at https://go.dev/doc/install
 
  Pull P4-K8s and other software
  ```bash
  git clone https://github.com/ipdk-io/k8s-infra-offload.git p4-k8s
  cd p4-k8s
  go get -u google.golang.org/protobuf
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
  golang                                 1.18          f81bafb819d5   6 days ago      965MB
  ...
  ```
  
  Pull images for use by Kubernetes CRI
  ```bash
  # crictl pull localhost:5000/inframanager:latest
  # crictl pull localhost:5000/infraagent:latest
  ```
 
## P4-K8s Deployment
  Run create_interfaces.sh script which, in addition to creating specified number of TAP interfaces, sets up the huge pages and starts P4-OVS.
  ```bash
  # ./p4-k8s/scripts/create_interfaces.sh <4/8/16/...> [OVS_DEP_INSTALL_PATH]
  ```
    
  After running the above script, verify that P4-OVS is running in the background.
  ```bash
  # ps -ef | grep ovs
  root       25050       1  0 07:15 ?        00:00:00 ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock --remote=db:Open_vSwitch,Open_vSwitch,manager_options --pidfile --detach
  root       25054       1 99 07:15 ?        00:09:03 ovs-vswitchd --pidfile --detach --no-chdir --mlockall --log-file=/tmp/logs/ovs-vswitchd.log
  ```

  Rename first TAP interface and run ARP-Proxy on it.
  ```bash
  ip link set P4TAP_0 name TAP0
  ip link set TAP0 up
  ip addr add 169.254.1.1/32 dev TAP0
  ARP_PROXY_IF=TAP0 ./bin/arp_proxy &
  ```

  Start the containerd services
  ```bash
  # systemctl start containerd.service
  ```
    
  Initialize and start the core k8s components as below
  ```bash
  # kubeadm init --pod-network-cidr=<pod-cidr>
  ```
    
  Once K8s control plane initialization is complete successfully, then (as non-root user)
  ```bash
  # mkdir -p $HOME/.kube
  # sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
  # sudo chown $(id -u):$(id -g) $HOME/.kube/config
  ```
  Or (as root user)
  ```bash
  # export KUBECONFIG=/etc/kubernetes/admin.conf
  ```
    
  Start the deployments
  ```bash
  # make deploy
  # make deploy-calico
  ```
  Note that, for single node deployment, the node must be untainted to allow worker pods to share the node with control plane. This can be done as below.
  ```bash
  # kubectl taint node <node-name> node-role.kubernetes.io/control-plane-
  # kubectl taint node <node-name> node-role.kubernetes.io/master-
  ```

### Simple Pod-to-Pod Ping Test
  To run a simple ping test from one pod to another, create two test pods as below. Note that, before creating the second test pod, edit the test_pod.yaml file to configure a different name (test-pod2) for the second pod.
  ```bash
  # kubectl create -f example/test_pod.yaml
  ```
    
  Check that the two test pods are ready and running.
  ```bash
  # kubectl get pods
  NAME        READY   STATUS    RESTARTS   AGE
  test-pod    1/1     Running   0          10m
  test-pod2   1/1     Running   0          9m33s
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

## Cleanup All  
  Reset kubernetes which would stop and remove all pods. Then, remove all k8s runtime configurations and other files
  ```bash
  make undeploy
  make undeploy-calico
  kubeadm reset -f
  rm -rf /etc/cni /etc/kubernetes
  rm -rf /var/lib/etcd /var/lib/kubelet /var/lib/cni /var/lib/dockershim
  rm -rf /var/run/kubernetes
  rm -rf $HOME/.kube
  ```
    
  Check if there are pods that are still running. If so, stop and remove them
  ```bash
  crictl ps -a
  crictl pods ls -a
  crictl stopp <pod_id>
  crictl rmp <pod_id>
  ```
    
  Stop the system services
  ```bash
  systemctl stop kubelet
  systemctl stop containerd
  ```

  Stop the ARP proxy and OVS processes running in the background. This will also remove all the TAP interfaces that were configured earlier.
  ```bash
  pkill arp_proxy
  pkill ovsdb-server
  pkill ovs-vswitchd
  ```
