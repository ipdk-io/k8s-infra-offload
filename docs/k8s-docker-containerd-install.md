# Kubernetes, Docker, Containerd Installation
 - [Pre-requisites](#pre-requisites)
 - [Kernel modules and kernel settings](#kernel-modules-and-kernel-settings)
 - [Install, configure and run Docker](#install-configure-and-run-docker)
 - [Install, configure and run containerd](#install-configure-and-run-containerd)
 - [Install kubernetes components](#install-kubernetes-components)

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
