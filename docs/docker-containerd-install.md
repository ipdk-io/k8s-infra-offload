# Kubernetes, Docker, and containerd Installation
 - [Prerequisites](#prerequisites)
 - [Set Up Kernel Modules and Kernel Settings](#set-up-kernel-modules-and-kernel-settings)
 - [Install, Configure, and Run Docker](#install-configure-and-run-docker)
 - [Install, Configure and Run Containerd](#install-configure-and-run-containerd)
 - [Install Kubernetes Components](#install-kubernetes-components)

## Prerequisites

Kubernetes is known to not work well with Linux swapping; as a result, swapping
should be turned off.

Before installing Kubernetes, do the following:

1. Disable swapping on all devices:
   ```bash
   swapoff -a
   ```

2. If swapoff doesn't completely turn off the swapping after
   a reboot. Remove the following package:
   ```bash
   dnf remove zram-generator-defaults
   ```

3. Check if swapping is off:
   ```bash
   swapon --show
   ```

4. Verify that no zram device is listed:
   ```bash
   lsblk
   ```

5. Remove any swap-specific entries from `/etc/fstab`.


## Set Up Kernel Modules and Kernel Settings
1. Load the following kernel modules and add them to `modules-load` so they
   get automatically loaded during the reboot:
   ```bash
   modprobe overlay
   modprobe br_netfilter

   cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
   br_netfilter
   EOF
   ```

2. Enable IPvX forwarding:
   ```bash
   sudo tee /etc/sysctl.d/kubernetes.conf<<EOF
   net.bridge.bridge-nf-call-ip6tables = 1
   net.bridge.bridge-nf-call-iptables = 1
   net.ipv4.ip_forward = 1
   EOF
   sysctl -p
   ```

3. Set `SELinux` in permissive mode and verify:
   ```bash
   sudo sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config
   getenforce
   ```

## Install, Configure, and Run Docker*

1. Install Docker*, configure associated settings, and start it. Docker is
   required if CRI is containerd. Please follow the overview and install
   sections in the link[Docker Install](https://docs.docker.com/engine/)

2. Create or edit `/etc/systemd/system/docker.service.d/http-proxy.conf` with
   proxies, if your setup is behind a proxy. It should have contents like the
   following:

   ```text
   [Service]
   Environment="HTTPS_PROXY=<proxy-url>"
   Environment="HTTP_PROXY=<proxy-url>"
   Environment="NO_PROXY=localhost,127.0.0.1,::1"
   ```

3. Steps 3-7 may be not be required if already configured.
   These are mentioned for added clarity. Set the storage driver as overlay2
   and use cgroupdriver:

   ```bash
   mkdir -p /etc/docker
   ```

4. Create `/edit /etc/docker/daemon.json` to have contents as shown below.
   The `registry-mirrors` setting in this file is needed when a user is limited
   by Docker pull cap limits on free user accounts.

   ```json
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

5. Create `~/.docker/config.json` with the following contents:

   ```json
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

6. Start the Docker daemon:

   ```bash
   systemctl start docker
   ```

7. Create a local registry and verify that it is running. Note that this
   requires Docker login credentials to set up an authentication token on
   a local node.

   ```bash
   docker login
   ```
   ```text
   Authenticating with existing credentials...
   WARNING! Your password will be stored unencrypted in /root/.docker/config.json.
   Configure a credential helper to remove this warning. See
   https://docs.docker.com/engine/reference/commandline/login/#credentials-store

   Login Succeeded
   ```
   ```bash
   docker run -d -p 5000:5000 --restart=always --name registry registry:2
   docker ps
   ```
   ```text
   CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                    NAMES
    99d9b2ede2ea        registry:2          "/entrypoint.sh /etc…"   36 seconds ago      Up 35 seconds       0.0.0.0:5000->5000/tcp   registry
   ```

## Install, Configure, and Run Containerd

1. Create `/etc/crictl.yaml` with following contents:

   ```bash
   cat /etc/crictl.yaml
   ```
   ```text
   runtime-endpoint: unix:///run/containerd/containerd.sock
   image-endpoint: unix:///run/containerd/containerd.sock
   timeout: 10
   debug: true
   ```

2. Enable containerd services and configure default settings and proxies:

   ```bash
   systemctl enable containerd.service
   mkdir -p /etc/containerd
   containerd config default | tee /etc/containerd/config.toml
   ```

3. In the `/etc/containerd/config.toml` file, under
   `[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]`,
   set `SystemCgroup` to `true`. The file would look as below:

   ```toml
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

4. Create the following directory:
   ```bash
   mkdir -p /usr/lib/systemd/system/containerd.service.d
   ```

5. Create a proxy file as shown below. In this example, the pod network is
   10.244.0.0/16, service network is 10.96.0.0/16, and API server, local API
   endpoint, control plane endpoint is 192.168.110.5.

   ```bash
   cat /usr/lib/systemd/system/containerd.service.d/proxy.conf
   ```
   ```text
   [Service]
   Environment="HTTP_PROXY=<proxy-url>"
   Environment="HTTPS_PROXY=<proxy-url>"
   Environment="NO_PROXY=localhost,127.0.0.1,::1,10.244.0.0/16,10.96.0.0/16,192.168.0.0/16,<node-ip>"
   ```

6. Configure the following environment variables for proxy settings for
   containerd. Include the host IP address, pod subnet, and service subnet in
   the `no_proxy` setting.

   ```bash
   export no_proxy=127.0.0.1,localhost,192.168.0.0/16,<pod-cidr>,<service-cidr>,<host-ip>
   export https_proxy=<proxy-url>
   export http_proxy=<proxy-url>
   ```

7. Start the containerd services:
   ```bash
   systemctl start containerd.service
   ```

8. Check the status. It should show it running as below:

   ```bash
   systemctl status containerd.service
   ```
   ```text
     containerd.service - containerd container runtime
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

## Install Kubernetes Components

1. Set up the Kubernetes repo manager. Please follow the
   link[Install K8S](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/#install-using-native-package-management)
   Below is just a sample example to install version 1.25.

   ```bash
   cat <<EOF | sudo tee /etc/yum.repos.d/kubernetes.repo
   [kubernetes]
   name=Kubernetes
   baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-\$basearch
   enabled=1
   gpgcheck=1
   repo_gpgcheck=1
   gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
   EOF
   ```
   ```bash
   dnf install -y kubelet-1.25.1 kubeadm-1.25.1 kubectl-1.25.1 containernetworking-plugins cri-tools-1.25.0 --disableexcludes=kubernetes
   dnf list installed | grep kube
   ```
   ```bash
   cri-tools.x86_64 1.25.0-0 @kubernetes
   kubeadm.x86_64 1.25.8-0 @kubernetes
   kubectl.x86_64 1.25.8-0 @kubernetes
   kubelet.x86_64 1.25.8-0 @kubernetes
   ```

2. Pull Kubernetes images and verify the downloaded images:

   ```bash
   kubeadm config images pull
   crictl images ls
   ```
   ```text
   IMAGE                                             TAG                 IMAGE ID            SIZE
   registry.k8s.io/coredns/coredns                   v1.9.3              5185b96f0becf       14.8MB
   registry.k8s.io/etcd                              3.5.6-0             fce326961ae2d       103MB
   registry.k8s.io/kube-apiserver                    v1.25.16            1f1beb7697603       35.1MB
   registry.k8s.io/kube-controller-manager           v1.25.16            008d3c66b06c6       31.9MB
   registry.k8s.io/kube-proxy                        v1.25.16            8bcccb40c8da7       20.5MB
   registry.k8s.io/kube-scheduler                    v1.25.16            37380a8f21afe       16.3MB
   registry.k8s.io/pause                             3.8                 4873874c08efc       311kB
   ```

   ```bash
   kubeadm config images list
   ```
   ```text
   registry.k8s.io/kube-apiserver:v1.25.0
   registry.k8s.io/kube-controller-manager:v1.25.0
   registry.k8s.io/kube-scheduler:v1.25.0
   registry.k8s.io/kube-proxy:v1.25.0
   registry.k8s.io/pause:3.8
   registry.k8s.io/etcd:3.5.4-0
   registry.k8s.io/coredns/coredns:v1.9.3
   ```

3. Enable the kubelet services:

   ```bash
   systemctl enable kubelet.service
   ```
