# Getting started

## Installing Kubernetes

Kubernetes Infra Offload requires Kubernetes, Docker*, and containerd* to be
installed. See [Kubernetes*, Docker*, and containerd* Installation](guides/k8s-docker-containerd-install.md)
for instructions. If these components are already installed on the machine,
proceed to next step.

## Set Up Target and Dependencies

Kubernetes Infra Offload supports two targets, viz. P4-DPDK and Intel IPU ES2K.
The Intel IPU ES2K target requires proper hardware setup and initialization.
On both these platforms, Kubernetes Infra Offload software depends upon the
daemon InfraP4d of the IPDK networking recipe to be runnning in the background.
Once InfraP4d is running, Kubernetes can load its P4 pipeline and offload
various functionalities on it (i.e. on the P4 data plane).

On the Intel IPU, k8s-infra-offload can run in 2 different modes details of which
are present later in the doc.
   a. The host mode, where every component runs on the host and offload happens
   from host.

   b. The split mode, where the inframanager runs on IPU ARM cores for rule offloads
   while the infraagent runs on host.

The instructions to setup the target and install infrap4d and its dependencies,
are different for the two targets.
See [Target Setup for P4-DPDK](guides/setup/target-setup-dpdk.md) for instructions on
installation of SDE and InfraP4d on P4-DPDK target.
See [Target Setup for Intel IPU ES2K](guides/setup/target-setup-es2k.md) for
instructions on hardware setup and installation of SDE and InfraP4d on Intel
IPU ES2K target.

## Set Up P4 Kubernetes

1. Install Go package (version 1.20.8)
   following instruction at https://go.dev/doc/install


2. Pull P4-K8s software from the GitHub repository:

   ```bash
   git clone https://github.com/ipdk-io/k8s-infra-offload.git p4-k8s
   cd p4-k8s
   git checkout ipdk_v23.07
   ```

3. Build K8s P4 artifacts

   Notes:
   i) For ES2K target, get the K8s P4 artifacts from ES2K release package and
      copy them into p4-k8s/k8s_dp/es2k/. This must be done before running
      below make commands. Ensure the following artifacts are present.
      ```bash
      cd k8s_dp/es2k/
      ls
      ```
      ```
      bf-rt.json  context.json  k8s_dp.p4  k8s_dp.pb.bin  p4Info.txt
      ```
      For generating the artifacts, use the
      [compiling-p4-programs](guides/es2k/compiling-p4-programs.md) guide.

   ii) By default, Makefile is configured to build for ES2K target. To build
      for P4-DPDK target, use "tagname=dpdk" argument for both make targets
      below.

   Build Kubernetes binaries:

   ```bash
   make build
   ```

4. Generate the certificates required for the mTLS connection between infraagent,
   inframanager, and infrap4d.
   Note that for split mode, users needs to add the IP of the ACC endpoint in the
   `openssl.cnf` file under `scripts/tls/`.

   ```bash
   make gen-certs
   ```
   Note that the above script generates the default keys and certificates and
   uses cipher suites as specified in the `deploy/inframanager-config.yaml` file.
   Refer to section [inframanager config file update](#inframanager-config-file-update)
   for any custom cipher suite, key, certificate change.

   Note that the above script generates the default keys and certificates and
   uses cipher suites as specified in the `deploy/inframanager-config.yaml` file.

5. Run `make install` to install all config and other artifacts to relevant
   directories

6. Run the `setup_infra.sh` script, which, in addition to creating the
   specified number of virtual interfaces (TAP type on DPDK target and IDPF
   Sub-Function type on ES2K), sets up the HugePages and starts infrap4d.
   The script supports setup in two different modes.

   a. "host" : Host mode

   b. "split" : In this mode, the communication channel between
   IPU ACC-ARM complex and host must pre-exist through provisioning on IPU.
   The communication channel on ARM-ACC side would require user to configure an IP
   address and later use it as an argument in setup_infra.sh script. The below example
   assumes remote ACC endpoint with an IP address of `10.10.0.2`.
   The grpc communication between the two infra components over the comms channel
   are encrypted. User would need to add IP address based on the configuration to
   `openssl.cnf` under scripts TLS directory and generate certificates as mentioned
   in the previous gen-certs step. Make sure to also update inframanager config file
   for this IP address for manager to bind to
   and infraagent config file for infraagent to connect to the remote manager.

   ```bash
   ./setup_infra.sh -i <8|16|..> -m <split|host> -r <10.10.0.2>
   ```

   Where, the options:
     -i  Num interfaces to configure for deployment
     -m  Mode host or split, depending on where Inframanager is configured to run
     -r  IP address configured by the user on the ACC-ARM complex for
       connectivity to the Host. This is provisioned using Node Policy - comms
       channel ([5,0],[4,0]),([4,2],[0,3]). This is needed for runnning in split mode.
       Script will assign an IP addresss from the same subnet on the Host side for connectivity.


   Please set following env variables for host deployment:
     SDE_INSTALL - Default SDE install directory
     P4CP_INSTALL - Default p4cp install directory
     DEPEND_INSTALL - Default target dependencies directory


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

7. Run ARP-Proxy script, which creates a new namespace and assigns an interface
   from the pool of interfaces created in previous step.
   On ES2K target, user needs to explicitly configure the interface to be
   assigned using IFACE environment variable.
   ```bash
   export IFACE=ens801f0d4
   ```
   Make changes to the [infragent config file](#infragent-config-file-update)
   for interface and interface type.

   For DPDK target, change the interfaceType in inframanager-config.yaml file to "tap".

   The script finally runs the arp-proxy on that assigned interface, within the
   isolated namespace.
   ```bash
   ./scripts/arp_proxy.sh
   ```

   Please note, any changes in config file need to be made
   as per section [inframanager config file update](#inframanager-config-file-update)
   before building the images.


8. Make the docker images. This step builds the Kubernetes container images:
   ```bash
   make docker-build
   ```

9. Push InfraManager and InfraAgent images into docker private repo either
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

10. Pull images for use by Kubernetes Container Runtime Interface (CRI):
    ```bash
    crictl pull localhost:5000/inframanager:latest
    crictl pull localhost:5000/infraagent:latest
    ```

### infraagent config file update

The config file `deploy/es2k/infraagent-config.yaml` is used to inform the
infraagent which interface and interfacetype to use.

The interfaceType should be `cdq` for ES2K and the the interface name is the
base name for PF for PCI device ID 1452

```text
interfaceType : cdq
interface: ens801f0
mtls: true
insecure: false
```
For split mode, also configure the follwing.

```text
managerAddr : <IP address of comms channel on ACC>
managerPort : 50002
```

### inframanager config file update

The config file `deploy/inframanager-config.yaml` is used to define the parameters
which the inframanager will use for the connection establishment with infrap4d
and for the interfaces created.

All fields have a default value in the file. Please verify if the values
correspond to the desired values especially arp-mac.

InfraManager section:
addr: The local address to which the inframanager will bind to as the
listening socket for infraagent. In `host` mode, it can be the localhost.
```bash
addr: 127.0.0.1:50002
```
For `split` mode, it needs to be the ACC comms channel IP. Example
```bash
addr:10.10.0.2:50002
```
arp-mac: The arp-mac needs to be configured. This should be the
MAC of the interface the user wants to configure as the ARP-proxy gateway.
This is the address of the interface which is given to the arp-proxy
namespace using the `scrips/arp_proxy.sh` script mentioned in
the [Set Up P4 Kubernetes](#set-up-p4-kubernetes) for ARP proxy gateway.


If user doesn't wish to use these default keys, certificates, and cipher suites, then
modify the `scripts/mev/tls/gen_certs.sh` script accordingly before running
`make gen-certs` and modify the `deploy/inframanager-config.yaml` file with preferred
cipher suites. These changes need to be done prior to the creation of container
images in step 8 of the [Set Up P4 Kubernetes](#set-up-p4-kubernetes) section.


## Deploy P4 Kubernetes

1. Initialize and start the core Kubernetes components:
   ```bash
   kubeadm init --pod-network-cidr=<pod-cidr> --service-cidr=<service-cidr>
   ```

2. Once the Kubernetes control plane initialization has completed successfully,
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

3. Install and setup Calico plugin
   ```bash
    cd /usr/local/bin
    curl -L https://github.com/projectcalico/calico/releases/download/v3.24.1/calicoctl-linux-amd64 -o kubectl-calico
    chmod +x kubectl-calico
   ```

4. Remove taints from the node.
   For single node deployment, the node must be untainted to allow worker pods
   to share the node with control plane. The taint to remove is "control-plane"
   or "master" or both. These taints can be removed as shown:
   ```bash
   kubectl taint node <node-name> node-role.kubernetes.io/control-plane-
   kubectl taint node <node-name> node-role.kubernetes.io/master-
   ```

5. Create Kubernetes secrets from the generated certificates. The infraagent and
   inframanager read the certificates from the secrets.
   ```bash
   make tls-secrets
   ```

6. Start the deployments:
   ```bash
   make deploy
   make deploy-calico
   ```

   Check deployment using the following:
   ```bash
   kubectl get pods -A -o wide
   ```

## Pod-to-Pod Ping

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
   kubectl exec test-pod -- ifconfig eth0
   kubectl exec test-pod2 -- ping 10.244.0.6
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

## Service Deployment

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
   ./scripts/cleanup.sh
   ```

## Setup Scripts

- The script `./script/setup_infra.sh` sets up HugePages required by
  DPDK and launches infrap4d (P4 OVS/SDE).

- The script `arp_proxy.sh` creates a separate namespace for the ARP proxy,
  assigns an interface to it, and then launches the ARP proxy within the
  isolated namespace.

## Troubleshooting

### Debugging

- The Kubernetes Infrastructure Offload software provides logging capabilities.
  Check logs emitted to stdout
  and stderr using `"kubectl logs <pod> -n <namespace>"`.

### FAQs

1. "failed to get a CDQ interface for pod: no free resources left" error is seen on infraagent and remaining pods do not come up

Reason : interface mapping available on host needs to be refreshed
Solution : Run [cleanup](#Clean-Up) before `make deploy`

2. CDQ interfaces not coming up.

Reason : IDPF driver failed to load
Solution : Verify using `dmesg` command that it is the case. Then perform a `modprobe idpf`

3. Failed to connect to inframanager seen on host when in `split` mode.

Reason: Firewalld blocking it
Solution: Disable firewall service on ACC. Might need to disable network-manager
  service on both host and ACC.

4. Certs error while processing seen on inframanager when in `split` mode.

Reason: Time might be out of sync.
Solution: Ensure that the time is synced using the correct protocol.

5. Host/IMC crash and reboot.

Reason: IDPF interfaces still exist on host and IMC is rebooted or host is
rebooted.
Solution: Ensure to run ./scripts/cleanup.sh prior to rebooting IMC or host.

## Clean Up
   Reset kubernetes which would stop and remove all pods. Then, remove all k8s
   runtime configurations and other files. Finally, stop container services.
   Short way to cleanup everything
   ```bash
   ./scripts/cleanup.sh
   ```

   If only delete all started pods, service deployments, namespace and
   daemonsets
   ```bash
   kubectl delete pod < >
   kubectl delete deployment < >
   sudo ip -all netns delete
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
## Versions and Third-parties

Versions of Kubernetes, linux distros, docker and other third-party libraries tested with (calico, felix)

### OS

* Linux
  * Fedora 37
  * Rocky Linux 9.2
  * RHEL 9.2

### golang

go1.21.4

### docker
```bash
docker version
Client: Docker Engine - Community
 Version:           20.10.12
 API version:       1.41
```

### containerd

Tested on 1.6.x

```bash
ctr version
```
### kubernetes

Versions tested and supported with

1.25.x

```bash
$ dnf list installed | grep kube
cri-tools.x86_64                                 1.25.2-0
kubeadm.x86_64                                   1.25.4-0
kubectl.x86_64                                   1.25.4-0
kubelet.x86_64                                   1.25.4-0
```

### Calico

v3.24.1
