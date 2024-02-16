# Getting started

## Installing Kubernetes

Kubernetes Infra Offload requires Kubernetes, Docker*, and containerd* to be
installed. See [Kubernetes, Docker, and containerd Installation](docker-containerd-install.md)
for instructions. If these components are already installed on the machine,
proceed to next step.

## Set Up Target and Dependencies

Kubernetes Infra Offload supports two targets, viz. P4-DPDK and Intel IPU E2100.
The Intel IPU E2100 target requires proper hardware setup and initialization.
On both these platforms, Kubernetes Infra Offload software depends upon the
daemon InfraP4d of the IPDK networking recipe to be runnning in the background.
Once InfraP4d is running, Kubernetes can load its P4 pipeline and offload
various functionalities on it (i.e. on the P4 data plane).

The instructions to setup the target and install infrap4d and its dependencies,
are different for the two targets.
See [Target Setup for P4-DPDK](target-setup-dpdk.md) for instructions on
installation of SDE and InfraP4d on P4-DPDK target.
See [Target Setup for Intel IPU E2100](target-setup-es2k.md) for host setup
and compilation of P4-SDE and P4-CP on Intel IPU E2100 target.

## Set Up P4 Kubernetes

On the Intel IPU, k8s-infra-offload can run in two different modes, details of
which are present in all relevant sections where mode based configurations are
needed. The modes are -

a. The split mode, where the inframanager runs on IPU ARM cores for rule offloads
   while the infraagent runs on host.

b. The host mode, where every component runs on the host and offload happens
   from host.

On DPDK, only the host mode is supported.

Following steps cover instructions on setting up P4-K8S in either modes,
once mentioned dependencies are compiled and installed.

1. Install Go package by following instructions at <https://go.dev/doc/install>
   (Pick the right version for golang go compiler corresponding to K8s Recipe
   release version. This information can be found in file
   [release-notes.rst](release-notes.rst). Information on the latest
   supported version is available in "Versions and third-parties" section below.)


2. Pull P4-K8s software from the GitHub repository:

   ```bash
   git clone https://github.com/ipdk-io/k8s-infra-offload.git p4-k8s
   cd p4-k8s
   git checkout ipdk_v24.01
   ```

   For building K8S recipe, follow the steps below.

3. Build K8s P4 artifacts

   Notes:
   i) For E2100 target, get the K8s P4 artifacts and
      copy them into p4-k8s/k8s_dp/es2k/. This must be done before running
      below make commands. Ensure the following artifacts are present.

      ```bash
      cd k8s_dp/es2k/
      ls
      ```
      ```
      tdi.json  context.json  k8s_dp.p4  k8s_dp.pb.bin  p4Info.txt
      ```

      For generating the artifacts for E2100, refer to the
      [compiling-p4-programs](target-setup-es2k.md#compile-k8s-p4) section

   ii) By default, Makefile is configured to build for E2100 target. To build
      for P4-DPDK target, use "tagname=dpdk" argument for both make targets
      below.

      Build Kubernetes binaries:

      ```bash
      make build
      ```

4. Generate the certificates required for the mTLS connection between infraagent,
   inframanager, and infrap4d:

   ```bash
   make gen-certs
   ```

   Note that the above script generates the default keys and certificates and
   uses cipher suites as specified in the `deploy/common-config.yaml` file.
   Refer to section [inframanager config file update](#inframanager-config-file-update)
   for any custom cipher suite, key, certificate change.

   Note that the above script generates the default keys and certificates and
   uses cipher suites as specified in the `deploy/common-config.yaml` file.

   For split mode, the openssl.cnf file under scripts/tls dir would require
   addition of the remote node IP address under `[server_alt_names]` section.
   inframanager in this mode runs on the remote ARM-ACC complex. This is
   required for mTLS between infraagent and inframanager to work.
   Look for sample "10.10.0.2" and replace it with the right IP Address.

5. Run `make install` to install all config and other artifacts to relevant
   directories

6. Run the `setup_infra.sh` script, which in addition to creating the
   specified number of virtual interfaces (TAP type on DPDK target and IDPF
   sub-functions on E2100), sets up the HugePages and starts infrap4d.
   The script supports infrastructure setup in two different modes.

   a. The split mode on E2100, where the inframanager runs on IPU ARM cores(remote end)
   while the infraagent runs on the host. In this mode, the communication channel
   between IPU ACC-ARM complex and host must pre-exist prior to execution of the
   script. This communication channel can be provisioned using node policy file
   on the IPU. The sample cdq node policy file has this communication channel
   pre-configured and channel will be functional if IPU is booted with this file.
   Please configure an IP address with a netmask of 255.255.0.0 on the remote
   ARM-ACC vport of this communication channel. This will be used later as an
   argument in setup_infra.sh script. For user convenience, certificates
   configuration file `openssl.cnf` is pre-configured with an example IP address
   of `10.10.0.2` for the remote end. Incase a different IP address is configured,
   update `scripts/tls/openssl.cnf` and re-execute step 4.

   b. The host mode on both targets, where every component runs on the host(engineering
   preview).

   For CDQ interfaces :
   ```bash
   ./scripts/setup_infra.sh -i <8|16|..> -m <host> [-r <remote IP>]
   ```

   For SRIOV interfaces:
   ```bash
   ./scripts/setup_infra_sriov.sh -i <8|16|..> -m <host>
   ```

   Where, the options:
     -i  Num interfaces to configure for deployment
     -m  Mode host for running inframanager on host
     -r  IP address configured by the user on the ACC-ARM complex for
       connectivity to the Host. This is provisioned using Node Policy - comms
       channel ([5,0],[4,0]),([4,2],[0,3]). This is needed only for runnning
       in split mode.

   Script will auto assign an IP addresss from the same subnet on the Host side
   vport for connectivity. The communication channel vport interface name is
   autodetected by the script for the above mentioned comms channel configuration
   in the cdq node policy.

   Please also set following env variables for the deployment. These paths are
   needed to set the dependencies correctly.
     SDE_INSTALL - Default p4sde install directory
     P4CP_INSTALL - Default p4-cp install directory
     DEPEND_INSTALL - Default target dependencies directory
     K8S_RECIPE - Path to k8s recipe on the host

   After running the above script, verify that infrap4d is running.

   ```bash
   ps -ef | grep infrap4d
   ```

   ```none
   root     1254701       1 99 13:34 ?        00:13:10 /host/networking-recipe/install/sbin/infrap4d
   ```

   On E2100 target, this script will also load the IDPF driver. Verify the
   presence of the PF:

   ```bash
   devlink dev show
   ```

   ```none
   pci/0000:af:00.0
   ```

7. For the Intel IPU E2100, connect to IMC from host and run the following command on IMC:
   ```bash
   devmem 0x202920C100 64 0x8yy
   ```
   where yy is the 2nd octet of the MAC of the interface on host ending with 'd5' (when using CDQ) or 'v1' (when using SR-IOV).
   For example if the interface `ens801f0d5` has MAC `00:11:00:05:03:14`, then it needs to be
   ```bash
   devmem 0x202920C100 64 0x811
   ```

   This command is currently required for the core-dns component of kubernetes to function.
   For CDQ, till ending with d3 are default sub-functions so first interface
   ending with d4 needs to be assigned to arp and d5 to host.

   For SRIOV - First VF interface ending with v0 goes to arp and V1 goes to host

8. Run ARP-Proxy script, which creates a new namespace and assigns an interface
   from the pool of interfaces created in previous step.
   On E2100 target, user needs to explicitly configure the interface to be
   assigned using IFACE environment variable.

   ```bash
   export IFACE=ens801f0d4
   ```

   Make changes to the [infraagent config file](#infraagent-config-file-update)
   for interface and interface type.

   For DPDK target, change the interfaceType in config.yaml file to "tap".

   The script finally runs the arp-proxy on that assigned interface, within the
   isolated namespace.

   ```bash
   ./scripts/arp_proxy.sh
   ```

   Please note, any changes in config file need to be made
   as per section [inframanager config file update](#inframanager-config-file-update)
   before building the images in next step. Refer to it for updating ARP MAC
   address in the config file.

9. Make the docker images. This step builds the Kubernetes container images:

   ```bash
   make docker-build
   ```

10. Push InfraManager and InfraAgent images into docker private repo either
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

11. Pull images for use by Kubernetes Container Runtime Interface (CRI):

    ```bash
    crictl pull localhost:5000/inframanager:latest
    crictl pull localhost:5000/infraagent:latest
    ```

### infraagent config file update

The config file `deploy/common-config.yaml` is used to inform the
infraagent which interface and interfacetype to use.

The interfaceType should be `cdq` for E2100 and the the interface name is the
base name for PF for PCI device ID 1452.
For SRIOV interfaces, the type should be `sriov`

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
Perform "make" after updates to `deploy/common-config.yaml` to bring changes
into effect.

### inframanager config file update

The config file `deploy/common-config.yaml` is used to define the parameters
which the inframanager will use for the connection establishment with infrap4d
and for the interfaces created.

All fields have a default value in the file. Please verify if the values
correspond to the desired values especially arpmac.

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

For InterfaceType, it needs to be `sriov` for SRIOV since it defaults to `cdq`.

arpmac: The arpmac needs to be configured. This should be the
MAC of the interface the user wants to configure as the ARP-proxy gateway.
This is the address of the interface which is given to the arp-proxy
namespace using the `scrips/arp_proxy.sh` script mentioned in
the [Set Up P4 Kubernetes](#set-up-p4-kubernetes) for ARP proxy gateway.

If user doesn't wish to use these default keys, certificates, and cipher suites, then
modify the `scripts/mev/tls/gen_certs.sh` script accordingly before running
`make gen-certs` and modify the `deploy/common-config.yaml` file with preferred
cipher suites. These changes need to be done prior to the creation of container
images in step 9 of the [Set Up P4 Kubernetes](#set-up-p4-kubernetes) section.

Perform "make" after updates to `deploy/common-config.yaml` to bring changes
into effect.

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

   For split mode on the Intel IPU E2100, run the below on the host
   ```bash
   make deploy-split
   make deploy-calico
   ```

   For host mode, run the below instead
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

  Under `example/service` directory, there are TCP and UDP examples. They contain scripts for running and cleaning,
  and also a README each giving guidelines for the steps. After running the run scripts, the sample output command
  should look like below

   ```bash
   kubectl get svc -A -o wide
   ```

   ```none
   NAME            TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)    AGE     SELECTOR
   iperf-server   ClusterIP   10.111.123.3   <none>        5201/TCP   6m56s   app=iperf-server
   kubernetes      ClusterIP   10.96.0.1      <none>        443/TCP    15m     <none>
   ```

   ```bash
   kubectl get ep -A -o wide
   ```

   ```none
   NAMESPACE     NAME            ENDPOINTS                                               AGE
   default       iperf-server   10.244.0.5:5201,10.244.0.6:5201                         5h22m
   default       kubernetes      10.233.134.119:6443                                     5h35m
   kube-system   kube-dns        10.244.0.3:53,10.244.0.4:53,10.244.0.3:53 + 3 more...   5h35m
   ```

   ```bash
   kubectl get pods -A -o wide
   ```

   ```none
   NAME                                        READY   STATUS    RESTARTS   AGE   IP           NODE    NOMINATED NODE   READINESS GATES
   iperf-clients-8gkv7                        1/1     Running   0          18m   10.244.0.9   ins21   <none>           <none>
   iperf-server-deployment-59bf4754f9-4hp4c   1/1     Running   0          18m   10.244.0.8   ins21   <none>           <none>
   ...
   ```

## Troubleshooting

### Debugging

- The Kubernetes Infrastructure Offload software provides logging capabilities.
  Check logs emitted to stdout
  and stderr using `"kubectl logs <pod> -n <namespace>"`.

### FAQs

1. idpf crash observed leading to host reboot

    Reason : The setup_infra.sh in scripts/es2k dir installs idpf driver and
    then proceeds with creation of sub-functions. Under some circumtances,
    the sleep configured in the script is not sufficient. Driver is still busy
    allocating resources and initializing the base interfaces when the first subfunction
    creation request comes in, leading to crash.

    Solution : Increase the sleep time in the setup_infra.sh script after `"install_drivers"`
    function.

2. "failed to get a CDQ interface for pod: no free resources left" error is seen on infraagent and
    remaining pods do not come up

    Reason : The wrong cp_init.cfg file was used in the IMC and the correct number of host apf under num_max_vport in the cp_init file needs to be at least 50.
    Solution : Use the cdq uses cases cp_init.cfg file

3. CDQ interfaces not coming up

    Reason : IDPF driver failed to load
    Solution : Verify using `dmesg` command that it is the case. Then perform a `modprobe idpf`

4. Failed to connect to inframanager seen on host when in `split` mode.

    Reason: Firewalld blocking it
    Solution: Disable firewall service on ACC. Might need to disable network-manager
    service on both host and ACC.
    ```bash
    systemctl disable NetworkManager
    ```

5. Certs error while processing seen on inframanager when in `split` mode.

    Reason: Time might be out of sync.
    Solution: Ensure that the time is synced using the correct protocol.

### Clean Up

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

   For ACC cleanup, only the below are needed
   ```bash
   pkill infrap4d
   pkill inframanager
   ```

## Versions and Third-parties

Versions of Kubernetes, linux distros, docker and other third-party libraries tested with (calico, felix)

### OS

- Linux
  - Rocky Linux 9.2
  - RHEL 9.2

### golang

go1.21.6

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
