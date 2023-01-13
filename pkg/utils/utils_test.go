// Copyright (c) 2022 Intel Corporation.  All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License")
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	cniTypes "github.com/containernetworking/cni/pkg/types"
	cni40 "github.com/containernetworking/cni/pkg/types/040"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/fsnotify/fsnotify"
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

const (
	nodeListString                          = `{"metadata":{"resourceVersion":"3188299"},"items":[{"metadata":{"name":"dummyNode","uid":"4c1f6487-99e8-4860-8534-7df51b6a682c","resourceVersion":"3188070","creationTimestamp":"2022-07-08T13:44:51Z","labels":{"beta.kubernetes.io/arch":"amd64","beta.kubernetes.io/os":"linux","kubernetes.io/arch":"amd64","kubernetes.io/hostname":"dummyNode","kubernetes.io/os":"linux","node-role.kubernetes.io/control-plane":"","node.kubernetes.io/exclude-from-external-load-balancers":""},"annotations":{"kubeadm.alpha.kubernetes.io/cri-socket":"unix:///var/run/containerd/containerd.sock","node.alpha.kubernetes.io/ttl":"0","projectcalico.org/IPv4Address":"10.244.0.7/24","projectcalico.org/IPv4IPIPTunnelAddr":"10.244.0.1","volumes.kubernetes.io/controller-managed-attach-detach":"true"},"managedFields":[{"manager":"kubelet","operation":"Update","apiVersion":"v1","time":"2022-07-08T13:44:51Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{".":{},"f:volumes.kubernetes.io/controller-managed-attach-detach":{}},"f:labels":{".":{},"f:beta.kubernetes.io/arch":{},"f:beta.kubernetes.io/os":{},"f:kubernetes.io/arch":{},"f:kubernetes.io/hostname":{},"f:kubernetes.io/os":{}}}}},{"manager":"kubeadm","operation":"Update","apiVersion":"v1","time":"2022-07-08T13:44:56Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{"f:kubeadm.alpha.kubernetes.io/cri-socket":{}},"f:labels":{"f:node-role.kubernetes.io/control-plane":{},"f:node.kubernetes.io/exclude-from-external-load-balancers":{}}}}},{"manager":"kube-controller-manager","operation":"Update","apiVersion":"v1","time":"2022-07-08T13:45:10Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{"f:node.alpha.kubernetes.io/ttl":{}}},"f:spec":{"f:podCIDR":{},"f:podCIDRs":{".":{},"v:\"10.244.0.0/24\"":{}}}}},{"manager":"Go-http-client","operation":"Update","apiVersion":"v1","time":"2022-07-08T13:46:55Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{"f:projectcalico.org/IPv4Address":{},"f:projectcalico.org/IPv4IPIPTunnelAddr":{}}}},"subresource":"status"},{"manager":"kubelet","operation":"Update","apiVersion":"v1","time":"2022-07-11T07:17:49Z","fieldsType":"FieldsV1","fieldsV1":{"f:status":{"f:conditions":{"k:{\"type\":\"DiskPressure\"}":{"f:lastHeartbeatTime":{}},"k:{\"type\":\"MemoryPressure\"}":{"f:lastHeartbeatTime":{}},"k:{\"type\":\"PIDPressure\"}":{"f:lastHeartbeatTime":{}},"k:{\"type\":\"Ready\"}":{"f:lastHeartbeatTime":{},"f:lastTransitionTime":{},"f:message":{},"f:reason":{},"f:status":{}}},"f:images":{}}},"subresource":"status"}]},"spec":{"podCIDR":"10.244.0.0/24","podCIDRs":["10.244.0.0/24"]},"status":{"capacity":{"cpu":"88","ephemeral-storage":"960847604Ki","hugepages-1Gi":"0","hugepages-2Mi":"2Gi","memory":"131695828Ki","pods":"110"},"allocatable":{"cpu":"88","ephemeral-storage":"885517150381","hugepages-1Gi":"0","hugepages-2Mi":"2Gi","memory":"129496276Ki","pods":"110"},"conditions":[{"type":"MemoryPressure","status":"False","lastHeartbeatTime":"2022-07-25T12:21:02Z","lastTransitionTime":"2022-07-08T13:44:49Z","reason":"KubeletHasSufficientMemory","message":"kubelet has sufficient memory available"},{"type":"DiskPressure","status":"False","lastHeartbeatTime":"2022-07-25T12:21:02Z","lastTransitionTime":"2022-07-08T13:44:49Z","reason":"KubeletHasNoDiskPressure","message":"kubelet has no disk pressure"},{"type":"PIDPressure","status":"False","lastHeartbeatTime":"2022-07-25T12:21:02Z","lastTransitionTime":"2022-07-08T13:44:49Z","reason":"KubeletHasSufficientPID","message":"kubelet has sufficient PID available"},{"type":"Ready","status":"True","lastHeartbeatTime":"2022-07-25T12:21:02Z","lastTransitionTime":"2022-07-08T13:44:57Z","reason":"KubeletReady","message":"kubelet is posting ready status. AppArmor enabled"}],"addresses":[{"type":"InternalIP","address":"192.168.111.66"},{"type":"Hostname","address":"dummyNode"}],"daemonEndpoints":{"kubeletEndpoint":{"Port":10250}},"nodeInfo":{"machineID":"77094b51073843e5acb5c3cdd16c909e","systemUUID":"30726035-e8ed-ea11-ba6b-a4bf01644732","bootID":"de767a54-9900-4e24-8514-8c4cbf817213","kernelVersion":"5.4.0-121-generic","osImage":"Ubuntu 20.04.4 LTS","containerRuntimeVersion":"containerd://1.5.11","kubeletVersion":"v1.24.0","kubeProxyVersion":"v1.24.0","operatingSystem":"linux","architecture":"amd64"},"images":[{"names":["docker.io/calico/cni@sha256:26802bb7714fda18b93765e908f2d48b0230fd1c620789ba2502549afcde4338","docker.io/calico/cni:v3.23.1"],"sizeBytes":110500425},{"names":["k8s.gcr.io/etcd@sha256:13f53ed1d91e2e11aac476ee9a0269fdda6cc4874eba903efd40daf50c55eee5","k8s.gcr.io/etcd:3.5.3-0"],"sizeBytes":102143581},{"names":["docker.io/calico/node@sha256:d2c1613ef26c9ad43af40527691db1f3ad640291d5e4655ae27f1dd9222cc380","docker.io/calico/node:v3.23.1"],"sizeBytes":76574475},{"names":["docker.io/calico/apiserver@sha256:231b782c7d464bd59b416033e28eae8b3ec2ff90d38ca718558430f67f3203fa","docker.io/calico/apiserver:v3.23.1"],"sizeBytes":76516308},{"names":["quay.io/tigera/operator@sha256:526c06f827200856fb1f5594cc3f7d23935674cf20c22330e8ab9a6ddc484c8d","quay.io/tigera/operator:v1.27.1"],"sizeBytes":60267159},{"names":["docker.io/library/nginx@sha256:10f14ffa93f8dedf1057897b745e5ac72ac5655c299dade0aa434c71557697ea","docker.io/library/nginx:latest"],"sizeBytes":56748232},{"names":["docker.io/calico/kube-controllers@sha256:e8b2af28f2c283a38b4d80436e2d2a25e70f2820d97d1a8684609d42c3973afb","docker.io/calico/kube-controllers:v3.23.1"],"sizeBytes":56361853},{"names":["docker.io/calico/typha@sha256:d58558013bce1387f40969f483f65b5178b4574a8c383c3e997768d6a0ffff34","docker.io/calico/typha:v3.23.1"],"sizeBytes":54003239},{"names":["docker.io/library/nginx@sha256:6fff55753e3b34e36e24e37039ee9eae1fe38a6420d8ae16ef37c92d1eb26699","docker.io/library/nginx:1.17"],"sizeBytes":51030575},{"names":["k8s.gcr.io/kube-proxy@sha256:c957d602267fa61082ab8847914b2118955d0739d592cc7b01e278513478d6a8","k8s.gcr.io/kube-proxy:v1.24.0"],"sizeBytes":39515042},{"names":["k8s.gcr.io/kube-apiserver@sha256:a04522b882e919de6141b47d72393fb01226c78e7388400f966198222558c955","k8s.gcr.io/kube-apiserver:v1.24.0"],"sizeBytes":33796127},{"names":["10.55.129.85:5000/infraagent@sha256:f9f2ef413a30e37ea5f3ca8a5affbeb41c58b56b4a3f36ac22cf85143e5148a0","10.55.129.85:5000/k8s-p4-dataplane@sha256:f9f2ef413a30e37ea5f3ca8a5affbeb41c58b56b4a3f36ac22cf85143e5148a0","10.55.129.85:5000/infraagent:latest","10.55.129.85:5000/k8s-p4-dataplane:latest"],"sizeBytes":32681228},{"names":["k8s.gcr.io/kube-controller-manager@sha256:df044a154e79a18f749d3cd9d958c3edde2b6a00c815176472002b7bbf956637","k8s.gcr.io/kube-controller-manager:v1.24.0"],"sizeBytes":31032816},{"names":["docker.io/wbitt/network-multitool@sha256:82a5ea955024390d6b438ce22ccc75c98b481bf00e57c13e9a9cc1458eb92652","docker.io/wbitt/network-multitool:latest"],"sizeBytes":24236758},{"names":["k8s.gcr.io/kube-scheduler@sha256:db842a7c431fd51db7e1911f6d1df27a7b6b6963ceda24852b654d2cd535b776","k8s.gcr.io/kube-scheduler:v1.24.0"],"sizeBytes":15488642},{"names":["k8s.gcr.io/coredns/coredns@sha256:5b6ec0d6de9baaf3e92d0f66cd96a25b9edbce8716f5f15dcd1a616b3abd590e","k8s.gcr.io/coredns/coredns:v1.8.6"],"sizeBytes":13585107},{"names":["docker.io/calico/pod2daemon-flexvol@sha256:5d5759fc6de1f6c09b95d36334d968fa074779120024c067a770cfb2af579670","docker.io/calico/pod2daemon-flexvol:v3.23.1"],"sizeBytes":8671600},{"names":["docker.io/leannet/k8s-netperf@sha256:dd79ca1b6ecefc1e5bd9301abff0cfdec25dce9cd4fb9a09ddf4e117aa5550cd","docker.io/leannet/k8s-netperf:latest"],"sizeBytes":6732296},{"names":["docker.io/library/busybox@sha256:3614ca5eacf0a3a1bcc361c939202a974b4902b9334ff36eb29ffe9011aaad83","docker.io/library/busybox:latest"],"sizeBytes":777536},{"names":["docker.io/library/busybox@sha256:ebadf81a7f2146e95f8c850ad7af8cf9755d31cdba380a8ffd5930fba5996095"],"sizeBytes":777101},{"names":["docker.io/library/busybox@sha256:d2b53584f580310186df7a2055ce3ff83cc0df6caacf1e3489bff8cf5d0af5d8"],"sizeBytes":777091},{"names":["k8s.gcr.io/pause@sha256:bb6ed397957e9ca7c65ada0db5c5d1c707c9c8afc80a94acbe69f3ae76988f0c","k8s.gcr.io/pause:3.7"],"sizeBytes":311278},{"names":["k8s.gcr.io/pause@sha256:927d98197ec1141a368550822d18fa1c60bdae27b78b0c004f705f548c07814f","k8s.gcr.io/pause:3.2"],"sizeBytes":299513}]}}]}`
	podListString                           = `{"metadata":{"resourceVersion":"1935781"},"items":[{"metadata":{"name":"kube-controller-manager-node01","namespace":"kube-system","uid":"6dded560-2e01-42a9-9d19-f77810da7972","resourceVersion":"303","creationTimestamp":"2022-08-08T07:00:54Z","labels":{"component":"kube-controller-manager","tier":"control-plane"},"annotations":{"kubernetes.io/config.hash":"c5a714e26839c594c550317b88301c99","kubernetes.io/config.mirror":"c5a714e26839c594c550317b88301c99","kubernetes.io/config.seen":"2022-08-08T08:00:47.159987024+01:00","kubernetes.io/config.source":"file","seccomp.security.alpha.kubernetes.io/pod":"runtime/default"},"ownerReferences":[{"apiVersion":"v1","kind":"Node","name":"node01","uid":"f41b3026-c2c9-449b-97a6-c7129dc97021","controller":true}],"managedFields":[]},"spec":{"volumes":[{"name":"ca-certs","hostPath":{"path":"/etc/ssl/certs","type":"DirectoryOrCreate"}},{"name":"etc-pki","hostPath":{"path":"/etc/pki","type":"DirectoryOrCreate"}},{"name":"flexvolume-dir","hostPath":{"path":"/usr/libexec/kubernetes/kubelet-plugins/volume/exec","type":"DirectoryOrCreate"}},{"name":"k8s-certs","hostPath":{"path":"/etc/kubernetes/pki","type":"DirectoryOrCreate"}},{"name":"kubeconfig","hostPath":{"path":"/etc/kubernetes/controller-manager.conf","type":"FileOrCreate"}}],"containers":[{"name":"kube-controller-manager","image":"k8s.gcr.io/kube-controller-manager:v1.24.3","command":["kube-controller-manager","--allocate-node-cidrs=true","--authentication-kubeconfig=/etc/kubernetes/controller-manager.conf","--authorization-kubeconfig=/etc/kubernetes/controller-manager.conf","--bind-address=127.0.0.1","--client-ca-file=/etc/kubernetes/pki/ca.crt","--cluster-cidr=10.210.0.0/16","--cluster-name=kubernetes","--cluster-signing-cert-file=/etc/kubernetes/pki/ca.crt","--cluster-signing-key-file=/etc/kubernetes/pki/ca.key","--controllers=*,bootstrapsigner,tokencleaner","--kubeconfig=/etc/kubernetes/controller-manager.conf","--leader-elect=true","--requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt","--root-ca-file=/etc/kubernetes/pki/ca.crt","--service-account-private-key-file=/etc/kubernetes/pki/sa.key","--service-cluster-ip-range=10.96.0.0/12","--use-service-account-credentials=true"],"env":[],"resources":{"requests":{"cpu":"200m"}},"volumeMounts":[{"name":"ca-certs","readOnly":true,"mountPath":"/etc/ssl/certs"},{"name":"etc-pki","readOnly":true,"mountPath":"/etc/pki"},{"name":"flexvolume-dir","mountPath":"/usr/libexec/kubernetes/kubelet-plugins/volume/exec"},{"name":"k8s-certs","readOnly":true,"mountPath":"/etc/kubernetes/pki"},{"name":"kubeconfig","readOnly":true,"mountPath":"/etc/kubernetes/controller-manager.conf"}],"livenessProbe":{"httpGet":{"path":"/healthz","port":10257,"host":"127.0.0.1","scheme":"HTTPS"},"initialDelaySeconds":10,"timeoutSeconds":15,"periodSeconds":10,"successThreshold":1,"failureThreshold":8},"startupProbe":{"httpGet":{"path":"/healthz","port":10257,"host":"127.0.0.1","scheme":"HTTPS"},"initialDelaySeconds":10,"timeoutSeconds":15,"periodSeconds":10,"successThreshold":1,"failureThreshold":24},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","imagePullPolicy":"IfNotPresent"}],"restartPolicy":"Always","terminationGracePeriodSeconds":30,"dnsPolicy":"ClusterFirst","nodeName":"node01","hostNetwork":true,"securityContext":{"seccompProfile":{"type":"RuntimeDefault"}},"schedulerName":"default-scheduler","tolerations":[{"operator":"Exists","effect":"NoExecute"}],"priorityClassName":"system-node-critical","priority":2000001000,"enableServiceLinks":true,"preemptionPolicy":"PreemptLowerPriority"},"status":{"phase":"Running","conditions":[{"type":"Initialized","status":"True","lastProbeTime":null,"lastTransitionTime":"2022-08-08T07:00:56Z"},{"type":"Ready","status":"True","lastProbeTime":null,"lastTransitionTime":"2022-08-08T07:01:06Z"},{"type":"ContainersReady","status":"True","lastProbeTime":null,"lastTransitionTime":"2022-08-08T07:01:06Z"},{"type":"PodScheduled","status":"True","lastProbeTime":null,"lastTransitionTime":"2022-08-08T07:00:56Z"}],"hostIP":"10.237.214.71","podIP":"10.237.214.71","podIPs":[{"ip":"10.237.214.71"}],"startTime":"2022-08-08T07:00:56Z","containerStatuses":[{"name":"kube-controller-manager","state":{"running":{"startedAt":"2022-08-08T07:00:48Z"}},"lastState":{},"ready":true,"restartCount":1,"image":"k8s.gcr.io/kube-controller-manager:v1.24.3","imageID":"k8s.gcr.io/kube-controller-manager@sha256:f504eead8b8674ebc9067370ef51abbdc531b4a81813bfe464abccb8c76b6a53","containerID":"containerd://b2b7d69d8f6e6d1f057e7c5a428e572f69e34deb41f6f051610dd3a9986c6ca1","started":true}],"qosClass":"Burstable"}}]}`
	podListStringNoSvcSubnet                = `{"metadata":{"resourceVersion":"1935781"},"items":[{"metadata":{"name":"kube-controller-manager-node01","namespace":"kube-system","uid":"6dded560-2e01-42a9-9d19-f77810da7972","resourceVersion":"303","creationTimestamp":"2022-08-08T07:00:54Z","labels":{"component":"kube-controller-manager","tier":"control-plane"},"annotations":{"kubernetes.io/config.hash":"c5a714e26839c594c550317b88301c99","kubernetes.io/config.mirror":"c5a714e26839c594c550317b88301c99","kubernetes.io/config.seen":"2022-08-08T08:00:47.159987024+01:00","kubernetes.io/config.source":"file","seccomp.security.alpha.kubernetes.io/pod":"runtime/default"},"ownerReferences":[{"apiVersion":"v1","kind":"Node","name":"node01","uid":"f41b3026-c2c9-449b-97a6-c7129dc97021","controller":true}],"managedFields":[]},"spec":{"volumes":[{"name":"ca-certs","hostPath":{"path":"/etc/ssl/certs","type":"DirectoryOrCreate"}},{"name":"etc-pki","hostPath":{"path":"/etc/pki","type":"DirectoryOrCreate"}},{"name":"flexvolume-dir","hostPath":{"path":"/usr/libexec/kubernetes/kubelet-plugins/volume/exec","type":"DirectoryOrCreate"}},{"name":"k8s-certs","hostPath":{"path":"/etc/kubernetes/pki","type":"DirectoryOrCreate"}},{"name":"kubeconfig","hostPath":{"path":"/etc/kubernetes/controller-manager.conf","type":"FileOrCreate"}}],"containers":[{"name":"kube-controller-manager","image":"k8s.gcr.io/kube-controller-manager:v1.24.3","command":["kube-controller-manager","--allocate-node-cidrs=true","--authentication-kubeconfig=/etc/kubernetes/controller-manager.conf","--authorization-kubeconfig=/etc/kubernetes/controller-manager.conf","--bind-address=127.0.0.1","--client-ca-file=/etc/kubernetes/pki/ca.crt","--cluster-cidr=10.210.0.0/16","--cluster-name=kubernetes","--cluster-signing-cert-file=/etc/kubernetes/pki/ca.crt","--cluster-signing-key-file=/etc/kubernetes/pki/ca.key","--controllers=*,bootstrapsigner,tokencleaner","--kubeconfig=/etc/kubernetes/controller-manager.conf","--leader-elect=true","--requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt","--root-ca-file=/etc/kubernetes/pki/ca.crt","--service-account-private-key-file=/etc/kubernetes/pki/sa.key","--use-service-account-credentials=true"],"env":[],"resources":{"requests":{"cpu":"200m"}},"volumeMounts":[{"name":"ca-certs","readOnly":true,"mountPath":"/etc/ssl/certs"},{"name":"etc-pki","readOnly":true,"mountPath":"/etc/pki"},{"name":"flexvolume-dir","mountPath":"/usr/libexec/kubernetes/kubelet-plugins/volume/exec"},{"name":"k8s-certs","readOnly":true,"mountPath":"/etc/kubernetes/pki"},{"name":"kubeconfig","readOnly":true,"mountPath":"/etc/kubernetes/controller-manager.conf"}],"livenessProbe":{"httpGet":{"path":"/healthz","port":10257,"host":"127.0.0.1","scheme":"HTTPS"},"initialDelaySeconds":10,"timeoutSeconds":15,"periodSeconds":10,"successThreshold":1,"failureThreshold":8},"startupProbe":{"httpGet":{"path":"/healthz","port":10257,"host":"127.0.0.1","scheme":"HTTPS"},"initialDelaySeconds":10,"timeoutSeconds":15,"periodSeconds":10,"successThreshold":1,"failureThreshold":24},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","imagePullPolicy":"IfNotPresent"}],"restartPolicy":"Always","terminationGracePeriodSeconds":30,"dnsPolicy":"ClusterFirst","nodeName":"node01","hostNetwork":true,"securityContext":{"seccompProfile":{"type":"RuntimeDefault"}},"schedulerName":"default-scheduler","tolerations":[{"operator":"Exists","effect":"NoExecute"}],"priorityClassName":"system-node-critical","priority":2000001000,"enableServiceLinks":true,"preemptionPolicy":"PreemptLowerPriority"},"status":{"phase":"Running","conditions":[{"type":"Initialized","status":"True","lastProbeTime":null,"lastTransitionTime":"2022-08-08T07:00:56Z"},{"type":"Ready","status":"True","lastProbeTime":null,"lastTransitionTime":"2022-08-08T07:01:06Z"},{"type":"ContainersReady","status":"True","lastProbeTime":null,"lastTransitionTime":"2022-08-08T07:01:06Z"},{"type":"PodScheduled","status":"True","lastProbeTime":null,"lastTransitionTime":"2022-08-08T07:00:56Z"}],"hostIP":"10.237.214.71","podIP":"10.237.214.71","podIPs":[{"ip":"10.237.214.71"}],"startTime":"2022-08-08T07:00:56Z","containerStatuses":[{"name":"kube-controller-manager","state":{"running":{"startedAt":"2022-08-08T07:00:48Z"}},"lastState":{},"ready":true,"restartCount":1,"image":"k8s.gcr.io/kube-controller-manager:v1.24.3","imageID":"k8s.gcr.io/kube-controller-manager@sha256:f504eead8b8674ebc9067370ef51abbdc531b4a81813bfe464abccb8c76b6a53","containerID":"containerd://b2b7d69d8f6e6d1f057e7c5a428e572f69e34deb41f6f051610dd3a9986c6ca1","started":true}],"qosClass":"Burstable"}}]}`
	emptyNodeListString                     = `{"metadata":{"resourceVersion":"3188299"},"items":[]}`
	noInternalIPNodeListString              = `{"metadata":{"resourceVersion":"3188299"},"items":[{"metadata":{"name":"dummyNode","uid":"4c1f6487-99e8-4860-8534-7df51b6a682c","resourceVersion":"3188070","creationTimestamp":"2022-07-08T13:44:51Z","labels":{"beta.kubernetes.io/arch":"amd64","beta.kubernetes.io/os":"linux","kubernetes.io/arch":"amd64","kubernetes.io/hostname":"dummyNode","kubernetes.io/os":"linux","node-role.kubernetes.io/control-plane":"","node.kubernetes.io/exclude-from-external-load-balancers":""},"annotations":{"kubeadm.alpha.kubernetes.io/cri-socket":"unix:///var/run/containerd/containerd.sock","node.alpha.kubernetes.io/ttl":"0","projectcalico.org/IPv4Address":"10.244.0.7/24","projectcalico.org/IPv4IPIPTunnelAddr":"10.244.0.1","volumes.kubernetes.io/controller-managed-attach-detach":"true"},"managedFields":[{"manager":"kubelet","operation":"Update","apiVersion":"v1","time":"2022-07-08T13:44:51Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{".":{},"f:volumes.kubernetes.io/controller-managed-attach-detach":{}},"f:labels":{".":{},"f:beta.kubernetes.io/arch":{},"f:beta.kubernetes.io/os":{},"f:kubernetes.io/arch":{},"f:kubernetes.io/hostname":{},"f:kubernetes.io/os":{}}}}},{"manager":"kubeadm","operation":"Update","apiVersion":"v1","time":"2022-07-08T13:44:56Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{"f:kubeadm.alpha.kubernetes.io/cri-socket":{}},"f:labels":{"f:node-role.kubernetes.io/control-plane":{},"f:node.kubernetes.io/exclude-from-external-load-balancers":{}}}}},{"manager":"kube-controller-manager","operation":"Update","apiVersion":"v1","time":"2022-07-08T13:45:10Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{"f:node.alpha.kubernetes.io/ttl":{}}},"f:spec":{"f:podCIDR":{},"f:podCIDRs":{".":{},"v:\"10.244.0.0/24\"":{}}}}},{"manager":"Go-http-client","operation":"Update","apiVersion":"v1","time":"2022-07-08T13:46:55Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{"f:projectcalico.org/IPv4Address":{},"f:projectcalico.org/IPv4IPIPTunnelAddr":{}}}},"subresource":"status"},{"manager":"kubelet","operation":"Update","apiVersion":"v1","time":"2022-07-11T07:17:49Z","fieldsType":"FieldsV1","fieldsV1":{"f:status":{"f:conditions":{"k:{\"type\":\"DiskPressure\"}":{"f:lastHeartbeatTime":{}},"k:{\"type\":\"MemoryPressure\"}":{"f:lastHeartbeatTime":{}},"k:{\"type\":\"PIDPressure\"}":{"f:lastHeartbeatTime":{}},"k:{\"type\":\"Ready\"}":{"f:lastHeartbeatTime":{},"f:lastTransitionTime":{},"f:message":{},"f:reason":{},"f:status":{}}},"f:images":{}}},"subresource":"status"}]},"spec":{"podCIDR":"10.244.0.0/24","podCIDRs":["10.244.0.0/24"]},"status":{"capacity":{"cpu":"88","ephemeral-storage":"960847604Ki","hugepages-1Gi":"0","hugepages-2Mi":"2Gi","memory":"131695828Ki","pods":"110"},"allocatable":{"cpu":"88","ephemeral-storage":"885517150381","hugepages-1Gi":"0","hugepages-2Mi":"2Gi","memory":"129496276Ki","pods":"110"},"conditions":[{"type":"MemoryPressure","status":"False","lastHeartbeatTime":"2022-07-25T12:21:02Z","lastTransitionTime":"2022-07-08T13:44:49Z","reason":"KubeletHasSufficientMemory","message":"kubelet has sufficient memory available"},{"type":"DiskPressure","status":"False","lastHeartbeatTime":"2022-07-25T12:21:02Z","lastTransitionTime":"2022-07-08T13:44:49Z","reason":"KubeletHasNoDiskPressure","message":"kubelet has no disk pressure"},{"type":"PIDPressure","status":"False","lastHeartbeatTime":"2022-07-25T12:21:02Z","lastTransitionTime":"2022-07-08T13:44:49Z","reason":"KubeletHasSufficientPID","message":"kubelet has sufficient PID available"},{"type":"Ready","status":"True","lastHeartbeatTime":"2022-07-25T12:21:02Z","lastTransitionTime":"2022-07-08T13:44:57Z","reason":"KubeletReady","message":"kubelet is posting ready status. AppArmor enabled"}],"addresses":[{"type":"InternalIP","address":""},{"type":"Hostname","address":"dummyNode"}],"daemonEndpoints":{"kubeletEndpoint":{"Port":10250}},"nodeInfo":{"machineID":"77094b51073843e5acb5c3cdd16c909e","systemUUID":"30726035-e8ed-ea11-ba6b-a4bf01644732","bootID":"de767a54-9900-4e24-8514-8c4cbf817213","kernelVersion":"5.4.0-121-generic","osImage":"Ubuntu 20.04.4 LTS","containerRuntimeVersion":"containerd://1.5.11","kubeletVersion":"v1.24.0","kubeProxyVersion":"v1.24.0","operatingSystem":"linux","architecture":"amd64"},"images":[{"names":["docker.io/calico/cni@sha256:26802bb7714fda18b93765e908f2d48b0230fd1c620789ba2502549afcde4338","docker.io/calico/cni:v3.23.1"],"sizeBytes":110500425},{"names":["k8s.gcr.io/etcd@sha256:13f53ed1d91e2e11aac476ee9a0269fdda6cc4874eba903efd40daf50c55eee5","k8s.gcr.io/etcd:3.5.3-0"],"sizeBytes":102143581},{"names":["docker.io/calico/node@sha256:d2c1613ef26c9ad43af40527691db1f3ad640291d5e4655ae27f1dd9222cc380","docker.io/calico/node:v3.23.1"],"sizeBytes":76574475},{"names":["docker.io/calico/apiserver@sha256:231b782c7d464bd59b416033e28eae8b3ec2ff90d38ca718558430f67f3203fa","docker.io/calico/apiserver:v3.23.1"],"sizeBytes":76516308},{"names":["quay.io/tigera/operator@sha256:526c06f827200856fb1f5594cc3f7d23935674cf20c22330e8ab9a6ddc484c8d","quay.io/tigera/operator:v1.27.1"],"sizeBytes":60267159},{"names":["docker.io/library/nginx@sha256:10f14ffa93f8dedf1057897b745e5ac72ac5655c299dade0aa434c71557697ea","docker.io/library/nginx:latest"],"sizeBytes":56748232},{"names":["docker.io/calico/kube-controllers@sha256:e8b2af28f2c283a38b4d80436e2d2a25e70f2820d97d1a8684609d42c3973afb","docker.io/calico/kube-controllers:v3.23.1"],"sizeBytes":56361853},{"names":["docker.io/calico/typha@sha256:d58558013bce1387f40969f483f65b5178b4574a8c383c3e997768d6a0ffff34","docker.io/calico/typha:v3.23.1"],"sizeBytes":54003239},{"names":["docker.io/library/nginx@sha256:6fff55753e3b34e36e24e37039ee9eae1fe38a6420d8ae16ef37c92d1eb26699","docker.io/library/nginx:1.17"],"sizeBytes":51030575},{"names":["k8s.gcr.io/kube-proxy@sha256:c957d602267fa61082ab8847914b2118955d0739d592cc7b01e278513478d6a8","k8s.gcr.io/kube-proxy:v1.24.0"],"sizeBytes":39515042},{"names":["k8s.gcr.io/kube-apiserver@sha256:a04522b882e919de6141b47d72393fb01226c78e7388400f966198222558c955","k8s.gcr.io/kube-apiserver:v1.24.0"],"sizeBytes":33796127},{"names":["10.55.129.85:5000/infraagent@sha256:f9f2ef413a30e37ea5f3ca8a5affbeb41c58b56b4a3f36ac22cf85143e5148a0","10.55.129.85:5000/k8s-p4-dataplane@sha256:f9f2ef413a30e37ea5f3ca8a5affbeb41c58b56b4a3f36ac22cf85143e5148a0","10.55.129.85:5000/infraagent:latest","10.55.129.85:5000/k8s-p4-dataplane:latest"],"sizeBytes":32681228},{"names":["k8s.gcr.io/kube-controller-manager@sha256:df044a154e79a18f749d3cd9d958c3edde2b6a00c815176472002b7bbf956637","k8s.gcr.io/kube-controller-manager:v1.24.0"],"sizeBytes":31032816},{"names":["docker.io/wbitt/network-multitool@sha256:82a5ea955024390d6b438ce22ccc75c98b481bf00e57c13e9a9cc1458eb92652","docker.io/wbitt/network-multitool:latest"],"sizeBytes":24236758},{"names":["k8s.gcr.io/kube-scheduler@sha256:db842a7c431fd51db7e1911f6d1df27a7b6b6963ceda24852b654d2cd535b776","k8s.gcr.io/kube-scheduler:v1.24.0"],"sizeBytes":15488642},{"names":["k8s.gcr.io/coredns/coredns@sha256:5b6ec0d6de9baaf3e92d0f66cd96a25b9edbce8716f5f15dcd1a616b3abd590e","k8s.gcr.io/coredns/coredns:v1.8.6"],"sizeBytes":13585107},{"names":["docker.io/calico/pod2daemon-flexvol@sha256:5d5759fc6de1f6c09b95d36334d968fa074779120024c067a770cfb2af579670","docker.io/calico/pod2daemon-flexvol:v3.23.1"],"sizeBytes":8671600},{"names":["docker.io/leannet/k8s-netperf@sha256:dd79ca1b6ecefc1e5bd9301abff0cfdec25dce9cd4fb9a09ddf4e117aa5550cd","docker.io/leannet/k8s-netperf:latest"],"sizeBytes":6732296},{"names":["docker.io/library/busybox@sha256:3614ca5eacf0a3a1bcc361c939202a974b4902b9334ff36eb29ffe9011aaad83","docker.io/library/busybox:latest"],"sizeBytes":777536},{"names":["docker.io/library/busybox@sha256:ebadf81a7f2146e95f8c850ad7af8cf9755d31cdba380a8ffd5930fba5996095"],"sizeBytes":777101},{"names":["docker.io/library/busybox@sha256:d2b53584f580310186df7a2055ce3ff83cc0df6caacf1e3489bff8cf5d0af5d8"],"sizeBytes":777091},{"names":["k8s.gcr.io/pause@sha256:bb6ed397957e9ca7c65ada0db5c5d1c707c9c8afc80a94acbe69f3ae76988f0c","k8s.gcr.io/pause:3.7"],"sizeBytes":311278},{"names":["k8s.gcr.io/pause@sha256:927d98197ec1141a368550822d18fa1c60bdae27b78b0c004f705f548c07814f","k8s.gcr.io/pause:3.2"],"sizeBytes":299513}]}}]}`
	kubeControllerManagerCommand            = `kube-controller-manager --allocate-node-cidrs=true --authentication-kubeconfig=/etc/kubernetes/controller-manager.conf --authorization-kubeconfig=/etc/kubernetes/controller-manager.conf --bind-address=127.0.0.1 --client-ca-file=/etc/kubernetes/pki/ca.crt --cluster-cidr=10.210.0.0/16 --cluster-name=kubernetes --cluster-signing-cert-file=/etc/kubernetes/pki/ca.crt --cluster-signing-key-file=/etc/kubernetes/pki/ca.key --controllers=*,bootstrapsigner,tokencleaner --kubeconfig=/etc/kubernetes/controller-manager.conf --leader-elect=true --requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt --root-ca-file=/etc/kubernetes/pki/ca.crt --service-account-private-key-file=/etc/kubernetes/pki/sa.key --service-cluster-ip-range=10.96.0.0/12 --use-service-account-credentials=true`
	kubeControllerManagerCommandNoSvcSubnet = `kube-controller-manager --allocate-node-cidrs=true --authentication-kubeconfig=/etc/kubernetes/controller-manager.conf --authorization-kubeconfig=/etc/kubernetes/controller-manager.conf --bind-address=127.0.0.1 --client-ca-file=/etc/kubernetes/pki/ca.crt --cluster-cidr=10.210.0.0/16 --cluster-name=kubernetes --cluster-signing-cert-file=/etc/kubernetes/pki/ca.crt --cluster-signing-key-file=/etc/kubernetes/pki/ca.key --controllers=*,bootstrapsigner,tokencleaner --kubeconfig=/etc/kubernetes/controller-manager.conf --leader-elect=true --requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt --root-ca-file=/etc/kubernetes/pki/ca.crt --service-account-private-key-file=/etc/kubernetes/pki/sa.key --use-service-account-credentials=true`

	testInterfacefName = "TestInterface"
	internalIP         = "192.168.111.66"
	nodeName           = "dummyNode"

	exampleConfig = `
        apiVersion: v1
        clusters:
        - cluster:
            certificate-authority-data: MQo=
            server: https://127.0.0.1:6443
          name: kubernetes
        contexts:
        - context:
            cluster: kubernetes
            user: kubernetes-admin
          name: kubernetes-admin@kubernetes
        current-context: kubernetes-admin@kubernetes
        kind: Config
        preferences: {}
        users:
        - name: kubernetes-admin
          user:
            client-certificate-data: MQo=
            client-key-data: MQo=`

	calicoConfig          = `{"name": "k8s-pod-network","cniVersion": "0.3.1","plugins": [{"type": "calico","datastore_type": "kubernetes","mtu": 0,"nodename_file_optional": false,"log_level": "Info","log_file_path": "/var/log/calico/cni/cni.log","ipam": { "type": "calico-ipam", "assign_ipv4" : "true", "assign_ipv6" : "false"},"container_settings": {"allow_ip_forwarding": false},"policy": {"type": "k8s"},"kubernetes": {"k8s_api_root":"https://10.96.0.1:443","kubeconfig": "/etc/cni/net.d/calico-kubeconfig"}},{"type": "bandwidth","capabilities": {"bandwidth": true}},{"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}]}`
	calicoConfigPodSubnet = `{"name": "k8s-pod-network","cniVersion": "0.3.1","plugins": [{"type": "calico","datastore_type": "kubernetes","mtu": 0,"nodename_file_optional": false,"log_level": "Info","log_file_path": "/var/log/calico/cni/cni.log","ipam": { "type": "calico-ipam", "assign_ipv4" : "true", "assign_ipv6" : "false", "subnet" : "usePodCidr"},"container_settings": {"allow_ip_forwarding": false},"policy": {"type": "k8s"},"kubernetes": {"k8s_api_root":"https://10.96.0.1:443","kubeconfig": "/etc/cni/net.d/calico-kubeconfig"}},{"type": "bandwidth","capabilities": {"bandwidth": true}},{"type": "portmap", "snat": true, "capabilities": {"portMappings": true}}]}`

	ipamExecResp      = `{"cniVersion":"0.3.1","ips":[{"version":"4","address":"10.210.0.85/24","gateway":"10.210.0.1"}],"dns":{}}`
	ipamExecRespNoIPs = `{"cniVersion":"0.3.1","ips":[],"dns":{}}`
)

var (
	tempDir string
	info    *types.InterfaceInfo
	ifList  []net.Interface
	podList *v1.PodList
)

func TestUtils(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Utils Test Suite")
}

var _ = BeforeSuite(func() {
	var err error
	tempDir, err = os.MkdirTemp("", "utils")
	Expect(err).To(BeNil())
	info = &types.InterfaceInfo{
		PciAddr:       "0000:0e:00.0",
		InterfaceName: "eth0",
		VfID:          1,
		MacAddr:       "FF:FF:FF:FF:FF:FF",
	}
	ifc := net.Interface{
		Name: testInterfacefName,
	}
	ifList = []net.Interface{ifc}
	podList = &v1.PodList{}
})

var _ = AfterSuite(func() {
	err := os.RemoveAll(tempDir)
	Expect(err).To(BeNil())
})

var _ = Describe("utils", func() {
	var _ = Context("SaveInterfaceConf() should store json file", func() {
		var _ = It("without error", func() {
			err := SaveInterfaceConf(tempDir, "dummy-ref-id", "dummy", info)
			Expect(err).ToNot(HaveOccurred())
		})
	})

	var _ = Context("ReadInterfaceConf() should read json file", func() {
		var _ = It("without error", func() {
			err := SaveInterfaceConf(tempDir, "dummy-ref-id", "dummy", info)
			Expect(err).ToNot(HaveOccurred())
			pi, err := ReadInterfaceConf(tempDir, "dummy-ref-id", "dummy")
			Expect(err).NotTo(HaveOccurred())
			Expect(pi).To(Equal(info))
		})
	})

	var _ = Context("CleanIntfConfCache() should remove json file", func() {
		var _ = It("without error", func() {
			err := SaveInterfaceConf(tempDir, "dummy-ref-id", "dummy", info)
			Expect(err).ToNot(HaveOccurred())
			err = CleanIntfConfCache(tempDir, "dummy-ref-id", "dummy")
			Expect(err).ToNot(HaveOccurred())
			fp := filepath.Join(tempDir, "dummy-ref-id", "dummy")
			_, err = os.Open(fp)
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("GetNodeIP() should", func() {
		var _ = It("return node ip", func() {
			nodeList := &v1.NodeList{}
			err := json.Unmarshal([]byte(nodeListString), nodeList)
			Expect(err).ToNot(HaveOccurred())
			client := fake.NewSimpleClientset(nodeList)
			ip, err := GetNodeIP(client, nodeName)
			Expect(err).NotTo(HaveOccurred())
			Expect(ip).NotTo(BeEmpty())
			netIP := net.ParseIP(ip)
			Expect(netIP).ToNot(BeNil())
		})
	})

	var _ = Context("GetNodeIP() should", func() {
		var _ = It("return error if node list is empty", func() {
			nodeList := &v1.NodeList{}
			err := json.Unmarshal([]byte(emptyNodeListString), nodeList)
			Expect(err).ToNot(HaveOccurred())
			client := fake.NewSimpleClientset(nodeList)
			_, err = GetNodeIP(client, nodeName)
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("GetNodeIP() should", func() {
		var _ = It("return error if no internal IP is available", func() {
			nodeList := &v1.NodeList{}
			err := json.Unmarshal([]byte(noInternalIPNodeListString), nodeList)
			Expect(err).ToNot(HaveOccurred())
			client := fake.NewSimpleClientset(nodeList)
			_, err = GetNodeIP(client, nodeName)
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("GetNodeNetInterface() should", func() {
		var _ = It("return no error", func() {
			nodeList := &v1.NodeList{}
			err := json.Unmarshal([]byte(nodeListString), nodeList)
			Expect(err).ToNot(HaveOccurred())
			client := fake.NewSimpleClientset(nodeList)
			addrGetterMock := interfaceAddressGetterMock{}
			_, err = GetNodeNetInterface(client, nodeName, &addrGetterMock, logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
		})

		var _ = It("return error if GetNodeIP is unsuccessful", func() {
			nodeList := &v1.NodeList{}
			err := json.Unmarshal([]byte(emptyNodeListString), nodeList)
			Expect(err).ToNot(HaveOccurred())
			client := fake.NewSimpleClientset(nodeList)
			addrGetterMock := interfaceAddressGetterMock{}
			_, err = GetNodeNetInterface(client, nodeName, &addrGetterMock, logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("GetK8sConfig() should", func() {
		var _ = It("return no error when it can build config from file", func() {
			t := testing.T{}
			t.Setenv("HOME", tempDir)
			_, tearDown, err := prepareKubeConfig(tempDir, exampleConfig)
			Expect(err).ToNot(HaveOccurred())
			defer tearDown()
			_, err = GetK8sConfig()
			Expect(err).ToNot(HaveOccurred())
		})

		var _ = It("return error if config file is invalid", func() {
			t := testing.T{}
			t.Setenv("HOME", tempDir)
			_, tearDown, err := prepareKubeConfig(tempDir, "BrokenConfig")
			Expect(err).ToNot(HaveOccurred())
			defer tearDown()
			_, err = GetK8sConfig()
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("GetNodeName() should", func() {
		var _ = It("return no error when NODE_NAME env variable is set", func() {
			t := testing.T{}
			t.Setenv("NODE_NAME", "dummyNode")
			nodeName, err := GetNodeName()
			Expect(err).ToNot(HaveOccurred())
			Expect(nodeName).To(Equal("dummyNode"))
		})
		var _ = It("return error when NODE_NAME evalue is unavailable", func() {
			t := testing.T{}
			t.Setenv("NODE_NAME", "")
			nodeName, err := GetNodeName()
			Expect(err).To(HaveOccurred())
			Expect(nodeName).To(Equal(""))
		})
	})

	var _ = Context("GetVFList() should", func() {
		var _ = It("return error if cannot read virtfn link", func() {
			fs := &FakeFilesystem{
				Dirs: []string{
					"sys/class/net/dummyPf/device/",
					"sys/class/net/dummyPf/0000:02:06.0/net/enp2s0",
					"sys/class/net/dummyPf/0000:02:06.1/net/enp2s1",
					"sys/class/net/dummyPf/0000:02:06.2/net/enp2s2",
					"sys/class/net/dummyPf/0000:02:06.3/net",
					"sys/class/net/dummyPf/0000:02:06.4",
				},
				Files: map[string][]byte{
					"sys/class/net/dummyPf/0000:02:06.0/net/enp2s0/address": []byte("00:00:00:00:00:00"),
					"sys/class/net/dummyPf/0000:02:06.1/net/enp2s1/address": []byte("00:00:00:00:00:01"),
				},
				Symlinks: map[string]string{
					"sys/class/net/dummyPf/device/virtfn0": "../0000:02:06.0",
					"sys/class/net/dummyPf/device/virtfn1": "../0000:02:06.1",
					"sys/class/net/dummyPf/device/virtfn2": "../0000:02:06.2",
					"sys/class/net/dummyPf/device/virtfn3": "../0000:02:06.3",
					"sys/class/net/dummyPf/device/virtfn4": "../0000:02:06.4",
				},
			}
			tempRoot, tearDown, err := fs.Use(tempDir)
			Expect(err).ToNot(HaveOccurred())
			defer tearDown()
			fakeSysFs := filepath.Join(tempRoot, SysClassNet)
			result, err := GetVFList("dummyPf", fakeSysFs)
			Expect(len(result)).To(Equal(2))
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return error if device does not exist", func() {
			fs := &FakeFilesystem{
				Dirs: []string{"sys/class/net/"},
			}
			tempRoot, tearDown, err := fs.Use(tempDir)
			Expect(err).ToNot(HaveOccurred())
			defer tearDown()
			fakeSysFs := filepath.Join(tempRoot, SysClassNet)
			_, err = GetVFList("dummyPf", fakeSysFs)
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("GetTapInterfaces() should", func() {
		var _ = It("return no error", func() {
			links, err := netlink.LinkList()
			Expect(err).ToNot(HaveOccurred())
			Expect(len(links)).ToNot(Equal(0))
			link := links[0]
			ifs, err := GetTapInterfaces(link.Attrs().Name)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(ifs)).ToNot(Equal(0))
		})
	})

	var _ = Context("GetNodePodsCIDR() should", func() {
		var _ = It("return Pod CIDR for valid data", func() {
			nodeList := &v1.NodeList{}
			err := json.Unmarshal([]byte(nodeListString), nodeList)
			Expect(err).ToNot(HaveOccurred())
			client := fake.NewSimpleClientset(nodeList)
			cidr, err := GetNodePodsCIDR(client, "dummyNode")
			Expect(err).ToNot(HaveOccurred())
			Expect(cidr).ToNot(BeEmpty())
			ip, ipnet, err := net.ParseCIDR(cidr)
			Expect(err).NotTo(HaveOccurred())
			Expect(ip).NotTo(BeNil())
			Expect(ipnet).NotTo(BeNil())
		})

		var _ = It("return error if list of nodes is empty", func() {
			nodeList := &v1.NodeList{}
			err := json.Unmarshal([]byte(emptyNodeListString), nodeList)
			Expect(err).ToNot(HaveOccurred())
			client := fake.NewSimpleClientset(nodeList)
			_, err = GetNodePodsCIDR(client, "dummyNode")
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("GetK8sClient() should", func() {
		var _ = It("return client for valid config", func() {
			client, err := GetK8sClient(&rest.Config{})
			Expect(err).ToNot(HaveOccurred())
			Expect(client).ToNot(BeNil())
		})
	})

	var _ = Context("getIPFromCommand() should", func() {
		var _ = It("return ip address if available", func() {
			svcIP := "10.96.0.0/12"
			ipAddr := getIPFromCommand(serviceSubnetPattern, []string{kubeControllerManagerCommand})
			Expect(ipAddr).To(Equal(svcIP))
		})

		var _ = It("return empty ip address if not found", func() {
			ipAddr := getIPFromCommand(serviceSubnetPattern, []string{kubeControllerManagerCommandNoSvcSubnet})
			Expect(ipAddr).To(Equal(""))
		})

		var _ = It("return empty ip address if pattern finds more than = characters", func() {
			ipAddr := getIPFromCommand("a=b=c", []string{"a=b=c"})
			Expect(ipAddr).To(Equal(""))
		})
	})

	var _ = Context("GetSubnets() should", func() {
		var _ = It("set Pods and Service CIDR", func() {
			err := json.Unmarshal([]byte(podListString), podList)
			Expect(err).ToNot(HaveOccurred())
			client := fake.NewSimpleClientset(podList)
			err = GetSubnets(client)
			Expect(err).ToNot(HaveOccurred())
			Expect(types.ClusterPodsCIDR).NotTo(BeEmpty())
			Expect(types.ClusterServicesSubnet).NotTo(BeEmpty())
			// check if we have valid CIDR
			_, _, err = net.ParseCIDR(types.ClusterPodsCIDR)
			Expect(err).ToNot(HaveOccurred())
			_, _, err = net.ParseCIDR(types.ClusterServicesSubnet)
			Expect(err).ToNot(HaveOccurred())
		})

		var _ = It("return error if no svc subnet was found", func() {
			err := json.Unmarshal([]byte(podListStringNoSvcSubnet), podList)
			Expect(err).ToNot(HaveOccurred())
			client := fake.NewSimpleClientset(podList)
			err = GetSubnets(client)
			Expect(err).To(HaveOccurred())
			Expect(types.ClusterPodsCIDR).NotTo(BeEmpty())
			Expect(types.ClusterServicesSubnet).To(BeEmpty())
		})

		var _ = It("return error if kube-controller-manager pod was not found", func() {
			err := json.Unmarshal([]byte(podListStringNoSvcSubnet), podList)
			Expect(err).ToNot(HaveOccurred())
			client := fake.NewSimpleClientset()
			err = GetSubnets(client)
			Expect(err).To(HaveOccurred())
			Expect(types.ClusterPodsCIDR).NotTo(BeEmpty())
			Expect(types.ClusterServicesSubnet).To(BeEmpty())
		})
	})

	var _ = Context("setupRequiredEnvironment() should", func() {
		var _ = It("return no error", func() {
			calicoFakeCfg, tearDown, err := prepareCalicoConfig(tempDir, calicoConfig)
			Expect(err).ToNot(HaveOccurred())
			defer tearDown()
			tvc := newTestVarConfigurer()
			tec := NewEnvConfigurer(tvc, calicoFakeCfg)
			_, err = setupRequiredEnvironment(tec)
			Expect(err).ToNot(HaveOccurred())
		})

		var _ = It("return no error if usePodSubnet is enabled", func() {
			calicoFakeCfg, tearDown, err := prepareCalicoConfig(tempDir, calicoConfigPodSubnet)
			Expect(err).ToNot(HaveOccurred())
			defer tearDown()
			tvc := newTestVarConfigurer()
			tec := NewEnvConfigurer(tvc, calicoFakeCfg)
			_, err = setupRequiredEnvironment(tec)
			Expect(err).ToNot(HaveOccurred())
		})

		var _ = It("return error if cannot read Calico config", func() {
			fs := &FakeFilesystem{
				Dirs: []string{
					"etc/cni/net.d/",
				},
			}
			tempRoot, tearDown, err := fs.Use(tempDir)
			Expect(err).ToNot(HaveOccurred())
			defer tearDown()

			calicoFakeCfg := filepath.Join(tempRoot, types.DefaultCalicoConfig)
			tvc := newTestVarConfigurer()
			tec := NewEnvConfigurer(tvc, calicoFakeCfg)
			_, err = setupRequiredEnvironment(tec)
			Expect(err).To(HaveOccurred())
		})

		var _ = It("return error if Calico config is broken", func() {
			calicoFakeCfg, tearDown, err := prepareCalicoConfig(tempDir, "{broken:config}")
			Expect(err).ToNot(HaveOccurred())
			defer tearDown()
			tvc := newTestVarConfigurer()
			tec := NewEnvConfigurer(tvc, calicoFakeCfg)
			_, err = setupRequiredEnvironment(tec)
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("GetIPFromIPAM() should", func() {
		var _ = It("return no error", func() {
			calicoFakeCfg, tearDown, err := prepareCalicoConfig(tempDir, calicoConfig)
			Expect(err).ToNot(HaveOccurred())
			defer tearDown()
			tvc := newTestVarConfigurer()
			tec := NewEnvConfigurer(tvc, calicoFakeCfg)
			_, err = GetIPFromIPAM(tec, ipamExecAdd)
			Expect(err).ToNot(HaveOccurred())
		})

		var _ = It("return errors if not IP addresses returned by IPAM", func() {
			calicoFakeCfg, tearDown, err := prepareCalicoConfig(tempDir, calicoConfig)
			Expect(err).ToNot(HaveOccurred())
			defer tearDown()
			tvc := newTestVarConfigurer()
			tec := NewEnvConfigurer(tvc, calicoFakeCfg)
			_, err = GetIPFromIPAM(tec, ipamExecAddNoIPs)
			Expect(err).To(HaveOccurred())
		})

		var _ = It("return error if cannot set the environment", func() {
			tvce := newTestVarConfigurerErr()
			tec := NewEnvConfigurer(tvce, "")
			_, err := GetIPFromIPAM(tec, nil)
			Expect(err).To(HaveOccurred())
		})

		var _ = It("return error if IPAM plugin returned error", func() {
			calicoFakeCfg, tearDown, err := prepareCalicoConfig(tempDir, calicoConfig)
			Expect(err).ToNot(HaveOccurred())
			defer tearDown()
			tvc := newTestVarConfigurer()
			tec := NewEnvConfigurer(tvc, calicoFakeCfg)

			_, err = GetIPFromIPAM(tec, ipamExecAddErr)
			Expect(err).To(HaveOccurred())
		})

		var _ = It("return error if IPAM plugin response is malformed", func() {
			calicoFakeCfg, tearDown, err := prepareCalicoConfig(tempDir, calicoConfig)
			Expect(err).ToNot(HaveOccurred())
			defer tearDown()
			tvc := newTestVarConfigurer()
			tec := NewEnvConfigurer(tvc, calicoFakeCfg)

			_, err = GetIPFromIPAM(tec, ipamExecAddBadResponse)
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("ReleaseIPFromIPAM() should", func() {
		var _ = It("return no error", func() {
			calicoFakeCfg, tearDown, err := prepareCalicoConfig(tempDir, calicoConfig)
			Expect(err).ToNot(HaveOccurred())
			defer tearDown()
			tvc := newTestVarConfigurer()
			tec := NewEnvConfigurer(tvc, calicoFakeCfg)
			err = ReleaseIPFromIPAM(tec, ipamExecDel)
			Expect(err).ToNot(HaveOccurred())
		})

		var _ = It("return error if cannot set the environment", func() {
			tvce := newTestVarConfigurerErr()
			tec := NewEnvConfigurer(tvce, "")
			err := ReleaseIPFromIPAM(tec, ipamExecDel)
			Expect(err).To(HaveOccurred())
		})

		var _ = It("return error if ipam ExecDel returns error", func() {
			calicoFakeCfg, tearDown, err := prepareCalicoConfig(tempDir, calicoConfig)
			Expect(err).ToNot(HaveOccurred())
			defer tearDown()
			tvc := newTestVarConfigurer()
			tec := NewEnvConfigurer(tvc, calicoFakeCfg)
			err = ReleaseIPFromIPAM(tec, ipamExecDelErr)
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("getInterface() should", func() {
		var _ = It("return no error if interface is found", func() {
			addrGetterMock := interfaceAddressGetterMock{}
			ifName, err := getInterface(ifList, internalIP, &addrGetterMock, logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			Expect(ifName).To(Equal(testInterfacefName))
		})

		var _ = It("return error if master interface is not found", func() {
			addrGetterMock := interfaceAddressGetterMock{}
			_, err := getInterface(ifList, "42.42.42.42", &addrGetterMock, logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})

		var _ = It("return error if address getter returns error", func() {
			addrGetterMock := interfaceAddressGetterMockErr{}
			_, err := getInterface(ifList, internalIP, &addrGetterMock, logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("NewOsVariableConfigurer() should", func() {
		var _ = It("return no error", func() {
			ovc := NewOsVariableConfigurer()
			Expect(ovc).ToNot(BeNil())

			testEnvKey := "TEST_KEY"
			testEnvVal := "TEST_VAL"
			t := testing.T{}
			t.Setenv(testEnvKey, "dummyVal")

			err := ovc.setenv(testEnvKey, testEnvVal)
			Expect(err).ToNot(HaveOccurred())

			val := ovc.getenv(testEnvKey)
			Expect(val).To(Equal(testEnvVal))

			err = os.Unsetenv(testEnvKey)
			Expect(err).ToNot(HaveOccurred())
		})
	})

	var _ = Context("WaitForCalicoConfig() should", func() {
		var _ = It("return error if file does not exist after 1 second", func() {
			fs := &FakeFilesystem{
				Dirs: []string{
					"etc/cni/net.d/",
				},
			}
			_, tearDown, err := fs.Use(tempDir)
			Expect(err).ToNot(HaveOccurred())
			defer tearDown()
			watcher, err := NewCalicoWatcher(time.Microsecond*20, filepath.Join(tempDir, types.DefaultCalicoConfig), fsnotify.NewWatcher)
			Expect(err).ToNot(HaveOccurred())
			err = WaitFor(watcher)
			Expect(err).To(HaveOccurred())
		})

		var _ = It("return no error if file exist", func() {
			calicoFakeCfg, tearDown, err := prepareCalicoConfig(tempDir, calicoConfig)
			Expect(err).ToNot(HaveOccurred())
			defer tearDown()
			watcher, err := NewCalicoWatcher(time.Second, calicoFakeCfg, fsnotify.NewWatcher)
			Expect(err).ToNot(HaveOccurred())
			err = WaitFor(watcher)
			Expect(err).ToNot(HaveOccurred())
		})

		var _ = It("return no error if file is created after some time", func() {
			configPath := filepath.Join(tempDir, types.DefaultCalicoConfig)
			err := os.MkdirAll(filepath.Dir(configPath), 0755)
			Expect(err).ToNot(HaveOccurred())
			check_done := false
			spin_done := false
			watcher, err := NewCalicoWatcher(0, configPath, fsnotify.NewWatcher)
			Expect(err).ToNot(HaveOccurred())
			go func() {
				defer GinkgoRecover()
				spin_done = true
				err := WaitFor(watcher)
				Expect(err).ToNot(HaveOccurred())
				check_done = true
			}()
			// wait until goroutine is created
			Eventually(func() bool {
				return spin_done
			}).Should(BeTrue())
			f, err := os.Create(configPath)
			Expect(err).ToNot(HaveOccurred())

			_, err = f.WriteString(calicoConfig)
			Expect(err).ToNot(HaveOccurred())
			f.Close()

			Eventually(func() bool {
				return check_done
			}, "1s").Should(BeTrue())
		})
	})

	var _ = Context("getCommandFromPod() should", func() {
		var _ = It("return error nil if no pods are in the pod slice", func() {
			pods := &v1.PodList{}
			res := getCommandFromPod(pods, "", "")
			Expect(res).To(BeNil())
		})
	})

	var _ = Context("VerifiedFilePath() should", func() {
		var _ = It("return no error with log file name that does not exist in allowed dir", func() {
			logDir := "/var/log/infraagent"
			logFile := "/var/log/infraagent/infraagent.log"
			fs := &FakeFilesystem{
				Dirs: []string{
					logDir,
				},
			}
			_, tearDown, err := fs.Use(tempDir)
			Expect(err).ToNot(HaveOccurred())
			defer tearDown()
			actualFilePath, err := VerifiedFilePath(filepath.Join(tempDir, logFile), filepath.Join(tempDir, logDir))
			Expect(err).NotTo(HaveOccurred())
			Expect(actualFilePath).To(Equal(filepath.Join(tempDir, logFile)))
		})
		var _ = It("return no error with log file name that already exists in allowed dir", func() {
			logDir := "/var/log/infraagent"
			logFile := "/var/log/infraagent/infraagent.log"
			fs := &FakeFilesystem{
				Dirs: []string{
					logDir,
				},
				Files: map[string][]byte{
					logFile: []byte(""),
				},
			}
			_, tearDown, err := fs.Use(tempDir)
			Expect(err).ToNot(HaveOccurred())
			defer tearDown()
			actualFilePath, err := VerifiedFilePath(filepath.Join(tempDir, logFile), filepath.Join(tempDir, logDir))
			Expect(err).NotTo(HaveOccurred())
			Expect(actualFilePath).To(Equal(filepath.Join(tempDir, logFile)))
		})
		var _ = It("return error with a log file that is not in the allowed dir", func() {
			logDir := "/var/log/infraagent"
			logFile := "/var/log/anotherDir/infraagent.log"
			fs := &FakeFilesystem{
				Dirs: []string{
					logDir,
					"/var/log/anotherDir",
				},
				Files: map[string][]byte{
					logFile: []byte(""),
				},
			}
			_, tearDown, err := fs.Use(tempDir)
			Expect(err).NotTo(HaveOccurred())
			defer tearDown()
			actualFilePath, err := VerifiedFilePath(filepath.Join(tempDir, logFile), filepath.Join(tempDir, logDir))
			Expect(err).To(HaveOccurred())
			Expect(actualFilePath).To(Equal(""))
		})
		var _ = It("return error with a log file with symlink outside of allowed dir", func() {
			logDir := "/var/log/infraagent"
			logFile := "/var/log/infraagent/infraagent.log"
			otherFile := "/var/log/anotherDir/infraagent.log"
			fs := &FakeFilesystem{
				Dirs: []string{
					logDir,
					"/var/log/anotherDir",
				},
				Files: map[string][]byte{
					otherFile: []byte(""),
				},
				Symlinks: map[string]string{
					logFile: "../anotherDir/infraagent.log",
				},
			}
			_, tearDown, err := fs.Use(tempDir)
			Expect(err).NotTo(HaveOccurred())
			defer tearDown()
			actualFilePath, err := VerifiedFilePath(filepath.Join(tempDir, logFile), filepath.Join(tempDir, logDir))
			Expect(err).To(HaveOccurred())
			Expect(actualFilePath).To(Equal(""))
		})
		var _ = It("return no error with a log file with symlink inside the allowed dir", func() {
			logDir := "/var/log/infraagent"
			logFile := "/var/log/infraagent/infraagent.log"
			otherFile := "/var/log/infraagent/otherfile.log"
			fs := &FakeFilesystem{
				Dirs: []string{
					logDir,
				},
				Files: map[string][]byte{
					otherFile: []byte(""),
				},
				Symlinks: map[string]string{
					logFile: "otherfile.log",
				},
			}
			_, tearDown, err := fs.Use(tempDir)
			Expect(err).NotTo(HaveOccurred())
			defer tearDown()
			actualFilePath, err := VerifiedFilePath(filepath.Join(tempDir, logFile), filepath.Join(tempDir, logDir))
			Expect(err).NotTo(HaveOccurred())
			Expect(actualFilePath).To(Equal(filepath.Join(tempDir, otherFile)))
		})
	})
	var _ = Context("CheckGrpcServerStatus() should", func() {
		var _ = It("return error if gRPC dial fails", func() {
			_, err := CheckGrpcServerStatus("", logrus.NewEntry(logrus.New()), fakeGrpcDialErr)
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if health server returns error", func() {
			getHealthServerResponseFunc = fakeGetHealthServerResponseErr
			_, err := CheckGrpcServerStatus("", logrus.NewEntry(logrus.New()), fakeGrpcDial)
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			getHealthServerResponseFunc = fakeGetHealthServerResponse
			_, err := CheckGrpcServerStatus("", logrus.NewEntry(logrus.New()), fakeGrpcDial)
			Expect(err).ToNot(HaveOccurred())
		})
	})
	var _ = Context("NewGrpcWatcher() should", func() {
		var _ = It("return new GrpcWatcher", func() {
			watcher := NewGrpcWatcher(time.Microsecond, time.Microsecond, "", fakeGrpcDial, fakeCheckHealth)
			Expect(watcher).ToNot(BeNil())
		})
	})
	var _ = Context("GrpcWatcher.initialCheck() should", func() {
		var _ = It("return true if fakeCheckHealth returns true", func() {
			watcher := NewGrpcWatcher(time.Microsecond, time.Microsecond, "", fakeGrpcDial, fakeCheckHealth)
			status := watcher.initialCheck()
			Expect(status).To(BeTrue())
		})
	})
	var _ = Context("GrpcWatcher.getChannels() should", func() {
		var _ = It("return 3 channels", func() {
			watcher := NewGrpcWatcher(time.Microsecond, time.Microsecond, "", fakeGrpcDial, fakeCheckHealth)
			done, quit, errors := watcher.getChannels()
			Expect(done).ToNot(BeNil())
			Expect(quit).ToNot(BeNil())
			Expect(errors).ToNot(BeNil())
		})
	})
	var _ = Context("GrpcWatcher.getTimeout() should", func() {
		var _ = It("return timeout", func() {
			sourceTimeout := time.Microsecond * 2
			watcher := NewGrpcWatcher(sourceTimeout, time.Microsecond, "", fakeGrpcDial, fakeCheckHealth)
			resultTimeout := watcher.getTimeout()
			Expect(resultTimeout).To(Equal(sourceTimeout))
		})
	})
	var _ = Context("GrpcWatcher.addWatchedResources() should", func() {
		var _ = It("return nil", func() {
			watcher := NewGrpcWatcher(time.Millisecond, time.Microsecond, "", fakeGrpcDial, fakeCheckHealth)
			result := watcher.addWatchedResources()
			Expect(result).To(BeNil())
		})
	})
	var _ = Context("GrpcWatcher.close() should", func() {
		var _ = It("return nil", func() {
			watcher := NewGrpcWatcher(time.Millisecond, time.Microsecond, "", fakeGrpcDial, fakeCheckHealth)
			result := watcher.close()
			Expect(result).To(BeNil())
		})
	})
	var _ = Context("GrpcWatcher.handleEvents() should", func() {
		var _ = It("return true on done channel if grpc server is serving", func() {
			watcher := NewGrpcWatcher(time.Millisecond, time.Microsecond, "", fakeGrpcDial, fakeCheckHealth)
			done, _, _ := watcher.getChannels()
			go watcher.handleEvents()
			result := <-done
			Expect(result).To(BeTrue())
		})
		var _ = It("exit on quit signal", func() {
			watcher := NewGrpcWatcher(time.Second, time.Microsecond, "", fakeGrpcDial, fakeCheckHealthErr)
			_, quit, errors := watcher.getChannels()
			go func() {
				watcher.handleEvents()
			}()
			quit <- true
			err := <-errors
			Expect(err).To(HaveOccurred())
		})
	})
	var _ = Context("NewCalicoWatcher() should", func() {
		var _ = It("return new CalicoWatcher", func() {
			watcher, err := NewCalicoWatcher(time.Microsecond, "", fakeNewFsWatcher)
			Expect(watcher).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return error if cannot create filesystem watcher", func() {
			watcher, err := NewCalicoWatcher(time.Microsecond, "", fakeNewFsWatcherErr)
			Expect(watcher).To(BeNil())
			Expect(err).To(HaveOccurred())
		})
	})
	var _ = Context("WaitFor() should", func() {
		var _ = It("return error if cannot add resources to watch", func() {
			watcher := newFakeWatcher(fakeAddWatchedResourcesErr, time.Microsecond)
			Expect(watcher).ToNot(BeNil())
			err := WaitFor(watcher)
			Expect(err).To(HaveOccurred())
		})
	})
	var _ = Context("processEvents() should", func() {
		var _ = It("return error if false received on done channel", func() {
			watcher := newFakeWatcher(fakeAddWatchedResources, time.Second)
			Expect(watcher).ToNot(BeNil())
			done, _, _ := watcher.getChannels()
			var err error
			finished := make(chan bool)
			go func() {
				err = processEvents(watcher)
				finished <- true
			}()
			done <- false
			<-finished
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if false received on done channel on infinite timeout", func() {
			watcher := newFakeWatcher(fakeAddWatchedResources, 0)
			Expect(watcher).ToNot(BeNil())
			done, _, _ := watcher.getChannels()
			var err error
			finished := make(chan bool)
			go func() {
				err = processEvents(watcher)
				finished <- true
			}()
			done <- false
			<-finished
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error if true received on done channel", func() {
			watcher := newFakeWatcher(fakeAddWatchedResources, time.Second)
			Expect(watcher).ToNot(BeNil())
			done, _, _ := watcher.getChannels()
			var err error
			finished := make(chan bool)
			go func() {
				err = processEvents(watcher)
				finished <- true
			}()
			done <- true
			<-finished
			Expect(err).ToNot(HaveOccurred())
		})
	})
	var _ = Context("CalicoWatcher.handleEvents() should", func() {
		var _ = It("return error on channel error if error occurred in fsWatcher", func() {
			watcher, err := NewCalicoWatcher(time.Second, "", fsnotify.NewWatcher)
			Expect(err).ToNot(HaveOccurred())
			go func() {
				_ = WaitFor(watcher)
			}()
			watcher.fsWatcher.Errors <- fmt.Errorf("Fake fsWatcher error")
			err = <-watcher.errors
			Expect(err).To(HaveOccurred())
		})
	})
})

type addrMock struct {
	name    string
	address string
}

func (am *addrMock) Network() string {
	return am.name
}
func (am *addrMock) String() string {
	return am.address
}

type interfaceAddressGetterMock struct{}

func (g *interfaceAddressGetterMock) GetAddr(ifc net.Interface) ([]net.Addr, error) {
	addr := addrMock{
		name:    "dummyIf",
		address: internalIP,
	}
	addrSlice := []net.Addr{}
	addrSlice = append(addrSlice, &addr)
	return addrSlice, nil
}

type interfaceAddressGetterMockErr struct{}

func (g *interfaceAddressGetterMockErr) GetAddr(ifc net.Interface) ([]net.Addr, error) {
	return nil, errors.New("Fake error")
}

type testVarConfigurer struct {
	t testing.T
}

func (tvc *testVarConfigurer) getenv(key string) string {
	return os.Getenv(key)
}

func (tvc *testVarConfigurer) setenv(key, value string) error {
	tvc.t.Setenv(key, value)
	return nil
}
func (tvc *testVarConfigurer) unsetenv(key string) error {
	return nil
}

func newTestVarConfigurer() variableConfigurer {
	return &testVarConfigurer{
		t: testing.T{},
	}
}

type testVarConfigurerErr struct{}

func (tvce *testVarConfigurerErr) getenv(key string) string {
	return ""
}

func (tvce *testVarConfigurerErr) setenv(key, value string) error {
	return errors.New("Fake setenv error")
}

func (tvce *testVarConfigurerErr) unsetenv(key string) error {
	return errors.New("Fake unsetenv error")
}
func newTestVarConfigurerErr() variableConfigurer {
	return &testVarConfigurerErr{}
}

func ipamExecAdd(plugin string, netconf []byte) (cniTypes.Result, error) {
	var resp cni40.Result
	err := json.Unmarshal(([]byte)(ipamExecResp), &resp)
	Expect(err).ToNot(HaveOccurred())
	return &resp, nil
}

func ipamExecAddNoIPs(plugin string, netconf []byte) (cniTypes.Result, error) {
	var resp cni40.Result
	err := json.Unmarshal(([]byte)(ipamExecRespNoIPs), &resp)
	Expect(err).ToNot(HaveOccurred())
	return &resp, nil
}

func ipamExecAddErr(plugin string, netconf []byte) (cniTypes.Result, error) {
	return nil, errors.New("Fake IPAM ExecAdd error")
}

func ipamExecAddBadResponse(plugin string, netconf []byte) (cniTypes.Result, error) {
	return &cniv1.Result{}, nil
}

func ipamExecDel(plugin string, netconf []byte) error {
	return nil
}

func ipamExecDelErr(plugin string, netconf []byte) error {
	return errors.New("Fake ipam.ExecDel error")
}

func prepareConfig(tempDir, configDir, configName, configData string) (string, func(), error) {
	configPath := filepath.Join(configDir, configName)
	fs := &FakeFilesystem{
		Dirs: []string{
			configDir,
		},
		Files: map[string][]byte{
			configPath: []byte(configData),
		},
	}
	tempRoot, tearDown, err := fs.Use(tempDir)
	if err != nil {
		return "", nil, err
	}

	fakeConfigPath := filepath.Join(tempRoot, configPath)
	return fakeConfigPath, tearDown, nil
}

func prepareCalicoConfig(tempDir string, configData string) (string, func(), error) {
	return prepareConfig(tempDir, "etc/cni/net.d/", "10-calico.conflist", configData)
}

func prepareKubeConfig(tempDir string, configData string) (string, func(), error) {
	return prepareConfig(tempDir, ".kube/", "config", configData)
}

// FakeFilesystem allows to setup isolated fake files structure used for the tests.
type FakeFilesystem struct {
	RootDir  string
	Dirs     []string
	Files    map[string][]byte
	Symlinks map[string]string
}

// Use function creates entire files structure and returns tempRoot dir and a function to tear it down.
// Example usage:
//
//	tempRoot, tearDown := fs.Use()
//	defer tearDown()
func (fs *FakeFilesystem) Use(tmpDir string) (string, func(), error) {
	// create the new fake fs root dir in tmpDir
	fs.RootDir = tmpDir

	for _, dir := range fs.Dirs {
		err := os.MkdirAll(filepath.Join(fs.RootDir, dir), 0755)
		if err != nil {
			return "", nil, err
		}

	}
	for filename, body := range fs.Files {
		err := os.WriteFile(filepath.Join(fs.RootDir, filename), body, 0600)
		if err != nil {
			return "", nil, err
		}

	}

	for link, target := range fs.Symlinks {
		if err := os.Symlink(target, filepath.Join(fs.RootDir, link)); err != nil {
			return "", nil, err
		}

	}

	return tmpDir, func() {
		// remove temporary fake fs
		err := os.RemoveAll(fs.RootDir)
		if err != nil {
			panic(fmt.Errorf("error tearing down fake filesystem: %s", err.Error()))
		}
	}, nil
}

func fakeGrpcDial(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	return grpc.DialContext(context.TODO(), "foo.bar:54321", grpc.WithTransportCredentials(insecure.NewCredentials()))
}

func fakeGrpcDialErr(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	return nil, errors.New("Fake error on grpcDial")
}

func fakeGetHealthServerResponse(conn *grpc.ClientConn) (*healthpb.HealthCheckResponse, error) {
	return &healthpb.HealthCheckResponse{}, nil
}

func fakeGetHealthServerResponseErr(conn *grpc.ClientConn) (*healthpb.HealthCheckResponse, error) {
	return nil, fmt.Errorf("Fake error on getHealthServerResponse")
}

func fakeCheckHealth(target string, log *logrus.Entry, grpcDial grpcDialType) (bool, error) {
	return true, nil
}

func fakeCheckHealthErr(target string, log *logrus.Entry, grpcDial grpcDialType) (bool, error) {
	return false, fmt.Errorf("Fake error on checkHealth")
}

func fakeNewFsWatcher() (*fsnotify.Watcher, error) {
	return &fsnotify.Watcher{}, nil
}
func fakeNewFsWatcherErr() (*fsnotify.Watcher, error) {
	return nil, fmt.Errorf("Fake error on newFsWatcher")
}

type fakeWatcher struct {
	addWatchResFunc func() error
	done            chan bool
	quit            chan bool
	errors          chan error
	timeout         time.Duration
}

func (fs *fakeWatcher) handleEvents() {
	<-fs.quit
	fs.errors <- fmt.Errorf("quiting")
}

func (fs *fakeWatcher) initialCheck() bool {
	return false
}

func (fs *fakeWatcher) getChannels() (chan bool, chan bool, chan error) {
	return fs.done, fs.quit, fs.errors
}

func (fs *fakeWatcher) getTimeout() time.Duration {
	return fs.timeout
}

func (fs *fakeWatcher) addWatchedResources() error {
	return fs.addWatchResFunc()
}

func (fs *fakeWatcher) close() error {
	return nil
}

func newFakeWatcher(addResFunc func() error, timeout time.Duration) *fakeWatcher {
	return &fakeWatcher{
		addWatchResFunc: addResFunc,
		done:            make(chan bool),
		quit:            make(chan bool),
		errors:          make(chan error),
		timeout:         timeout,
	}
}

func fakeAddWatchedResources() error {
	return nil
}

func fakeAddWatchedResourcesErr() error {
	return fmt.Errorf("Fake error on addWatchedResources")
}
