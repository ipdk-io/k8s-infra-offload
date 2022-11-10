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

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"errors"
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/ipdk-io/k8s-infra-offload/pkg/mock_proto"
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/proto"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"gopkg.in/tomb.v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

const (
	nodeListString = `{"metadata":{"resourceVersion":"3188299"},"items":[{"metadata":{"name":"dummyNode","uid":"4c1f6487-99e8-4860-8534-7df51b6a682c","resourceVersion":"3188070","creationTimestamp":"2022-07-08T13:44:51Z","labels":{"beta.kubernetes.io/arch":"amd64","beta.kubernetes.io/os":"linux","kubernetes.io/arch":"amd64","kubernetes.io/hostname":"dummyNode","kubernetes.io/os":"linux","node-role.kubernetes.io/control-plane":"","node.kubernetes.io/exclude-from-external-load-balancers":""},"annotations":{"kubeadm.alpha.kubernetes.io/cri-socket":"unix:///var/run/containerd/containerd.sock","node.alpha.kubernetes.io/ttl":"0","projectcalico.org/IPv4Address":"10.244.0.7/24","projectcalico.org/IPv4IPIPTunnelAddr":"10.244.0.1","volumes.kubernetes.io/controller-managed-attach-detach":"true"},"managedFields":[{"manager":"kubelet","operation":"Update","apiVersion":"v1","time":"2022-07-08T13:44:51Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{".":{},"f:volumes.kubernetes.io/controller-managed-attach-detach":{}},"f:labels":{".":{},"f:beta.kubernetes.io/arch":{},"f:beta.kubernetes.io/os":{},"f:kubernetes.io/arch":{},"f:kubernetes.io/hostname":{},"f:kubernetes.io/os":{}}}}},{"manager":"kubeadm","operation":"Update","apiVersion":"v1","time":"2022-07-08T13:44:56Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{"f:kubeadm.alpha.kubernetes.io/cri-socket":{}},"f:labels":{"f:node-role.kubernetes.io/control-plane":{},"f:node.kubernetes.io/exclude-from-external-load-balancers":{}}}}},{"manager":"kube-controller-manager","operation":"Update","apiVersion":"v1","time":"2022-07-08T13:45:10Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{"f:node.alpha.kubernetes.io/ttl":{}}},"f:spec":{"f:podCIDR":{},"f:podCIDRs":{".":{},"v:\"10.244.0.0/24\"":{}}}}},{"manager":"Go-http-client","operation":"Update","apiVersion":"v1","time":"2022-07-08T13:46:55Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{"f:projectcalico.org/IPv4Address":{},"f:projectcalico.org/IPv4IPIPTunnelAddr":{}}}},"subresource":"status"},{"manager":"kubelet","operation":"Update","apiVersion":"v1","time":"2022-07-11T07:17:49Z","fieldsType":"FieldsV1","fieldsV1":{"f:status":{"f:conditions":{"k:{\"type\":\"DiskPressure\"}":{"f:lastHeartbeatTime":{}},"k:{\"type\":\"MemoryPressure\"}":{"f:lastHeartbeatTime":{}},"k:{\"type\":\"PIDPressure\"}":{"f:lastHeartbeatTime":{}},"k:{\"type\":\"Ready\"}":{"f:lastHeartbeatTime":{},"f:lastTransitionTime":{},"f:message":{},"f:reason":{},"f:status":{}}},"f:images":{}}},"subresource":"status"}]},"spec":{"podCIDR":"10.244.0.0/24","podCIDRs":["10.244.0.0/24"]},"status":{"capacity":{"cpu":"88","ephemeral-storage":"960847604Ki","hugepages-1Gi":"0","hugepages-2Mi":"2Gi","memory":"131695828Ki","pods":"110"},"allocatable":{"cpu":"88","ephemeral-storage":"885517150381","hugepages-1Gi":"0","hugepages-2Mi":"2Gi","memory":"129496276Ki","pods":"110"},"conditions":[{"type":"MemoryPressure","status":"False","lastHeartbeatTime":"2022-07-25T12:21:02Z","lastTransitionTime":"2022-07-08T13:44:49Z","reason":"KubeletHasSufficientMemory","message":"kubelet has sufficient memory available"},{"type":"DiskPressure","status":"False","lastHeartbeatTime":"2022-07-25T12:21:02Z","lastTransitionTime":"2022-07-08T13:44:49Z","reason":"KubeletHasNoDiskPressure","message":"kubelet has no disk pressure"},{"type":"PIDPressure","status":"False","lastHeartbeatTime":"2022-07-25T12:21:02Z","lastTransitionTime":"2022-07-08T13:44:49Z","reason":"KubeletHasSufficientPID","message":"kubelet has sufficient PID available"},{"type":"Ready","status":"True","lastHeartbeatTime":"2022-07-25T12:21:02Z","lastTransitionTime":"2022-07-08T13:44:57Z","reason":"KubeletReady","message":"kubelet is posting ready status. AppArmor enabled"}],"addresses":[{"type":"InternalIP","address":"192.168.111.66"},{"type":"Hostname","address":"dummyNode"}],"daemonEndpoints":{"kubeletEndpoint":{"Port":10250}},"nodeInfo":{"machineID":"77094b51073843e5acb5c3cdd16c909e","systemUUID":"30726035-e8ed-ea11-ba6b-a4bf01644732","bootID":"de767a54-9900-4e24-8514-8c4cbf817213","kernelVersion":"5.4.0-121-generic","osImage":"Ubuntu 20.04.4 LTS","containerRuntimeVersion":"containerd://1.5.11","kubeletVersion":"v1.24.0","kubeProxyVersion":"v1.24.0","operatingSystem":"linux","architecture":"amd64"},"images":[{"names":["docker.io/calico/cni@sha256:26802bb7714fda18b93765e908f2d48b0230fd1c620789ba2502549afcde4338","docker.io/calico/cni:v3.23.1"],"sizeBytes":110500425},{"names":["k8s.gcr.io/etcd@sha256:13f53ed1d91e2e11aac476ee9a0269fdda6cc4874eba903efd40daf50c55eee5","k8s.gcr.io/etcd:3.5.3-0"],"sizeBytes":102143581},{"names":["docker.io/calico/node@sha256:d2c1613ef26c9ad43af40527691db1f3ad640291d5e4655ae27f1dd9222cc380","docker.io/calico/node:v3.23.1"],"sizeBytes":76574475},{"names":["docker.io/calico/apiserver@sha256:231b782c7d464bd59b416033e28eae8b3ec2ff90d38ca718558430f67f3203fa","docker.io/calico/apiserver:v3.23.1"],"sizeBytes":76516308},{"names":["quay.io/tigera/operator@sha256:526c06f827200856fb1f5594cc3f7d23935674cf20c22330e8ab9a6ddc484c8d","quay.io/tigera/operator:v1.27.1"],"sizeBytes":60267159},{"names":["docker.io/library/nginx@sha256:10f14ffa93f8dedf1057897b745e5ac72ac5655c299dade0aa434c71557697ea","docker.io/library/nginx:latest"],"sizeBytes":56748232},{"names":["docker.io/calico/kube-controllers@sha256:e8b2af28f2c283a38b4d80436e2d2a25e70f2820d97d1a8684609d42c3973afb","docker.io/calico/kube-controllers:v3.23.1"],"sizeBytes":56361853},{"names":["docker.io/calico/typha@sha256:d58558013bce1387f40969f483f65b5178b4574a8c383c3e997768d6a0ffff34","docker.io/calico/typha:v3.23.1"],"sizeBytes":54003239},{"names":["docker.io/library/nginx@sha256:6fff55753e3b34e36e24e37039ee9eae1fe38a6420d8ae16ef37c92d1eb26699","docker.io/library/nginx:1.17"],"sizeBytes":51030575},{"names":["k8s.gcr.io/kube-proxy@sha256:c957d602267fa61082ab8847914b2118955d0739d592cc7b01e278513478d6a8","k8s.gcr.io/kube-proxy:v1.24.0"],"sizeBytes":39515042},{"names":["k8s.gcr.io/kube-apiserver@sha256:a04522b882e919de6141b47d72393fb01226c78e7388400f966198222558c955","k8s.gcr.io/kube-apiserver:v1.24.0"],"sizeBytes":33796127},{"names":["10.55.129.85:5000/infra-agent@sha256:f9f2ef413a30e37ea5f3ca8a5affbeb41c58b56b4a3f36ac22cf85143e5148a0","10.55.129.85:5000/k8s-p4-dataplane@sha256:f9f2ef413a30e37ea5f3ca8a5affbeb41c58b56b4a3f36ac22cf85143e5148a0","10.55.129.85:5000/infra-agent:latest","10.55.129.85:5000/k8s-p4-dataplane:latest"],"sizeBytes":32681228},{"names":["k8s.gcr.io/kube-controller-manager@sha256:df044a154e79a18f749d3cd9d958c3edde2b6a00c815176472002b7bbf956637","k8s.gcr.io/kube-controller-manager:v1.24.0"],"sizeBytes":31032816},{"names":["docker.io/wbitt/network-multitool@sha256:82a5ea955024390d6b438ce22ccc75c98b481bf00e57c13e9a9cc1458eb92652","docker.io/wbitt/network-multitool:latest"],"sizeBytes":24236758},{"names":["k8s.gcr.io/kube-scheduler@sha256:db842a7c431fd51db7e1911f6d1df27a7b6b6963ceda24852b654d2cd535b776","k8s.gcr.io/kube-scheduler:v1.24.0"],"sizeBytes":15488642},{"names":["k8s.gcr.io/coredns/coredns@sha256:5b6ec0d6de9baaf3e92d0f66cd96a25b9edbce8716f5f15dcd1a616b3abd590e","k8s.gcr.io/coredns/coredns:v1.8.6"],"sizeBytes":13585107},{"names":["docker.io/calico/pod2daemon-flexvol@sha256:5d5759fc6de1f6c09b95d36334d968fa074779120024c067a770cfb2af579670","docker.io/calico/pod2daemon-flexvol:v3.23.1"],"sizeBytes":8671600},{"names":["docker.io/leannet/k8s-netperf@sha256:dd79ca1b6ecefc1e5bd9301abff0cfdec25dce9cd4fb9a09ddf4e117aa5550cd","docker.io/leannet/k8s-netperf:latest"],"sizeBytes":6732296},{"names":["docker.io/library/busybox@sha256:3614ca5eacf0a3a1bcc361c939202a974b4902b9334ff36eb29ffe9011aaad83","docker.io/library/busybox:latest"],"sizeBytes":777536},{"names":["docker.io/library/busybox@sha256:ebadf81a7f2146e95f8c850ad7af8cf9755d31cdba380a8ffd5930fba5996095"],"sizeBytes":777101},{"names":["docker.io/library/busybox@sha256:d2b53584f580310186df7a2055ce3ff83cc0df6caacf1e3489bff8cf5d0af5d8"],"sizeBytes":777091},{"names":["k8s.gcr.io/pause@sha256:bb6ed397957e9ca7c65ada0db5c5d1c707c9c8afc80a94acbe69f3ae76988f0c","k8s.gcr.io/pause:3.7"],"sizeBytes":311278},{"names":["k8s.gcr.io/pause@sha256:927d98197ec1141a368550822d18fa1c60bdae27b78b0c004f705f548c07814f","k8s.gcr.io/pause:3.2"],"sizeBytes":299513}]}}]}`
	srvListString  = `{"metadata":{"resourceVersion":"3102"},"items":[{"metadata":{"name":"kubernetes","namespace":"default","uid":"5e1695b8-ca90-41af-ad7c-610efec9b7cb","resourceVersion":"210","creationTimestamp":"2022-07-26T12:30:51Z","labels":{"component":"apiserver","provider":"kubernetes"},"managedFields":[{"manager":"kube-apiserver","operation":"Update","apiVersion":"v1","time":"2022-07-26T12:30:51Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:labels":{".":{},"f:component":{},"f:provider":{}}},"f:spec":{"f:clusterIP":{},"f:internalTrafficPolicy":{},"f:ipFamilyPolicy":{},"f:ports":{".":{},"k:{\"port\":443,\"protocol\":\"TCP\"}":{".":{},"f:name":{},"f:port":{},"f:protocol":{},"f:targetPort":{}}},"f:sessionAffinity":{},"f:type":{}}}}]},"spec":{"ports":[{"name":"https","protocol":"TCP","port":443,"targetPort":6443}],"clusterIP":"10.96.0.1","clusterIPs":["10.96.0.1"],"type":"ClusterIP","sessionAffinity":"None","ipFamilies":["IPv4"],"ipFamilyPolicy":"SingleStack","internalTrafficPolicy":"Cluster"},"status":{"loadBalancer":{}}},{"metadata":{"name":"nginx-service","namespace":"default","uid":"f0ab5958-03c8-459b-84fe-148e35a8ad8d","resourceVersion":"2460","creationTimestamp":"2022-07-26T12:49:46Z","annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"annotations\":{},\"name\":\"nginx-service\",\"namespace\":\"default\"},\"spec\":{\"ports\":[{\"name\":\"name-of-service-port\",\"port\":80,\"protocol\":\"TCP\",\"targetPort\":\"http-web-svc\"}],\"selector\":{\"app.kubernetes.io/name\":\"proxy\"}}}\n"},"managedFields":[{"manager":"kubectl-client-side-apply","operation":"Update","apiVersion":"v1","time":"2022-07-26T12:49:46Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{".":{},"f:kubectl.kubernetes.io/last-applied-configuration":{}}},"f:spec":{"f:internalTrafficPolicy":{},"f:ports":{".":{},"k:{\"port\":80,\"protocol\":\"TCP\"}":{".":{},"f:name":{},"f:port":{},"f:protocol":{},"f:targetPort":{}}},"f:selector":{},"f:sessionAffinity":{},"f:type":{}}}}]},"spec":{"ports":[{"name":"name-of-service-port","protocol":"TCP","port":80,"targetPort":"http-web-svc"}],"selector":{"app.kubernetes.io/name":"proxy"},"clusterIP":"10.96.30.210","clusterIPs":["10.96.30.210"],"type":"ClusterIP","sessionAffinity":"None","ipFamilies":["IPv4"],"ipFamilyPolicy":"SingleStack","internalTrafficPolicy":"Cluster"},"status":{"loadBalancer":{}}},{"kind":"Service","apiVersion":"v1","metadata":{"name":"nginx-svc-cl","namespace":"default","uid":"99b626ee-1a89-44e7-91ae-6a702eb1add6","resourceVersion":"2378","creationTimestamp":"2022-08-01T08:36:55Z","annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"annotations\":{},\"name\":\"nginx-svc-cl\",\"namespace\":\"default\"},\"spec\":{\"externalIPs\":[\"1.2.3.42\"],\"ports\":[{\"name\":\"http\",\"port\":80,\"protocol\":\"TCP\",\"targetPort\":80}],\"selector\":{\"app\":\"nginx-cl\"}}}\n"}},"spec":{"ports":[{"name":"http","protocol":"TCP","port":80,"targetPort":80}],"selector":{"app":"nginx-cl"},"clusterIP":"10.98.247.229","clusterIPs":["10.98.247.229"],"type":"ClusterIP","externalIPs":["1.2.3.42"],"sessionAffinity":"None","ipFamilies":["IPv4"],"ipFamilyPolicy":"SingleStack","internalTrafficPolicy":"Cluster"},"status":{"loadBalancer":{}}},{"kind":"Service","apiVersion":"v1","metadata":{"name":"nginx-svc-np","namespace":"default","uid":"18524032-4e56-4d14-800a-29ca2476dc14","resourceVersion":"13002","creationTimestamp":"2022-08-01T09:58:00Z","annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"annotations\":{},\"name\":\"nginx-svc-np\",\"namespace\":\"default\"},\"spec\":{\"ports\":[{\"nodePort\":30080,\"port\":80,\"targetPort\":80}],\"selector\":{\"app\":\"nginx-np\"},\"type\":\"NodePort\"}}\n"}},"spec":{"ports":[{"protocol":"TCP","port":80,"targetPort":80,"nodePort":30080}],"selector":{"app":"nginx-np"},"clusterIP":"10.109.14.106","clusterIPs":["10.109.14.106"],"type":"NodePort","sessionAffinity":"None","externalTrafficPolicy":"Cluster","ipFamilies":["IPv4"],"ipFamilyPolicy":"SingleStack","internalTrafficPolicy":"Cluster"},"status":{"loadBalancer":{}}},{"kind":"Service","apiVersion":"v1","metadata":{"name":"nginx-svc-lb","namespace":"default","uid":"47392643-d502-4728-a62c-9e613e83a9a8","resourceVersion":"39797","creationTimestamp":"2022-08-01T13:22:49Z","annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"annotations\":{},\"name\":\"nginx-svc-lb\",\"namespace\":\"default\"},\"spec\":{\"clusterIP\":\"10.96.100.100\",\"ports\":[{\"port\":80,\"protocol\":\"TCP\",\"targetPort\":80}],\"selector\":{\"app\":\"nginx-lb\"},\"type\":\"LoadBalancer\"},\"status\":{\"loadBalancer\":{\"ingress\":[{\"ip\":\"192.0.2.127\"}]}}}\n"}},"spec":{"ports":[{"protocol":"TCP","port":80,"targetPort":80,"nodePort":30126}],"selector":{"app":"nginx-lb"},"clusterIP":"10.96.100.100","clusterIPs":["10.96.100.100"],"type":"LoadBalancer","sessionAffinity":"None","externalTrafficPolicy":"Cluster","ipFamilies":["IPv4"],"ipFamilyPolicy":"SingleStack","allocateLoadBalancerNodePorts":true,"internalTrafficPolicy":"Cluster"},"status":{"loadBalancer":{"ingress":[{"ip":"127.0.0.1"}]}}},{"kind":"Service","apiVersion":"v1","metadata":{"name":"nginx-svc-npB","namespace":"default","uid":"18524032-4e56-4d14-800a-29ca2476dc15","resourceVersion":"13002","creationTimestamp":"2022-08-01T09:58:00Z","annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Service\",\"metadata\":{\"annotations\":{},\"name\":\"nginx-svc-np\",\"namespace\":\"default\"},\"spec\":{\"ports\":[{\"nodePort\":30080,\"port\":80,\"targetPort\":80}],\"selector\":{\"app\":\"nginx-np\"},\"type\":\"NodePort\"}}\n"}},"spec":{"ports":[{"protocol":"TCP","port":80,"targetPort":80,"nodePort":30080}],"selector":{"app":"nginx-np"},"clusterIP":"10.109.14.106","clusterIPs":["10.109.14.106"],"type":"NodePort","sessionAffinity":"None","externalTrafficPolicy":"Cluster","ipFamilies":["IPv4"],"ipFamilyPolicy":"SingleStack","internalTrafficPolicy":"Cluster"},"status":{"loadBalancer":{}}}]}`
	epListString   = `{"metadata":{"resourceVersion":"3102"},"items":[{"metadata":{"name":"kubernetes","namespace":"default","uid":"e5df8985-8b70-440d-97ae-83a8a38c6c50","resourceVersion":"212","creationTimestamp":"2022-07-26T12:30:51Z","labels":{"endpointslice.kubernetes.io/skip-mirror":"true"},"managedFields":[{"manager":"kube-apiserver","operation":"Update","apiVersion":"v1","time":"2022-07-26T12:30:51Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:labels":{".":{},"f:endpointslice.kubernetes.io/skip-mirror":{}}},"f:subsets":{}}}]},"subsets":[{"addresses":[{"ip":"192.168.111.66"}],"ports":[{"name":"https","port":6443,"protocol":"TCP"}]}]},{"metadata":{"name":"nginx-service","namespace":"default","uid":"bd00dd32-64c8-4a36-8d9c-fa1743100587","resourceVersion":"2500","creationTimestamp":"2022-07-26T12:49:46Z","annotations":{"endpoints.kubernetes.io/last-change-trigger-time":"2022-07-26T12:50:00Z"},"managedFields":[{"manager":"kube-controller-manager","operation":"Update","apiVersion":"v1","time":"2022-07-26T12:50:00Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{".":{},"f:endpoints.kubernetes.io/last-change-trigger-time":{}}},"f:subsets":{}}}]},"subsets":[{"addresses":[{"ip":"10.244.0.28","nodeName":"dummyNode","targetRef":{"kind":"Pod","namespace":"default","name":"nginx","uid":"46b11a7f-bb3c-4c2c-9780-04da3fea7e0e"}}],"ports":[{"name":"name-of-service-port","port":80,"protocol":"TCP"}]}]},{"apiVersion": "v1","kind": "Endpoints","metadata": {"annotations": {"endpoints.kubernetes.io/last-change-trigger-time": "2022-08-01T08:36:55Z"},"creationTimestamp": "2022-08-01T08:36:55Z","name": "nginx-svc-cl","namespace": "default","resourceVersion": "2380","uid": "8de7b90c-5e02-45da-b8e1-e4dfdebfe04f"},"subsets": [{"addresses": [{"ip": "10.210.193.70","nodeName": "infratest","targetRef": {"kind": "Pod","name": "nginx-cl","namespace": "default","uid": "1b4aaa88-0d8a-4a1e-a4d9-3f5b2e14ac35"}}],"ports": [{"name": "http","port": 80,"protocol": "TCP"}]}]},{"apiVersion": "v1","kind": "Endpoints","metadata": {"annotations": {"endpoints.kubernetes.io/last-change-trigger-time": "2022-08-01T09:58:00Z"},"creationTimestamp": "2022-08-01T09:58:00Z","name": "nginx-svc-np","namespace": "default","resourceVersion": "13004","uid": "2ef245e6-7ca8-4dff-a3b3-ed228f7410fa"},"subsets": [{"addresses": [{"ip": "10.210.193.71","nodeName": "infratest","targetRef": {"kind": "Pod","name": "nginx-np","namespace": "default","uid": "9db2c098-283a-4827-83c0-961dd8345497"}}],"ports": [{"port": 80,"protocol": "TCP"}]}]},{"apiVersion": "v1","kind": "Endpoints","metadata": {"annotations": {"endpoints.kubernetes.io/last-change-trigger-time": "2022-08-01T13:22:49Z"},"creationTimestamp": "2022-08-01T13:22:49Z","name": "nginx-svc-lb","namespace": "default","resourceVersion": "39798","uid": "e794042d-3357-4c33-84a7-fa1fa6770c6a"},"subsets": [{"addresses": [{"ip": "10.210.193.72","nodeName": "infratest","targetRef": {"kind": "Pod","name": "nginx-lb","namespace": "default","uid": "8959ad46-cbe5-4450-97a7-813c0dec8509"}}],"ports": [{"port": 80,"protocol": "TCP"}]}]},{"apiVersion": "v1","kind": "Endpoints","metadata": {"annotations": {"endpoints.kubernetes.io/last-change-trigger-time": "2022-08-01T09:58:00Z"},"creationTimestamp": "2022-08-01T09:58:00Z","name": "nginx-svc-npA","namespace": "default","resourceVersion": "13004","uid": "2ef245e6-7ca8-4dff-a3b3-ed228f7410fb"},"subsets": [{"addresses": [{"ip": "10.210.193.71","nodeName": "infratest","targetRef": {"kind": "Pod","name": "nginx-np","namespace": "default","uid": "9db2c098-283a-4827-83c0-961dd8345497"}}],"ports": [{"port": 80,"protocol": "TCP"}]}]}]}`
	bufSize        = 1024 * 1024

	testNamespace = "default"
)

var (
	servicesList  *v1.ServiceList
	endpointsList *v1.EndpointsList
	nodeList      *v1.NodeList
	mockCrtl      *gomock.Controller
	mockClient    *mock_proto.MockInfraAgentClient
	listener      *bufconn.Listener
	fakeClient    *fake.Clientset
	testEnv       *envtest.Environment
	testEnvCfg    *rest.Config
	testEnvClient *kubernetes.Clientset
	svcTest       string
	epTest        string
)

func bufDialer(context.Context, string) (net.Conn, error) {
	return listener.Dial()
}

func TestServices(t *testing.T) {
	mockCrtl = gomock.NewController(t)
	mockClient = mock_proto.NewMockInfraAgentClient(mockCrtl)
	testEnv = &envtest.Environment{
		// CRDDirectoryPaths: []string{filepath.Join("..", "config", "crd", "bases")},
	}
	RegisterFailHandler(Fail)
	RunSpecs(t, "Services Test Suite")
}

var _ = BeforeSuite(func() {
	servicesList = &v1.ServiceList{}
	err := json.Unmarshal([]byte(srvListString), servicesList)
	Expect(err).ShouldNot(HaveOccurred())
	endpointsList = &v1.EndpointsList{}
	err = json.Unmarshal([]byte(epListString), endpointsList)
	Expect(err).ShouldNot(HaveOccurred())
	nodeList = &v1.NodeList{}
	err = json.Unmarshal([]byte(nodeListString), nodeList)
	Expect(err).ShouldNot(HaveOccurred())
	listener = bufconn.Listen(bufSize)
	//start testEnv
	testEnvCfg, err = testEnv.Start()
	testEnvClient = kubernetes.NewForConfigOrDie(testEnvCfg)
	Expect(err).ShouldNot(HaveOccurred())

	epTest = `apiVersion: v1
kind: Endpoints
metadata:
  name: my-service
  labels:
    test: test
subsets:
  - addresses:
    - ip: 192.0.2.42
ports:
  - port: 9376`

	svcTest = `apiVersion: v1
kind: Service
metadata:
  name: my-service
  labels:
    test: test
spec:
  ports:
  - protocol: TCP
    port: 80
    targetPort: 9376`
})

var _ = AfterSuite(func() {
	//stop testEnv
	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred())
	mockCrtl.Finish()
	listener.Close()
})

var _ = Describe("proxy", func() {
	var _ = BeforeEach(func() {
		grpcDial = func(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
			return grpc.DialContext(context.TODO(), "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
		}
		newInfraAgentClient = func(cc *grpc.ClientConn) proto.InfraAgentClient {
			return mockClient
		}
	})

	var _ = Context("NewServiceServer() should", func() {
		var _ = It("create new proxy server without error", func() {
			getK8sConfig = fakeGetK8sConfig
			newForConfig = fakeNewForConfig
			getNodeIP = fakeGetNodeIP
			types.NodeName = "dummyNode"
			server, err := NewServiceServer(logrus.NewEntry(logrus.StandardLogger()), NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger())), 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(server).NotTo(BeNil())
			Expect(server.(*serviceServer).nodeAddress).NotTo(BeEmpty())
			Expect(server.GetName()).To(Equal("services-server"))
		})

		var _ = It("return error if cannot get k8s config", func() {
			getK8sConfig = fakeGetK8sConfigErr
			types.NodeName = "dummyNode"
			_, err := NewServiceServer(logrus.NewEntry(logrus.StandardLogger()), NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger())), 0)
			Expect(err).Should(HaveOccurred())
		})

		var _ = It("return error if cannot get k8s client", func() {
			getK8sConfig = fakeGetK8sConfig
			newForConfig = fakeNewForConfigErr
			types.NodeName = "dummyNode"
			_, err := NewServiceServer(logrus.NewEntry(logrus.StandardLogger()), NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger())), 0)
			Expect(err).Should(HaveOccurred())
		})

		var _ = It("return error if cannot get node IP", func() {
			getK8sConfig = fakeGetK8sConfig
			newForConfig = fakeNewForConfig
			getNodeIP = fakeGetNodeIPErr
			types.NodeName = "dummyNode"
			_, err := NewServiceServer(logrus.NewEntry(logrus.StandardLogger()), NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger())), 0)
			Expect(err).Should(HaveOccurred())
		})
	})

	var _ = Context("Service proxy controller should", func() {
		var _ = It("return if cannot sync cache", func() {
			getK8sConfig = fakeGetK8sConfig
			newForConfig = fakeNewForConfig
			getNodeIP = fakeGetNodeIP
			waitForCacheSync = fakeWaitForCacheSyncFalse
			types.NodeName = "dummyNode"
			server, err := NewServiceServer(logrus.NewEntry(logrus.StandardLogger()), NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger())), 0)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(server).NotTo(BeNil())
			Expect(server.(*serviceServer).nodeAddress).NotTo(BeEmpty())
			Expect(server.GetName()).To(Equal("services-server"))

			testTomb := &tomb.Tomb{}
			go func() { _ = server.Start(testTomb) }()
			s := server.(*serviceServer)
			<-s.t.Dying()
			testTomb.Kill(fmt.Errorf("Fake kill"))
		})
		var _ = It("run add handlers without errors", func() {
			getK8sConfig = fakeGetK8sConfig
			newForConfig = fakeNewForConfig
			getNodeIP = fakeGetNodeIP
			waitForCacheSync = fakeWaitForCacheSync
			types.NodeName = "dummyNode"
			server, err := NewServiceServer(logrus.NewEntry(logrus.StandardLogger()), NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger())), 0)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(server).NotTo(BeNil())
			Expect(server.(*serviceServer).nodeAddress).NotTo(BeEmpty())
			Expect(server.GetName()).To(Equal("services-server"))

			var calls [](*gomock.Call)
			calls = append(calls, mockClient.EXPECT().NatTranslationAdd(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: true}, nil))
			gomock.InOrder(calls...)

			testTomb := &tomb.Tomb{}
			go func() { _ = server.Start(testTomb) }()

			// add handler test - service
			svc := decodeSvc(svcTest)
			Expect(svc).ToNot(BeNil())
			_, err = testEnvClient.CoreV1().Services("default").Create(context.TODO(), svc, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			time.Sleep(10 * time.Millisecond)
			// kill server
			testTomb.Kill(fmt.Errorf("Fake kill"))
		})

		var _ = It("run service del handlers without errors", func() {
			getK8sConfig = fakeGetK8sConfig
			newForConfig = fakeNewForConfig
			getNodeIP = fakeGetNodeIP
			waitForCacheSync = fakeWaitForCacheSync
			types.NodeName = "dummyNode"
			server, err := NewServiceServer(logrus.NewEntry(logrus.StandardLogger()), NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger())), 0)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(server).NotTo(BeNil())
			Expect(server.(*serviceServer).nodeAddress).NotTo(BeEmpty())
			Expect(server.GetName()).To(Equal("services-server"))

			var calls [](*gomock.Call)

			calls = append(calls, mockClient.EXPECT().NatTranslationAdd(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: true}, nil))

			gomock.InOrder(calls...)

			testTomb := &tomb.Tomb{}
			go func() { _ = server.Start(testTomb) }()

			svc := decodeSvc(svcTest)
			Expect(svc).ToNot(BeNil())
			err = testEnvClient.CoreV1().Services(testNamespace).Delete(context.TODO(), svc.Name, metav1.DeleteOptions{})
			Expect(err).ToNot(HaveOccurred())

			time.Sleep(10 * time.Millisecond)
			// kill server
			testTomb.Kill(fmt.Errorf("Fake kill"))
		})

		var _ = It("run endpoint add handlers without errors", func() {
			getK8sConfig = fakeGetK8sConfig
			newForConfig = fakeNewForConfig
			getNodeIP = fakeGetNodeIP
			waitForCacheSync = fakeWaitForCacheSync
			types.NodeName = "dummyNode"
			server, err := NewServiceServer(logrus.NewEntry(logrus.StandardLogger()), NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger())), 0)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(server).NotTo(BeNil())
			Expect(server.(*serviceServer).nodeAddress).NotTo(BeEmpty())
			Expect(server.GetName()).To(Equal("services-server"))

			var calls [](*gomock.Call)

			calls = append(calls, mockClient.EXPECT().NatTranslationAdd(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: true}, nil))
			calls = append(calls, mockClient.EXPECT().NatTranslationDelete(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: true}, nil))

			gomock.InOrder(calls...)

			testTomb := &tomb.Tomb{}
			go func() { _ = server.Start(testTomb) }()

			// add handler test - service
			svc := decodeSvc(svcTest)
			Expect(svc).ToNot(BeNil())
			ep := decodeEp(epTest)
			Expect(ep).ToNot(BeNil())
			_, err = testEnvClient.CoreV1().Services(testNamespace).Create(context.TODO(), svc, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())
			_, err = testEnvClient.CoreV1().Endpoints(testNamespace).Create(context.TODO(), ep, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())
			err = testEnvClient.CoreV1().Endpoints(testNamespace).Delete(context.TODO(), ep.Name, metav1.DeleteOptions{})
			Expect(err).ToNot(HaveOccurred())
			err = testEnvClient.CoreV1().Services(testNamespace).Delete(context.TODO(), svc.Name, metav1.DeleteOptions{})
			Expect(err).ToNot(HaveOccurred())

			time.Sleep(10 * time.Millisecond)
			// kill server
			testTomb.Kill(fmt.Errorf("Fake kill"))
		})

		var _ = It("run service update handlers without errors", func() {
			getK8sConfig = fakeGetK8sConfig
			newForConfig = fakeNewForConfig
			getNodeIP = fakeGetNodeIP
			waitForCacheSync = fakeWaitForCacheSync
			types.NodeName = "dummyNode"
			server, err := NewServiceServer(logrus.NewEntry(logrus.StandardLogger()), NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger())), 0)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(server).NotTo(BeNil())
			Expect(server.(*serviceServer).nodeAddress).NotTo(BeEmpty())
			Expect(server.GetName()).To(Equal("services-server"))

			var calls [](*gomock.Call)

			calls = append(calls, mockClient.EXPECT().NatTranslationAdd(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: true}, nil))
			calls = append(calls, mockClient.EXPECT().NatTranslationDelete(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: true}, nil))

			gomock.InOrder(calls...)

			testTomb := &tomb.Tomb{}
			go func() { _ = server.Start(testTomb) }()

			// add handler test - service
			svc := decodeSvc(svcTest)
			Expect(svc).ToNot(BeNil())
			ep := decodeEp(epTest)
			Expect(ep).ToNot(BeNil())

			currentSvc, err := testEnvClient.CoreV1().Services(testNamespace).Create(context.TODO(), svc, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())
			_, err = testEnvClient.CoreV1().Endpoints(testNamespace).Create(context.TODO(), ep, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			currentSvc.ObjectMeta.Labels["test"] = "modified"
			_, err = testEnvClient.CoreV1().Services(testNamespace).Update(context.TODO(), currentSvc, metav1.UpdateOptions{})
			Expect(err).ToNot(HaveOccurred())

			err = testEnvClient.CoreV1().Endpoints("default").Delete(context.TODO(), ep.Name, metav1.DeleteOptions{})
			Expect(err).ToNot(HaveOccurred())
			err = testEnvClient.CoreV1().Services("default").Delete(context.TODO(), svc.Name, metav1.DeleteOptions{})
			Expect(err).ToNot(HaveOccurred())

			time.Sleep(10 * time.Millisecond)
			// kill server
			testTomb.Kill(fmt.Errorf("Fake kill"))
		})

		var _ = It("run endpoint update handlers without errors", func() {
			getK8sConfig = fakeGetK8sConfig
			newForConfig = fakeNewForConfig
			getNodeIP = fakeGetNodeIP
			waitForCacheSync = fakeWaitForCacheSync
			types.NodeName = "dummyNode"
			server, err := NewServiceServer(logrus.NewEntry(logrus.StandardLogger()), NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger())), 0)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(server).NotTo(BeNil())
			Expect(server.(*serviceServer).nodeAddress).NotTo(BeEmpty())
			Expect(server.GetName()).To(Equal("services-server"))

			var calls [](*gomock.Call)

			calls = append(calls, mockClient.EXPECT().NatTranslationAdd(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: true}, nil))
			calls = append(calls, mockClient.EXPECT().NatTranslationDelete(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: true}, nil))

			gomock.InOrder(calls...)

			testTomb := &tomb.Tomb{}
			go func() { _ = server.Start(testTomb) }()

			// add handler test - service
			svc := decodeSvc(svcTest)
			Expect(svc).ToNot(BeNil())
			ep := decodeEp(epTest)
			Expect(ep).ToNot(BeNil())

			_, err = testEnvClient.CoreV1().Services(testNamespace).Create(context.TODO(), svc, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())
			currentEp, err := testEnvClient.CoreV1().Endpoints(testNamespace).Create(context.TODO(), ep, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			currentEp.ObjectMeta.Labels["test"] = "modified"
			_, err = testEnvClient.CoreV1().Endpoints(testNamespace).Update(context.TODO(), currentEp, metav1.UpdateOptions{})
			Expect(err).ToNot(HaveOccurred())

			err = testEnvClient.CoreV1().Endpoints(testNamespace).Delete(context.TODO(), ep.Name, metav1.DeleteOptions{})
			Expect(err).ToNot(HaveOccurred())
			err = testEnvClient.CoreV1().Services(testNamespace).Delete(context.TODO(), svc.Name, metav1.DeleteOptions{})
			Expect(err).ToNot(HaveOccurred())

			time.Sleep(10 * time.Millisecond)
			// kill server
			testTomb.Kill(fmt.Errorf("Fake kill"))
		})

		var _ = It("run add handler without errors when Manager fails", func() {
			getK8sConfig = fakeGetK8sConfig
			newForConfig = fakeNewForConfig
			getNodeIP = fakeGetNodeIP
			waitForCacheSync = fakeWaitForCacheSync
			types.NodeName = "dummyNode"
			server, err := NewServiceServer(logrus.NewEntry(logrus.StandardLogger()), newFakeNatServiceHandler(logrus.NewEntry(logrus.StandardLogger()), fakeNatTranslationErr, fakeNatTranslation), 0)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(server).NotTo(BeNil())
			Expect(server.(*serviceServer).nodeAddress).NotTo(BeEmpty())
			Expect(server.GetName()).To(Equal("services-server"))

			testTomb := &tomb.Tomb{}
			go func() { _ = server.Start(testTomb) }()

			// add handler test - service
			svc := decodeSvc(svcTest)
			Expect(svc).ToNot(BeNil())
			_, err = testEnvClient.CoreV1().Services(testNamespace).Create(context.TODO(), svc, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())
			err = testEnvClient.CoreV1().Services(testNamespace).Delete(context.TODO(), svc.Name, metav1.DeleteOptions{})
			Expect(err).ToNot(HaveOccurred())

			time.Sleep(10 * time.Millisecond)
			// kill server
			testTomb.Kill(fmt.Errorf("Fake kill"))
		})

		var _ = It("run add handler without errors when Manager fails", func() {
			getK8sConfig = fakeGetK8sConfig
			newForConfig = fakeNewForConfig
			getNodeIP = fakeGetNodeIP
			waitForCacheSync = fakeWaitForCacheSync
			types.NodeName = "dummyNode"
			server, err := NewServiceServer(logrus.NewEntry(logrus.StandardLogger()), newFakeNatServiceHandler(logrus.NewEntry(logrus.StandardLogger()), fakeNatTranslation, fakeNatTranslationErr), 0)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(server).NotTo(BeNil())
			Expect(server.(*serviceServer).nodeAddress).NotTo(BeEmpty())
			Expect(server.GetName()).To(Equal("services-server"))

			testTomb := &tomb.Tomb{}
			go func() { _ = server.Start(testTomb) }()

			// add handler test - service
			svc := decodeSvc(svcTest)
			Expect(svc).ToNot(BeNil())
			_, err = testEnvClient.CoreV1().Services(testNamespace).Create(context.TODO(), svc, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())
			time.Sleep(time.Second)
			err = testEnvClient.CoreV1().Services(testNamespace).Delete(context.TODO(), svc.Name, metav1.DeleteOptions{})
			Expect(err).ToNot(HaveOccurred())

			time.Sleep(10 * time.Millisecond)
			// kill server
			testTomb.Kill(fmt.Errorf("Fake kill"))
		})
	})
	var _ = Context("NewServiceServer() should", func() {
		var _ = It("return no error if key splitting failed", func() {
			getK8sConfig = fakeGetK8sConfig
			newForConfig = fakeNewForConfig
			getNodeIP = fakeGetNodeIP
			types.NodeName = "dummyNode"
			server, err := NewServiceServer(logrus.NewEntry(logrus.StandardLogger()), NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger())), 0)
			Expect(err).ToNot(HaveOccurred())
			Expect(server).NotTo(BeNil())
			Expect(server.(*serviceServer).nodeAddress).NotTo(BeEmpty())
			Expect(server.GetName()).To(Equal("services-server"))
			splitMetaNamespaceKey = fakeSplitMetaNamespaceKeyErr
			err = server.(*serviceServer).syncHandler("")
			Expect(err).ToNot(HaveOccurred())
		})
	})
})

var _ = Describe("NAT settings handler", func() {
	var _ = BeforeEach(func() {
		grpcDial = func(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
			return grpc.DialContext(context.TODO(), "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
		}
		newInfraAgentClient = func(cc *grpc.ClientConn) proto.InfraAgentClient {
			return mockClient
		}
		fakeClient = fake.NewSimpleClientset(nodeList, servicesList, endpointsList)
		newForConfig = func(c *rest.Config) (kubernetes.Interface, error) {
			return fakeClient, nil
		}
		getK8sConfig = func() (*rest.Config, error) { return &rest.Config{}, nil }
	})

	var _ = Context("Methods should run without errors", func() {
		var _ = It("NatTranslationAdd", func() {
			grpcCall := mockClient.EXPECT().NatTranslationAdd(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: true}, nil)
			gomock.InOrder(grpcCall)
			h := NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger()))
			err := h.NatTranslationAdd(&proto.NatTranslation{})
			Expect(err).ToNot(HaveOccurred())
		})

		var _ = It("SetSnatAddress", func() {
			grpcCall := mockClient.EXPECT().SetSnatAddress(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: true}, nil)
			gomock.InOrder(grpcCall)
			h := NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger()))
			err := h.SetSnatAddress("127.0.0.1")
			Expect(err).ToNot(HaveOccurred())
		})

		var _ = It("AddDelSnatPrefix", func() {
			grpcCall := mockClient.EXPECT().AddDelSnatPrefix(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: true}, nil)
			gomock.InOrder(grpcCall)
			h := NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger()))
			err := h.AddDelSnatPrefix("127.0.0.1", true)
			Expect(err).ToNot(HaveOccurred())
		})

		var _ = It("NatTranslationDelete", func() {
			grpcCall := mockClient.EXPECT().NatTranslationDelete(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: true}, nil)
			gomock.InOrder(grpcCall)
			h := NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger()))
			err := h.NatTranslationDelete(&proto.NatTranslation{})
			Expect(err).ToNot(HaveOccurred())
		})
	})

	var _ = Context("Methods should return error", func() {
		var _ = It("NatTranslationAdd - error reply from Manager", func() {
			grpcCall := mockClient.EXPECT().NatTranslationAdd(gomock.Any(), gomock.Any()).Return(nil, errors.New("Fake error"))
			gomock.InOrder(grpcCall)
			h := NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger()))
			err := h.NatTranslationAdd(&proto.NatTranslation{})
			Expect(err).To(HaveOccurred())
		})

		var _ = It("NatTranslationAdd - failure reply from Manager", func() {
			grpcCall := mockClient.EXPECT().NatTranslationAdd(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: false}, nil)
			gomock.InOrder(grpcCall)
			h := NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger()))
			err := h.NatTranslationAdd(&proto.NatTranslation{})
			Expect(err).To(HaveOccurred())
		})

		var _ = It("SetSnatAddress - failure reply from Manager", func() {
			grpcCall := mockClient.EXPECT().SetSnatAddress(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: false}, nil)
			gomock.InOrder(grpcCall)
			h := NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger()))
			err := h.SetSnatAddress("127.0.0.1")
			Expect(err).To(HaveOccurred())
		})

		var _ = It("AddDelSnatPrefix - failure reply from Manager", func() {
			grpcCall := mockClient.EXPECT().AddDelSnatPrefix(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: false}, nil)
			gomock.InOrder(grpcCall)
			h := NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger()))
			err := h.AddDelSnatPrefix("127.0.0.1", true)
			Expect(err).To(HaveOccurred())
		})

		var _ = It("NatTranslationDelete - failure reply from Manager", func() {
			grpcCall := mockClient.EXPECT().NatTranslationDelete(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: false}, nil)
			gomock.InOrder(grpcCall)
			h := NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger()))
			err := h.NatTranslationDelete(&proto.NatTranslation{})
			Expect(err).To(HaveOccurred())
		})
	})
})

var _ = Describe("NAT settings handler connection", func() {
	var _ = BeforeEach(func() {
		grpcDial = func(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
			return nil, errors.New("Connection error")
		}
	})

	var _ = Context("Methods should run return connection errors", func() {
		var _ = It("NatTranslationAdd", func() {
			h := NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger()))
			err := h.NatTranslationAdd(&proto.NatTranslation{})
			Expect(err).To(HaveOccurred())
		})

		var _ = It("SetSnatAddress", func() {
			h := NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger()))
			err := h.SetSnatAddress("127.0.0.1")
			Expect(err).To(HaveOccurred())
		})

		var _ = It("AddDelSnatPrefix", func() {
			h := NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger()))
			err := h.AddDelSnatPrefix("127.0.0.1", true)
			Expect(err).To(HaveOccurred())
		})

		var _ = It("NatTranslationDelete", func() {
			h := NewNatServiceHandler(logrus.NewEntry(logrus.StandardLogger()))
			err := h.NatTranslationDelete(&proto.NatTranslation{})
			Expect(err).To(HaveOccurred())
		})
	})
})

var _ = Describe("NAT translation builter utilities", func() {
	var _ = Context("getDstPort should return servicePort.Port", func() {
		var _ = It("NatTranslationAdd", func() {
			sp := v1.ServicePort{
				Port: 42,
				TargetPort: intstr.IntOrString{
					Type:   intstr.Int,
					IntVal: 0,
				},
			}
			port := getDstPort(&sp, nil)
			Expect(port).To(Equal(uint32(sp.Port)))
		})
	})
})

func decode(object string) interface{} {
	decode := scheme.Codecs.UniversalDeserializer().Decode
	obj, _, err := decode([]byte(object), nil, nil)
	Expect(err).ToNot(HaveOccurred())
	Expect(obj).ToNot(BeNil())
	return obj
}

func decodeSvc(svc string) *v1.Service {
	return decode(svc).(*v1.Service)
}

func decodeEp(ep string) *v1.Endpoints {
	return decode(ep).(*v1.Endpoints)
}

func fakeGetNodeIP(client kubernetes.Interface, nodeName string) (string, error) {
	return "127.0.0.1", nil
}

func fakeGetNodeIPErr(client kubernetes.Interface, nodeName string) (string, error) {
	return "", fmt.Errorf("Fake error on getNodeIP")
}

func fakeGetK8sConfig() (*rest.Config, error) {
	return testEnvCfg, nil
}

func fakeGetK8sConfigErr() (*rest.Config, error) {
	return nil, fmt.Errorf("Fake error on getK8sConfig")
}

func fakeNewForConfig(config *rest.Config) (kubernetes.Interface, error) {
	return testEnvClient, nil
}

func fakeNewForConfigErr(config *rest.Config) (kubernetes.Interface, error) {
	return nil, fmt.Errorf("Fake error on newForConfig")
}

func fakeWaitForCacheSync(stopCh <-chan struct{}, cacheSyncs ...cache.InformerSynced) bool {
	return true
}

func fakeWaitForCacheSyncFalse(stopCh <-chan struct{}, cacheSyncs ...cache.InformerSynced) bool {
	return false
}

type fakeServiceHandler struct {
	log                      *logrus.Entry
	natTranslationAddFunc    func(translation *proto.NatTranslation, name string) error
	natTranslationDeleteFunc func(translation *proto.NatTranslation, name string) error
}

func newFakeNatServiceHandler(log *logrus.Entry, natTranslationAddFunc func(*proto.NatTranslation, string) error,
	natTranslationDeleteFunc func(*proto.NatTranslation, string) error) *fakeServiceHandler {
	return &fakeServiceHandler{
		log:                      log,
		natTranslationAddFunc:    natTranslationAddFunc,
		natTranslationDeleteFunc: natTranslationDeleteFunc,
	}
}

func (fsh *fakeServiceHandler) NatTranslationAdd(translation *proto.NatTranslation) error {
	return fsh.natTranslationAddFunc(translation, "NatTranslationAdd")
}

func (fsh *fakeServiceHandler) NatTranslationDelete(translation *proto.NatTranslation) error {
	return fsh.natTranslationDeleteFunc(translation, "NatTranslationDelete")
}

func (fsh *fakeServiceHandler) SetSnatAddress(ip string) error {
	return nil
}

func (fsh *fakeServiceHandler) AddDelSnatPrefix(ip string, isAdd bool) error {
	return nil
}

func fakeNatTranslationErr(translation *proto.NatTranslation, name string) error {
	return errors.New("Fake error on " + name)
}

func fakeNatTranslation(translation *proto.NatTranslation, name string) error {
	return nil
}

func fakeSplitMetaNamespaceKeyErr(key string) (namespace string, name string, err error) {
	return "", "", errors.New("Fake error on SplitMetaNamespaceKey")
}
