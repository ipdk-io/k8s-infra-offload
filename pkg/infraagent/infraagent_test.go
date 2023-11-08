package infraagent

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"gopkg.in/tomb.v2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
)

var (
	tempDir string

	nodeListString = `{"metadata":{"resourceVersion":"3188299"},"items":[{"metadata":{"name":"dummyNode","uid":"4c1f6487-99e8-4860-8534-7df51b6a682c","resourceVersion":"3188070","creationTimestamp":"2022-07-08T13:44:51Z","labels":{"beta.kubernetes.io/arch":"amd64","beta.kubernetes.io/os":"linux","kubernetes.io/arch":"amd64","kubernetes.io/hostname":"dummyNode","kubernetes.io/os":"linux","node-role.kubernetes.io/control-plane":"","node.kubernetes.io/exclude-from-external-load-balancers":""},"annotations":{"kubeadm.alpha.kubernetes.io/cri-socket":"unix:///var/run/containerd/containerd.sock","node.alpha.kubernetes.io/ttl":"0","projectcalico.org/IPv4Address":"10.244.0.7/24","projectcalico.org/IPv4IPIPTunnelAddr":"10.244.0.1","volumes.kubernetes.io/controller-managed-attach-detach":"true"},"managedFields":[{"manager":"kubelet","operation":"Update","apiVersion":"v1","time":"2022-07-08T13:44:51Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{".":{},"f:volumes.kubernetes.io/controller-managed-attach-detach":{}},"f:labels":{".":{},"f:beta.kubernetes.io/arch":{},"f:beta.kubernetes.io/os":{},"f:kubernetes.io/arch":{},"f:kubernetes.io/hostname":{},"f:kubernetes.io/os":{}}}}},{"manager":"kubeadm","operation":"Update","apiVersion":"v1","time":"2022-07-08T13:44:56Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{"f:kubeadm.alpha.kubernetes.io/cri-socket":{}},"f:labels":{"f:node-role.kubernetes.io/control-plane":{},"f:node.kubernetes.io/exclude-from-external-load-balancers":{}}}}},{"manager":"kube-controller-manager","operation":"Update","apiVersion":"v1","time":"2022-07-08T13:45:10Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{"f:node.alpha.kubernetes.io/ttl":{}}},"f:spec":{"f:podCIDR":{},"f:podCIDRs":{".":{},"v:\"10.244.0.0/24\"":{}}}}},{"manager":"Go-http-client","operation":"Update","apiVersion":"v1","time":"2022-07-08T13:46:55Z","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{"f:projectcalico.org/IPv4Address":{},"f:projectcalico.org/IPv4IPIPTunnelAddr":{}}}},"subresource":"status"},{"manager":"kubelet","operation":"Update","apiVersion":"v1","time":"2022-07-11T07:17:49Z","fieldsType":"FieldsV1","fieldsV1":{"f:status":{"f:conditions":{"k:{\"type\":\"DiskPressure\"}":{"f:lastHeartbeatTime":{}},"k:{\"type\":\"MemoryPressure\"}":{"f:lastHeartbeatTime":{}},"k:{\"type\":\"PIDPressure\"}":{"f:lastHeartbeatTime":{}},"k:{\"type\":\"Ready\"}":{"f:lastHeartbeatTime":{},"f:lastTransitionTime":{},"f:message":{},"f:reason":{},"f:status":{}}},"f:images":{}}},"subresource":"status"}]},"spec":{"podCIDR":"10.244.0.0/24","podCIDRs":["10.244.0.0/24"]},"status":{"capacity":{"cpu":"88","ephemeral-storage":"960847604Ki","hugepages-1Gi":"0","hugepages-2Mi":"2Gi","memory":"131695828Ki","pods":"110"},"allocatable":{"cpu":"88","ephemeral-storage":"885517150381","hugepages-1Gi":"0","hugepages-2Mi":"2Gi","memory":"129496276Ki","pods":"110"},"conditions":[{"type":"MemoryPressure","status":"False","lastHeartbeatTime":"2022-07-25T12:21:02Z","lastTransitionTime":"2022-07-08T13:44:49Z","reason":"KubeletHasSufficientMemory","message":"kubelet has sufficient memory available"},{"type":"DiskPressure","status":"False","lastHeartbeatTime":"2022-07-25T12:21:02Z","lastTransitionTime":"2022-07-08T13:44:49Z","reason":"KubeletHasNoDiskPressure","message":"kubelet has no disk pressure"},{"type":"PIDPressure","status":"False","lastHeartbeatTime":"2022-07-25T12:21:02Z","lastTransitionTime":"2022-07-08T13:44:49Z","reason":"KubeletHasSufficientPID","message":"kubelet has sufficient PID available"},{"type":"Ready","status":"True","lastHeartbeatTime":"2022-07-25T12:21:02Z","lastTransitionTime":"2022-07-08T13:44:57Z","reason":"KubeletReady","message":"kubelet is posting ready status. AppArmor enabled"}],"addresses":[{"type":"InternalIP","address":"192.168.111.66"},{"type":"Hostname","address":"dummyNode"}],"daemonEndpoints":{"kubeletEndpoint":{"Port":10250}},"nodeInfo":{"machineID":"77094b51073843e5acb5c3cdd16c909e","systemUUID":"30726035-e8ed-ea11-ba6b-a4bf01644732","bootID":"de767a54-9900-4e24-8514-8c4cbf817213","kernelVersion":"5.4.0-121-generic","osImage":"Ubuntu 20.04.4 LTS","containerRuntimeVersion":"containerd://1.5.11","kubeletVersion":"v1.24.0","kubeProxyVersion":"v1.24.0","operatingSystem":"linux","architecture":"amd64"},"images":[{"names":["docker.io/calico/cni@sha256:26802bb7714fda18b93765e908f2d48b0230fd1c620789ba2502549afcde4338","docker.io/calico/cni:v3.23.1"],"sizeBytes":110500425},{"names":["k8s.gcr.io/etcd@sha256:13f53ed1d91e2e11aac476ee9a0269fdda6cc4874eba903efd40daf50c55eee5","k8s.gcr.io/etcd:3.5.3-0"],"sizeBytes":102143581},{"names":["docker.io/calico/node@sha256:d2c1613ef26c9ad43af40527691db1f3ad640291d5e4655ae27f1dd9222cc380","docker.io/calico/node:v3.23.1"],"sizeBytes":76574475},{"names":["docker.io/calico/apiserver@sha256:231b782c7d464bd59b416033e28eae8b3ec2ff90d38ca718558430f67f3203fa","docker.io/calico/apiserver:v3.23.1"],"sizeBytes":76516308},{"names":["quay.io/tigera/operator@sha256:526c06f827200856fb1f5594cc3f7d23935674cf20c22330e8ab9a6ddc484c8d","quay.io/tigera/operator:v1.27.1"],"sizeBytes":60267159},{"names":["docker.io/library/nginx@sha256:10f14ffa93f8dedf1057897b745e5ac72ac5655c299dade0aa434c71557697ea","docker.io/library/nginx:latest"],"sizeBytes":56748232},{"names":["docker.io/calico/kube-controllers@sha256:e8b2af28f2c283a38b4d80436e2d2a25e70f2820d97d1a8684609d42c3973afb","docker.io/calico/kube-controllers:v3.23.1"],"sizeBytes":56361853},{"names":["docker.io/calico/typha@sha256:d58558013bce1387f40969f483f65b5178b4574a8c383c3e997768d6a0ffff34","docker.io/calico/typha:v3.23.1"],"sizeBytes":54003239},{"names":["docker.io/library/nginx@sha256:6fff55753e3b34e36e24e37039ee9eae1fe38a6420d8ae16ef37c92d1eb26699","docker.io/library/nginx:1.17"],"sizeBytes":51030575},{"names":["k8s.gcr.io/kube-proxy@sha256:c957d602267fa61082ab8847914b2118955d0739d592cc7b01e278513478d6a8","k8s.gcr.io/kube-proxy:v1.24.0"],"sizeBytes":39515042},{"names":["k8s.gcr.io/kube-apiserver@sha256:a04522b882e919de6141b47d72393fb01226c78e7388400f966198222558c955","k8s.gcr.io/kube-apiserver:v1.24.0"],"sizeBytes":33796127},{"names":["10.55.129.85:5000/infra-agent@sha256:f9f2ef413a30e37ea5f3ca8a5affbeb41c58b56b4a3f36ac22cf85143e5148a0","10.55.129.85:5000/k8s-p4-dataplane@sha256:f9f2ef413a30e37ea5f3ca8a5affbeb41c58b56b4a3f36ac22cf85143e5148a0","10.55.129.85:5000/infra-agent:latest","10.55.129.85:5000/k8s-p4-dataplane:latest"],"sizeBytes":32681228},{"names":["k8s.gcr.io/kube-controller-manager@sha256:df044a154e79a18f749d3cd9d958c3edde2b6a00c815176472002b7bbf956637","k8s.gcr.io/kube-controller-manager:v1.24.0"],"sizeBytes":31032816},{"names":["docker.io/wbitt/network-multitool@sha256:82a5ea955024390d6b438ce22ccc75c98b481bf00e57c13e9a9cc1458eb92652","docker.io/wbitt/network-multitool:latest"],"sizeBytes":24236758},{"names":["k8s.gcr.io/kube-scheduler@sha256:db842a7c431fd51db7e1911f6d1df27a7b6b6963ceda24852b654d2cd535b776","k8s.gcr.io/kube-scheduler:v1.24.0"],"sizeBytes":15488642},{"names":["k8s.gcr.io/coredns/coredns@sha256:5b6ec0d6de9baaf3e92d0f66cd96a25b9edbce8716f5f15dcd1a616b3abd590e","k8s.gcr.io/coredns/coredns:v1.8.6"],"sizeBytes":13585107},{"names":["docker.io/calico/pod2daemon-flexvol@sha256:5d5759fc6de1f6c09b95d36334d968fa074779120024c067a770cfb2af579670","docker.io/calico/pod2daemon-flexvol:v3.23.1"],"sizeBytes":8671600},{"names":["docker.io/leannet/k8s-netperf@sha256:dd79ca1b6ecefc1e5bd9301abff0cfdec25dce9cd4fb9a09ddf4e117aa5550cd","docker.io/leannet/k8s-netperf:latest"],"sizeBytes":6732296},{"names":["docker.io/library/busybox@sha256:3614ca5eacf0a3a1bcc361c939202a974b4902b9334ff36eb29ffe9011aaad83","docker.io/library/busybox:latest"],"sizeBytes":777536},{"names":["docker.io/library/busybox@sha256:ebadf81a7f2146e95f8c850ad7af8cf9755d31cdba380a8ffd5930fba5996095"],"sizeBytes":777101},{"names":["docker.io/library/busybox@sha256:d2b53584f580310186df7a2055ce3ff83cc0df6caacf1e3489bff8cf5d0af5d8"],"sizeBytes":777091},{"names":["k8s.gcr.io/pause@sha256:bb6ed397957e9ca7c65ada0db5c5d1c707c9c8afc80a94acbe69f3ae76988f0c","k8s.gcr.io/pause:3.7"],"sizeBytes":311278},{"names":["k8s.gcr.io/pause@sha256:927d98197ec1141a368550822d18fa1c60bdae27b78b0c004f705f548c07814f","k8s.gcr.io/pause:3.2"],"sizeBytes":299513}]}}]}`
	podListString  = `{"metadata":{"resourceVersion":"1935781"},"items":[{"metadata":{"name":"kube-controller-manager-dummyNode","namespace":"kube-system","uid":"6dded560-2e01-42a9-9d19-f77810da7972","resourceVersion":"303","creationTimestamp":"2022-08-08T07:00:54Z","labels":{"component":"kube-controller-manager","tier":"control-plane"},"annotations":{"kubernetes.io/config.hash":"c5a714e26839c594c550317b88301c99","kubernetes.io/config.mirror":"c5a714e26839c594c550317b88301c99","kubernetes.io/config.seen":"2022-08-08T08:00:47.159987024+01:00","kubernetes.io/config.source":"file","seccomp.security.alpha.kubernetes.io/pod":"runtime/default"},"ownerReferences":[{"apiVersion":"v1","kind":"Node","name":"node01","uid":"f41b3026-c2c9-449b-97a6-c7129dc97021","controller":true}],"managedFields":[]},"spec":{"volumes":[{"name":"ca-certs","hostPath":{"path":"/etc/ssl/certs","type":"DirectoryOrCreate"}},{"name":"etc-pki","hostPath":{"path":"/etc/pki","type":"DirectoryOrCreate"}},{"name":"flexvolume-dir","hostPath":{"path":"/usr/libexec/kubernetes/kubelet-plugins/volume/exec","type":"DirectoryOrCreate"}},{"name":"k8s-certs","hostPath":{"path":"/etc/kubernetes/pki","type":"DirectoryOrCreate"}},{"name":"kubeconfig","hostPath":{"path":"/etc/kubernetes/controller-manager.conf","type":"FileOrCreate"}}],"containers":[{"name":"kube-controller-manager","image":"k8s.gcr.io/kube-controller-manager:v1.24.3","command":["kube-controller-manager","--allocate-node-cidrs=true","--authentication-kubeconfig=/etc/kubernetes/controller-manager.conf","--authorization-kubeconfig=/etc/kubernetes/controller-manager.conf","--bind-address=127.0.0.1","--client-ca-file=/etc/kubernetes/pki/ca.crt","--cluster-cidr=10.210.0.0/16","--cluster-name=kubernetes","--cluster-signing-cert-file=/etc/kubernetes/pki/ca.crt","--cluster-signing-key-file=/etc/kubernetes/pki/ca.key","--controllers=*,bootstrapsigner,tokencleaner","--kubeconfig=/etc/kubernetes/controller-manager.conf","--leader-elect=true","--requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt","--root-ca-file=/etc/kubernetes/pki/ca.crt","--service-account-private-key-file=/etc/kubernetes/pki/sa.key","--service-cluster-ip-range=10.96.0.0/12","--use-service-account-credentials=true"],"env":[],"resources":{"requests":{"cpu":"200m"}},"volumeMounts":[{"name":"ca-certs","readOnly":true,"mountPath":"/etc/ssl/certs"},{"name":"etc-pki","readOnly":true,"mountPath":"/etc/pki"},{"name":"flexvolume-dir","mountPath":"/usr/libexec/kubernetes/kubelet-plugins/volume/exec"},{"name":"k8s-certs","readOnly":true,"mountPath":"/etc/kubernetes/pki"},{"name":"kubeconfig","readOnly":true,"mountPath":"/etc/kubernetes/controller-manager.conf"}],"livenessProbe":{"httpGet":{"path":"/healthz","port":10257,"host":"127.0.0.1","scheme":"HTTPS"},"initialDelaySeconds":10,"timeoutSeconds":15,"periodSeconds":10,"successThreshold":1,"failureThreshold":8},"startupProbe":{"httpGet":{"path":"/healthz","port":10257,"host":"127.0.0.1","scheme":"HTTPS"},"initialDelaySeconds":10,"timeoutSeconds":15,"periodSeconds":10,"successThreshold":1,"failureThreshold":24},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","imagePullPolicy":"IfNotPresent"}],"restartPolicy":"Always","terminationGracePeriodSeconds":30,"dnsPolicy":"ClusterFirst","nodeName":"node01","hostNetwork":true,"securityContext":{"seccompProfile":{"type":"RuntimeDefault"}},"schedulerName":"default-scheduler","tolerations":[{"operator":"Exists","effect":"NoExecute"}],"priorityClassName":"system-node-critical","priority":2000001000,"enableServiceLinks":true,"preemptionPolicy":"PreemptLowerPriority"},"status":{"phase":"Running","conditions":[{"type":"Initialized","status":"True","lastProbeTime":null,"lastTransitionTime":"2022-08-08T07:00:56Z"},{"type":"Ready","status":"True","lastProbeTime":null,"lastTransitionTime":"2022-08-08T07:01:06Z"},{"type":"ContainersReady","status":"True","lastProbeTime":null,"lastTransitionTime":"2022-08-08T07:01:06Z"},{"type":"PodScheduled","status":"True","lastProbeTime":null,"lastTransitionTime":"2022-08-08T07:00:56Z"}],"hostIP":"10.237.214.71","podIP":"10.237.214.71","podIPs":[{"ip":"10.237.214.71"}],"startTime":"2022-08-08T07:00:56Z","containerStatuses":[{"name":"kube-controller-manager","state":{"running":{"startedAt":"2022-08-08T07:00:48Z"}},"lastState":{},"ready":true,"restartCount":1,"image":"k8s.gcr.io/kube-controller-manager:v1.24.3","imageID":"k8s.gcr.io/kube-controller-manager@sha256:f504eead8b8674ebc9067370ef51abbdc531b4a81813bfe464abccb8c76b6a53","containerID":"containerd://b2b7d69d8f6e6d1f057e7c5a428e572f69e34deb41f6f051610dd3a9986c6ca1","started":true}],"qosClass":"Burstable"}}]}`
)

var _ = BeforeSuite(func() {
	var err error
	tempDir, err = os.MkdirTemp("", "infraagent")
	Expect(err).To(BeNil())
})

var _ = AfterSuite(func() {
	err := os.RemoveAll(tempDir)
	Expect(err).To(BeNil())
})

func TestInfraagent(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Infraagent Test Suite")
}

var _ = Describe("Infraagent", func() {
	var _ = Context("NewAgent() should", func() {
		var _ = It("return agent", func() {
			a, err := NewAgent("dummy", "Debug", "interface", tempDir, nil)
			Expect(a).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
		})
	})
	var _ = Context("startServer() should", func() {
		var _ = It("return no error", func() {
			a, err := NewAgent("dummy", "Debug", "interface", tempDir, nil)
			Expect(a).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			agent, ok := a.(*agent)
			Expect(ok).To(BeTrue())
			err = agent.startServer("dummy", fakeServe)
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return error", func() {
			a, err := NewAgent("dummy", "Debug", "interface", tempDir, nil)
			Expect(a).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			agent, ok := a.(*agent)
			Expect(ok).To(BeTrue())
			_ = agent.startServer("dummy", fakeServeErr)
			err = agent.t.Wait()
			Expect(err).To(HaveOccurred())
		})
	})
	var _ = Context("setConfig() should", func() {
		var _ = It("return error if NODE_NAME env is not set", func() {
			a, err := NewAgent("dummy", "Debug", "interface", tempDir, nil)
			Expect(a).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			agent, ok := a.(*agent)
			Expect(ok).To(BeTrue())
			err = agent.setConfig()
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if can't get node's interface", func() {
			nodeList := &v1.NodeList{}
			err := json.Unmarshal([]byte(nodeListString), nodeList)
			Expect(err).ToNot(HaveOccurred())

			client := fake.NewSimpleClientset(nodeList)
			a, err := NewAgent("dummy", "Debug", "", tempDir, client)
			Expect(a).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			agent, ok := a.(*agent)
			Expect(ok).To(BeTrue())
			types.NodeName = "dummyNode"
			err = agent.setConfig()
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if can't get NodePodsCIDR", func() {
			client := fake.NewSimpleClientset()
			a, err := NewAgent("dummy", "Debug", "dummyIf", tempDir, client)
			Expect(a).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			agent, ok := a.(*agent)
			Expect(ok).To(BeTrue())
			types.NodeName = "dummyNode"
			err = agent.setConfig()
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if can't get  subnets", func() {
			nodeList := &v1.NodeList{}
			err := json.Unmarshal([]byte(nodeListString), nodeList)
			Expect(err).ToNot(HaveOccurred())

			client := fake.NewSimpleClientset(nodeList)

			a, err := NewAgent("dummy", "Debug", "dummyIf", tempDir, client)
			Expect(a).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			agent, ok := a.(*agent)
			Expect(ok).To(BeTrue())
			types.NodeName = "dummyNode"
			err = agent.setConfig()
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			nodeList := &v1.NodeList{}
			err := json.Unmarshal([]byte(nodeListString), nodeList)
			Expect(err).ToNot(HaveOccurred())

			podList := &v1.PodList{}
			err = json.Unmarshal([]byte(podListString), podList)
			Expect(err).ToNot(HaveOccurred())

			client := fake.NewSimpleClientset(nodeList, podList)
			a, err := NewAgent("dummy", "Debug", "dummyIf", tempDir, client)
			Expect(a).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			agent, ok := a.(*agent)
			Expect(ok).To(BeTrue())
			types.NodeName = "dummyNode"
			err = agent.setConfig()
			Expect(err).ToNot(HaveOccurred())
		})
	})
	var _ = Context("startServers() should", func() {
		var _ = It("return no error", func() {
			a, err := NewAgent("dummy", "Debug", "dummyIf", tempDir, nil)
			Expect(a).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			agent, ok := a.(*agent)
			Expect(ok).To(BeTrue())
			servers := []types.Server{&fakeServer{}, &fakeServer{}, &fakeServer{}, &fakeServer{}}
			err = agent.startServers(servers)
			Expect(err).ToNot(HaveOccurred())
			agent.stopServers()
		})
		var _ = It("return error if any server failed", func() {
			a, err := NewAgent("dummy", "Debug", "dummyIf", tempDir, nil)
			Expect(a).ToNot(BeNil())
			Expect(err).ToNot(HaveOccurred())
			agent, ok := a.(*agent)
			Expect(ok).To(BeTrue())
			servers := []types.Server{&fakeServer{}, &fakeServer{}, &fakeServerErr{}, &fakeServer{}}
			_ = agent.startServers(servers)
			err = agent.t.Wait()
			Expect(err).To(HaveOccurred())
			agent.stopServers()
		})
	})

})

func fakeServe(t *tomb.Tomb) error {
	return nil
}

func fakeServeErr(t *tomb.Tomb) error {
	return errors.New("Fake error")
}

type fakeServer struct{}

func (fs *fakeServer) GetName() string          { return "fakeServer" }
func (fs *fakeServer) StopServer()              {}
func (fs *fakeServer) Start(t *tomb.Tomb) error { return nil }

type fakeServerErr struct{}

func (fs *fakeServerErr) GetName() string          { return "fakeServerErr" }
func (fs *fakeServerErr) StopServer()              {}
func (fs *fakeServerErr) Start(t *tomb.Tomb) error { return errors.New("Fake error") }
