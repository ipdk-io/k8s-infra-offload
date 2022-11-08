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
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	"github.com/ipdk-io/k8s-infra-offload/proto"
	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

var (
	newForConfig = utils.GetK8sClient
	getK8sConfig = utils.GetK8sConfig
)

type ServicesListWatchType int

const (
	SERVICES_LIST_WATCH ServicesListWatchType = iota
	ENDPOINTS_LIST_WATCH
)

type ServicesListWatch struct {
	kubernetes.Interface
	watchType ServicesListWatchType
}

func NewServiceListWatch(client kubernetes.Interface, watchType ServicesListWatchType) *ServicesListWatch {
	return &ServicesListWatch{Interface: client, watchType: watchType}
}

func (w ServicesListWatch) List(options metav1.ListOptions) (runtime.Object, error) {
	switch w.watchType {
	case SERVICES_LIST_WATCH:
		return w.Interface.CoreV1().Services("").List(context.TODO(), options)
	case ENDPOINTS_LIST_WATCH:
		return w.Interface.CoreV1().Endpoints("").List(context.TODO(), options)
	default:
		return nil, fmt.Errorf("invalid watch list type")
	}
}

func (w ServicesListWatch) Watch(options metav1.ListOptions) (watch.Interface, error) {
	switch w.watchType {
	case SERVICES_LIST_WATCH:
		return w.Interface.CoreV1().Services("").Watch(context.TODO(), options)
	case ENDPOINTS_LIST_WATCH:
		return w.Interface.CoreV1().Endpoints("").Watch(context.TODO(), options)
	default:
		return nil, fmt.Errorf("invalid watch list type")
	}
}

// Assert ServicesListWatch implements watch.ListerWatcher
var _ cache.ListerWatcher = (*ServicesListWatch)(nil)

type ServiceServer struct {
	log                *logrus.Entry
	endpointStore      cache.Store
	serviceStore       cache.Store
	endpointController cache.Controller
	serviceController  cache.Controller
	t                  tomb.Tomb
	handler            NatSettingsHandler
	nodeAddress        string
	stateMap           map[string]ServiceEntries
	name               string
	mutex              sync.Mutex
}

type ServiceEntries struct {
	Entries   []*proto.NatTranslation
	ServiceID string
}

type NatSettingsHandler interface {
	NatTranslationAdd(translation *proto.NatTranslation) error
	SetSnatAddress(ip string) error
	AddDelSnatPrefix(ip string, isAdd bool) error
	NatTranslationDelete(translation *proto.NatTranslation) error
}

func (s *ServiceServer) findMatchingEndpoints(service *v1.Service) *v1.Endpoints {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(service)
	if err != nil {
		s.log.Errorf("Error getting service %+v key: %v", service, err)
		return nil
	}
	ep, found, err := s.endpointStore.GetByKey(key)
	if err != nil {
		s.log.Errorf("Error getting endpoint %s: %v", key, err)
		return nil
	}
	if !found {
		s.log.Debugf("Endpoint %s not found", key)
		return nil
	}
	return ep.(*v1.Endpoints)
}

func (s *ServiceServer) findMatchingService(ep *v1.Endpoints) *v1.Service {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(ep)
	if err != nil {
		s.log.Errorf("Error getting endpoint %+v key: %v", ep, err)
		return nil
	}
	service, found, err := s.serviceStore.GetByKey(key)
	if err != nil {
		s.log.Errorf("Error getting service %s: %v", key, err)
		return nil
	}
	if !found {
		s.log.Debugf("Service %s not found", key)
		return nil
	}
	return service.(*v1.Service)
}

func (s *ServiceServer) handleServiceEndpointEvent(service *v1.Service, endpoint *v1.Endpoints, isDel bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if service != nil && endpoint == nil {
		endpoint = s.findMatchingEndpoints(service)
	}
	if endpoint != nil && service == nil {
		service = s.findMatchingService(endpoint)
	}
	if service == nil || endpoint == nil {
		return
	}
	s.log.Infof("update service %v namespace %v", service.Name, service.Namespace)
	s.log.Infof("update endpoint name %v namespace %v", endpoint.Name, endpoint.Namespace)

	if isDel {
		s.delServicePort(service, endpoint)
	} else {
		s.addServicePort(service, endpoint)
	}
}

func buildNatTranslations(s *v1.Service, e *v1.Endpoints, nodeIP string) []*proto.NatTranslation {
	entries := make([]*proto.NatTranslation, 0)
	clusterIP := net.ParseIP(s.Spec.ClusterIP)
	builder := NewNatTranslationBuilder(s, e)
	for _, servicePort := range s.Spec.Ports {
		if clusterIP != nil && !clusterIP.IsUnspecified() {
			entry := builder.ForServicePort(&servicePort).WithServiceIP(clusterIP).WithIsNodePort(false).Build()
			entries = append(entries, entry)
		}

		externalIPsEntries := processExternalIPs(servicePort, s.Spec.ExternalIPs, builder)
		entries = append(entries, externalIPsEntries...)

		lbIngressEntries := processLBIngress(servicePort, s.Status.LoadBalancer.Ingress, builder)
		entries = append(entries, lbIngressEntries...)

		if s.Spec.Type == v1.ServiceTypeNodePort {
			nip := net.ParseIP(nodeIP)
			if nip != nil && !nip.IsUnspecified() {
				entry := builder.ForServicePort(&servicePort).WithServiceIP(nip).WithIsNodePort(true).Build()
				entries = append(entries, entry)
			}
		}

	}
	return entries
}

func processExternalIPs(servicePort v1.ServicePort, externalIPs []string, builder NatTranslationBuilder) []*proto.NatTranslation {
	entries := make([]*proto.NatTranslation, 0)
	for _, eip := range externalIPs {
		extIP := net.ParseIP(eip)
		if extIP != nil && !extIP.IsUnspecified() {
			entry := builder.ForServicePort(&servicePort).WithServiceIP(extIP).WithIsNodePort(false).Build()
			entries = append(entries, entry)
		}
	}
	return entries
}

func processLBIngress(servicePort v1.ServicePort, ingress []v1.LoadBalancerIngress, builder NatTranslationBuilder) []*proto.NatTranslation {
	entries := make([]*proto.NatTranslation, 0)
	for _, ingress := range ingress {
		ingressIP := net.ParseIP(ingress.IP)
		if ingressIP != nil && !ingressIP.IsUnspecified() {
			entry := builder.ForServicePort(&servicePort).WithServiceIP(ingressIP).WithIsNodePort(false).Build()
			entries = append(entries, entry)
		}
	}
	return entries
}

func serviceID(meta *metav1.ObjectMeta) string {
	return meta.Namespace + "/" + meta.Name
}

func (s *ServiceServer) delServicePort(service *v1.Service, ep *v1.Endpoints) {
	serviceID := serviceID(&service.ObjectMeta)
	s.log.Infof("Del: got service id %s", serviceID)
	if entry, ok := s.stateMap[serviceID]; ok {
		s.log.Infof("Delete entry %s from state", serviceID)
		for _, nt := range entry.Entries {
			s.log.Infof("Delete NAT translation endpoint %v backends %v", nt.Endpoint, nt.Backends)
			if err := s.handler.NatTranslationDelete(nt); err != nil {
				s.log.WithError(err).Errorf("Failed to delete translation entry for %v", nt)
			}
		}
		delete(s.stateMap, entry.ServiceID)
	} else {
		s.log.Errorf("Entry %s does not exist in state map", serviceID)
	}
}

func (s *ServiceServer) addServicePort(service *v1.Service, ep *v1.Endpoints) {
	serviceID := serviceID(&service.ObjectMeta)
	s.log.Infof("Add: got service id %s", serviceID)
	se := ServiceEntries{
		Entries:   buildNatTranslations(service, ep, s.nodeAddress),
		ServiceID: serviceID,
	}
	if oldEntry, found := s.stateMap[serviceID]; found {
		if reflect.DeepEqual(se.Entries, oldEntry.Entries) {
			s.log.Infof("No change in entry %s, do not update anything", serviceID)
			return
		}
		for _, nt := range oldEntry.Entries {
			// if backends are empty we did not send message to inframanager
			if len(nt.Backends) > 0 {
				if err := s.handler.NatTranslationDelete(nt); err != nil {
					s.log.WithError(err).Errorf("Failed to delete entry for %v", nt)
				}
			}
		}
		delete(s.stateMap, serviceID)
	}
	for _, nt := range se.Entries {
		// do not send if there are no backends available
		if len(nt.Backends) > 0 {
			if err := s.handler.NatTranslationAdd(nt); err != nil {
				s.log.WithError(err).Errorf("Failed to delete entry for %v", nt)
			}
		}
	}
	s.stateMap[serviceID] = se
}

// func (s *ServiceServer) SetSnatAddress() {
// 	if err := s.handler.SetSnatAddress(s.nodeAddress); err != nil {
// 		s.log.Infof("set snat address reply %v", err)
// 	}
// }

func NewServiceServer(log *logrus.Entry, handler NatSettingsHandler, refreshTime uint32) (types.Server, error) {
	clusterConfig, err := getK8sConfig()
	if err != nil {
		return nil, err
	}
	log.Infof("Creating new server, cluster config %+v", clusterConfig)
	k8sc, err := newForConfig(clusterConfig)
	if err != nil {
		return nil, err
	}
	srv := ServiceServer{
		log:      log,
		handler:  handler,
		stateMap: make(map[string]ServiceEntries),
		name:     "services-server",
	}
	nodeIP, err := utils.GetNodeIP(k8sc, types.NodeName)
	if err != nil {
		return nil, err
	}
	srv.nodeAddress = nodeIP
	//k8sc.CoreV1().RESTClient(), "services", "", fields.Everything()
	serviceListWatch := NewServiceListWatch(k8sc, SERVICES_LIST_WATCH)
	serviceStore, serviceController := cache.NewInformer(serviceListWatch, &v1.Service{}, time.Duration(refreshTime)*time.Second,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { srv.handleServiceEndpointEvent(obj.(*v1.Service), nil, false) },
			DeleteFunc: func(obj interface{}) { srv.handleServiceEndpointEvent(obj.(*v1.Service), nil, true) },
			UpdateFunc: func(_, newObj interface{}) { srv.handleServiceEndpointEvent(newObj.(*v1.Service), nil, false) }})
	srv.serviceStore = serviceStore
	srv.serviceController = serviceController
	endpointsListWatch := NewServiceListWatch(k8sc, ENDPOINTS_LIST_WATCH)
	endpointStore, endpointController := cache.NewInformer(endpointsListWatch, &v1.Endpoints{}, time.Duration(refreshTime)*time.Second,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { srv.handleServiceEndpointEvent(nil, obj.(*v1.Endpoints), false) },
			DeleteFunc: func(obj interface{}) { srv.handleServiceEndpointEvent(nil, obj.(*v1.Endpoints), true) },
			UpdateFunc: func(_, newObj interface{}) { srv.handleServiceEndpointEvent(nil, newObj.(*v1.Endpoints), false) },
		})
	srv.endpointStore = endpointStore
	srv.endpointController = endpointController
	return &srv, nil
}

func (s *ServiceServer) GetName() string {
	return s.name
}

func (s *ServiceServer) serve() error {
	s.t.Go(func() error { s.serviceController.Run(s.t.Dying()); return nil })
	s.t.Go(func() error { s.endpointController.Run(s.t.Dying()); return nil })
	types.ServiceServerStatus = types.ServerStatusOK
	<-s.t.Dying()
	s.log.Info("Service server returned")
	return nil
}

func (s *ServiceServer) StopServer() {
	types.ServiceServerStatus = types.ServerStatusStopped
	// stop internal goroutines
	s.t.Kill(errors.New("GracefulStop"))
	_ = s.t.Wait()
}

func (s *ServiceServer) Start(t *tomb.Tomb) error {
	go func() {
		if err := s.serve(); err != nil {
			s.log.Warnf("Error when starting services err %v", err)
		}
	}()
	// wait until kill appear on parent tomb
	<-t.Dying()
	s.StopServer()
	return nil
}
