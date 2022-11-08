// Copyright (c) 2022 Intel Corporation.  All Rights Reserved.
// Copyright 2017 The Kubernetes Authors.
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
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	kubeinformers "k8s.io/client-go/informers"
	corelister "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
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

type serviceServer struct {
	name                string
	log                 *logrus.Entry
	t                   tomb.Tomb
	handler             NatSettingsHandler
	nodeAddress         string
	kubeInformerFactory informers.SharedInformerFactory
	servicesLister      corelister.ServiceLister
	endpointsLister     corelister.EndpointsLister
	serviceSynced       cache.InformerSynced
	endpointSynced      cache.InformerSynced
	workqueue           workqueue.RateLimitingInterface
	stateMap            map[string]ServiceEntries
	mutex               sync.Mutex
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

// NewServiceServer returns an instance of serviceServer with types.Server interface
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

	informerFactory := kubeinformers.NewSharedInformerFactory(k8sc, time.Duration(refreshTime)*time.Second)
	serviceInformer := informerFactory.Core().V1().Services()
	endpointsInformer := informerFactory.Core().V1().Endpoints()

	srv := serviceServer{
		log:                 log,
		handler:             handler,
		stateMap:            make(map[string]ServiceEntries),
		name:                "services-server",
		kubeInformerFactory: informerFactory,
		servicesLister:      serviceInformer.Lister(),
		serviceSynced:       serviceInformer.Informer().HasSynced,
		endpointsLister:     endpointsInformer.Lister(),
		endpointSynced:      endpointsInformer.Informer().HasSynced,
		workqueue:           workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Services"),
	}

	serviceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			svc := obj.(*corev1.Service)
			log.Info("Service ADD - ", "Name:", svc.Name, "Namespace:", svc.Namespace)
			srv.enqueueService(svc)
		},
		UpdateFunc: func(old, new interface{}) {
			newSvc := new.(*corev1.Service)
			oldSvc := old.(*corev1.Service)
			if newSvc.ResourceVersion == oldSvc.ResourceVersion {
				// Periodic resync will send update events for all known Service.
				// Two different versions of the same Service will always have different RVs.
				return
			}
			log.Info("Service UPDATE - ", "Name:", newSvc.Name, "Namespace:", newSvc.Namespace)
			srv.enqueueService(newSvc)
		},
		DeleteFunc: func(obj interface{}) {
			svc := obj.(*corev1.Service)
			log.Info("Service DELETE - ", "Name:", svc.Name, "Namespace:", svc.Namespace)
			srv.enqueueService(svc)
		},
	})

	endpointsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ep := obj.(*corev1.Endpoints)
			log.Info("Endpoints ADD - ", "Name:", ep.Name, "Namespace:", ep.Namespace)
			srv.enqueueService(ep)
		},
		UpdateFunc: func(old, new interface{}) {
			newEp := new.(*corev1.Endpoints)
			oldEp := old.(*corev1.Endpoints)
			if newEp.ResourceVersion == oldEp.ResourceVersion {
				// Periodic resync will send update events for all known Endpoints.
				// Two different versions of the same Endpoints will always have different RVs.
				return
			}
			log.Info("Endpoints UPDATE - ", "Name:", newEp.Name, "Namespace:", newEp.Namespace)
			srv.enqueueService(newEp)
		},
		DeleteFunc: func(obj interface{}) {
			ep := obj.(*corev1.Endpoints)
			log.Info("Endpoints DELETE - ", "Name:", ep.Name, "Namespace:", ep.Namespace)
			srv.enqueueService(ep)
		},
	})

	nodeIP, err := utils.GetNodeIP(k8sc, types.NodeName)
	if err != nil {
		return nil, err
	}
	srv.nodeAddress = nodeIP
	return &srv, nil
}

// enqueueService takes a Service/Endpoints resource and converts it into a namespace/name
// string which is then put onto the work queue. We can enqueue a service for endpoints resource
// matching with same namespace/name
func (s *serviceServer) enqueueService(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	s.workqueue.Add(key)
}

func (s *serviceServer) GetName() string {
	return s.name
}

func (s *serviceServer) StopServer() {
	s.log.Info("Service server is dying, calling Stop on service worker threads")
	types.ServiceServerStatus = types.ServerStatusStopped

	// stop internal goroutines
	s.t.Kill(errors.New("GracefulStop"))
	s.log.Info("Service server sent Kill signal to its threads")
	_ = s.t.Wait()

}

func (s *serviceServer) Start(t *tomb.Tomb) error {
	// Start all informers in informers factory
	s.kubeInformerFactory.Start(s.t.Dying())

	// Start contorller.Run() in tomb thread so that we can stop from top level agent thread
	s.t.Go(func() error { return s.Run(2, s.t.Dying()) })

	types.ServiceServerStatus = types.ServerStatusOK
	s.log.Info("Service server has started serving")
	// wait until kill appear on parent tomb
	<-t.Dying()
	s.log.Info("Recived kill signal from Agent, calling StopServer()")
	s.StopServer()
	return nil
}

// Run will set up the event handlers for Service and Endpoints, as well
// as syncing their informer caches and starting workers. It will block until stopCh
// is closed, at which point it will shutdown the workqueue and wait for
// workers to finish processing their current work items.
func (s *serviceServer) Run(workers int, stopCh <-chan struct{}) error {
	s.log.Info("Running service workers")

	defer utilruntime.HandleCrash()
	defer s.workqueue.ShutDown()

	// Wait for the caches to be synced before starting workers
	s.log.Info("Waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(stopCh, s.serviceSynced, s.endpointSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	// Launch two workers to process Service & Enpoints resources
	for i := 0; i < workers; i++ {
		go wait.Until(s.runWorker, time.Second, stopCh)
	}
	s.log.Info("Two service workers are running")
	<-stopCh
	s.log.Info("Shutting down service workers")
	return nil

}

func (s *serviceServer) runWorker() {
	for s.processNextWorkItem() {
	}
}

// processNextWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the syncHandler.
func (s *serviceServer) processNextWorkItem() bool {
	obj, shutdown := s.workqueue.Get()

	if shutdown {
		return false
	}

	// We wrap this block in a func so we can defer c.workqueue.Done.
	err := func(obj interface{}) error {
		// We call Done here so the workqueue knows we have finished
		// processing this item. We also must remember to call Forget if we
		// do not want this work item being re-queued. For example, we do
		// not call Forget if a transient error occurs, instead the item is
		// put back on the workqueue and attempted again after a back-off
		// period.
		defer s.workqueue.Done(obj)
		var key string
		var ok bool
		// We expect strings to come off the workqueue. These are of the
		// form namespace/name. We do this as the delayed nature of the
		// workqueue means the items in the informer cache may actually be
		// more up to date that when the item was initially put onto the
		// workqueue.
		if key, ok = obj.(string); !ok {
			// As the item in the workqueue is actually invalid, we call
			// Forget here else we'd go into a loop of attempting to
			// process a work item that is invalid.
			s.workqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}
		// Run the syncHandler, passing it the namespace/name string of the
		// Service resource to be synced.
		if err := s.syncHandler(key); err != nil {
			// Put the item back on the workqueue to handle any transient errors.
			s.workqueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		s.workqueue.Forget(obj)
		s.log.Infof("Successfully synced '%s'", key)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

// syncHandler compares the actual state with the desired, and attempts to
// converge the two.
func (s *serviceServer) syncHandler(key string) error {
	// Convert the namespace/name string into a distinct namespace and name
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	// We start with assumptions that service and endpoint resource exist
	// so that we can handle either deletion any of these two resources at once.
	svcFound := true
	epFound := true
	// Get the Service resource with this namespace/name
	svc, err := s.servicesLister.Services(namespace).Get(name)
	if err != nil {
		// The service resource may no longer exist, in which case we stop
		// processing.
		if !kerrors.IsNotFound(err) {
			// return any other error other than resource 'NotFound' so that it gets put back in workqueue to try again later.
			return err
		}
		svcFound = false
		utilruntime.HandleError(fmt.Errorf("service '%s' in work queue no longer exists", key))
	}

	// Get the Endpoints resource with this namespace/name
	ep, err := s.endpointsLister.Endpoints(namespace).Get(name)
	if err != nil {
		// The endpoints resource may no longer exist, in which case we stop
		// processing.
		if !kerrors.IsNotFound(err) {
			// return any other error other than resource 'NotFound' so that it gets put back in workqueue to try again later.
			return err
		}
		epFound = false
		utilruntime.HandleError(fmt.Errorf("endpoints '%s' in work queue no longer exists", key))
	}

	// If either Service or Endpoints resource got deleted we delete rules associated with that Service from dataplane
	if !svcFound || !epFound {
		return s.handleServiceDel(key, svc, ep)
	}

	return s.handleServiceUpdate(key, svc, ep)
}

func (s *serviceServer) handleServiceDel(key string, svc *corev1.Service, ep *corev1.Endpoints) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.delServicePort(key, svc, ep)
}

func (s *serviceServer) handleServiceUpdate(key string, svc *corev1.Service, ep *corev1.Endpoints) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.updateServicePort(key, svc, ep)
}

func (s *serviceServer) delServicePort(key string, service *v1.Service, ep *v1.Endpoints) error {
	serviceID := key
	s.log.Infof("Del: service NamespceName %s", serviceID)
	if entry, ok := s.stateMap[serviceID]; ok {
		s.log.Infof("Delete entry %s from state", serviceID)
		for _, nt := range entry.Entries {
			s.log.Infof("Delete NAT translation endpoint %v backends %v", nt.Endpoint, nt.Backends)
			if err := s.handler.NatTranslationDelete(nt); err != nil {
				s.log.WithError(err).Errorf("Failed to delete translation entry for %v", nt)
				return err
			}
		}
		delete(s.stateMap, entry.ServiceID)
	} else {
		s.log.Errorf("Entry %s does not exist in state map", serviceID)
	}
	return nil
}

func (s *serviceServer) updateServicePort(key string, service *v1.Service, ep *v1.Endpoints) error {
	serviceID := key
	s.log.Infof("Update: service NamespceName %s", serviceID)
	se := ServiceEntries{
		Entries:   buildNatTranslations(service, ep, s.nodeAddress),
		ServiceID: serviceID,
	}
	if oldEntry, found := s.stateMap[serviceID]; found {
		if reflect.DeepEqual(se.Entries, oldEntry.Entries) {
			s.log.Infof("No change in entry %s, do not update anything", serviceID)
			return nil
		}

		for _, nt := range oldEntry.Entries {
			// if backends are empty we did not send message to inframanager
			if len(nt.Backends) > 0 {
				if err := s.handler.NatTranslationDelete(nt); err != nil {
					s.log.WithError(err).Errorf("Failed to delete entry for %v", nt)
					return err
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
				return err
			}
		}
	}
	s.stateMap[serviceID] = se
	return nil
}
