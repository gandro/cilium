package metadata

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/cilium/pkg/cgroups"
	"github.com/cilium/cilium/pkg/defaults"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "metadata")
	// example cgroup path in kubernetes environments
	// /run/cilium/cgroupv2/kubepods/burstable/pod1858680e-b044-4fd5-9dd4-f137e30e2180/e275d1a37782ab30008aa3ae6666cccefe53b3a14a2ab5a8dc459939107c8c0
	defaultCgroupBasePath = cgroups.GetCgroupRoot() + "/kubepods"
	// example cgroup path in nested kubernetes environments like kind
	// /run/cilium/cgroupv2/kubelet/kubepods/pod4841248b-fc2f-41f4-9981-a685bf840ab5/d8f227cc24940cfdce8d8e601f3b92242ac9661b0e83f0ea57fdea1cb6bc93ec
	defaultNestedCgroupBasePath = cgroups.GetCgroupRoot() + "/kubelet" + "/kubepods"
	cgroupBasePaths             = []string{defaultCgroupBasePath, defaultNestedCgroupBasePath}
)

// Manager maintains Kubernetes and low-level metadata (cgroup path and
// cgroup id) for local pods and their containers. In order to do that, it defines
// and implements callback functions that are called on Kubernetes pod watcher events.
// It also exposes APIs to read the saved metadata.
//
// During initialization, the manager checks for a valid base cgroup path.
// In case of environments using non-default cgroup base paths, manager will
// fail to get a valid cgroup base path, and ignore all the subsequent pod events.
type Manager struct {
	// Map of pod metadata indexed by their ids
	podMetadataById map[string]*podMetadata
	// Map of container metadata indexed by their cgroup ids
	containerMetadataByCgrpId map[uint64]*containerMetadata
	// Set to the valid cgroup base path if found
	templateCgroupBasePath string
	// Buffered channel to receive pod events
	podEvents chan podEvent
	// Object to check cgroup base path
	checkCgroupPath *sync.Once
	// Flag to check if manager is enabled, and processing events
	enabled atomic.Bool
	// Channel to shut down manager
	shutdown chan struct{}
	// Interface to do file operations
	fschecker fs
	// Interface to do cgroups related operations
	cgroupsChecker cgroup
}

type PodMetadata struct {
	Name      string
	Namespace string
	IPs       []v1.PodIP
}

const (
	PodAddEvent = iota
	PodUpdateEvent
	PodDeleteEvent
	PodMetadataEvent
)

func NewManager() *Manager {
	m := &Manager{
		podMetadataById:           make(map[string]*podMetadata),
		containerMetadataByCgrpId: make(map[uint64]*containerMetadata),
		podEvents:                 make(chan podEvent, 20),
		shutdown:                  make(chan struct{}),
	}
	m.fschecker = fsImpl{}
	m.cgroupsChecker = cgroupImpl{}
	m.checkCgroupPath = new(sync.Once)

	m.enable()

	return m
}

func (m *Manager) OnAddPod(pod *v1.Pod) {
	if pod.Spec.NodeName != nodetypes.GetName() {
		return
	}
	m.podEvents <- podEvent{
		pod:       pod,
		eventType: PodAddEvent,
	}
}

func (m *Manager) OnUpdatePod(oldPod, newPod *v1.Pod) {
	if newPod.Spec.NodeName != nodetypes.GetName() {
		return
	}
	m.podEvents <- podEvent{
		pod:       newPod,
		oldPod:    oldPod,
		eventType: PodUpdateEvent,
	}
}

func (m *Manager) OnDeletePod(pod *v1.Pod) {
	if pod.Spec.NodeName != nodetypes.GetName() {
		return
	}
	m.podEvents <- podEvent{
		pod:       pod,
		eventType: PodDeleteEvent,
	}
}

// GetParentPodMetadata returns parent pod metadata for the given container
// cgroup id in case of success, or nil otherwise.
func (m *Manager) GetParentPodMetadata(cgroupId uint64) *PodMetadata {
	if !m.enabled.Load() {
		return nil
	}
	podMetaOut := make(chan *PodMetadata)

	m.podEvents <- podEvent{
		cgroupId:       cgroupId,
		eventType:      PodMetadataEvent,
		podMetadataOut: podMetaOut,
	}
	select {
	// We either receive pod metadata, or zero value when the channel is closed.
	case pm := <-podMetaOut:
		return pm
	}
}

// Close should only be called once from daemon close.
func (m *Manager) Close() {
	close(m.shutdown)
}

type podMetadata struct {
	name       string
	namespace  string
	id         string
	ips        []v1.PodIP
	containers map[string]struct{}
}

type containerMetadata struct {
	cgroupId    uint64
	cgroupPath  string
	parentPodId string
}

type podEvent struct {
	pod            *v1.Pod
	oldPod         *v1.Pod
	cgroupId       uint64
	eventType      int
	podMetadataOut chan *PodMetadata
}

type fs interface {
	Stat(name string) (os.FileInfo, error)
}

type cgroup interface {
	GetCgroupID(cgroupPath string) (uint64, error)
}

type fsImpl struct{}

func (f fsImpl) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

type cgroupImpl struct{}

func (c cgroupImpl) GetCgroupID(cgroupPath string) (uint64, error) {
	return cgroups.GetCgroupID(cgroupPath)
}

func (m *Manager) enable() {
	enable := option.Config.Opts.IsEnabled(option.TraceSockNotify)
	m.checkCgroupPath.Do(func() {
		for _, path := range cgroupBasePaths {
			if _, err := m.fschecker.Stat(path); err != nil {
				log.Infof("path %s err: %v", path, err)
				continue
			}
			m.templateCgroupBasePath = path
			break
		}
		if m.templateCgroupBasePath == "" {
			// log.Warnf("No valid cgroup base path found: socket " +
			// 	"load-balancing tracing feature will not work")
			log.Info("No valid cgroup base path found: socket " +
				"load-balancing tracing feature will not work")
			m.dumpFiles(true)
			// enable = false
		}
	})

	m.enabled.Store(enable)
	if enable {
		log.Info("Metadata manager is enabled")
		go m.processPodEvents()
	}
}

func (m *Manager) processPodEvents() {
	for {
		select {
		case ev := <-m.podEvents:
			if !m.enabled.Load() {
				return
			}
			switch ev.eventType {
			case PodAddEvent, PodUpdateEvent:
				m.updatePodMetadata(ev.pod, ev.oldPod)
			case PodDeleteEvent:
				m.deletePodMetadata(ev.pod)
			case PodMetadataEvent:
				m.getParentPodMetadata(ev.cgroupId, ev.podMetadataOut)
			}
		case <-m.shutdown:
			return
		}
	}
}

func (m *Manager) updatePodMetadata(pod, oldPod *v1.Pod) {
	id := string(pod.ObjectMeta.UID)
	pm, ok := m.podMetadataById[id]
	if !ok {
		// Fill in pod static metadata.
		pm = &podMetadata{
			// TODO: remove id?
			id:        id,
			name:      pod.Name,
			namespace: pod.Namespace,
		}
		m.podMetadataById[id] = pm
	}
	if oldPod != nil && oldPod.Status.DeepEqual(&pod.Status) {
		return
	}
	// Only update the metadata that can change. This excludes pod's name,
	// namespace, id, and qos class.
	podIPs := pod.Status.PodIPs
	pm.ips = make([]v1.PodIP, len(podIPs))
	for i := range podIPs {
		pm.ips[i] = podIPs[i]
	}
	// Get metadata for pod's containers that are in the running state. Containers
	// can get re-created, and their ids can change. Update the new containers.
	// Pod's metadata including its containers map will be deleted when the pod
	// is deleted.
	numContainers := len(pod.Status.ContainerStatuses)
	if pm.containers == nil && numContainers > 0 {
		pm.containers = make(map[string]struct{})
	}
	currContainers := make(map[string]struct{}, numContainers)
	for _, c := range pod.Status.ContainerStatuses {
		var cId string
		if cId = c.ContainerID; cId == "" || c.State.Running == nil {
			continue
		}
		// The container ID field is of the form: <container-runtime>://<containerID>
		// Example:containerd://e275d1a37782ab30008aa3ae6666cccefe53b3a14a2ab5a8dc459939107c8c0e
		_, after, found := strings.Cut(cId, "//")
		if !found || after == "" {
			log.Errorf("unexpected container ID: %s", cId)
			continue
		}
		cId = after
		if _, ok := pm.containers[cId]; ok {
			currContainers[cId] = struct{}{}
			// Container cgroup path doesn't change as long as the container id
			// is the same.
			continue
		}
		pm.containers[cId] = struct{}{}
		currContainers[cId] = struct{}{}

		// Container could've been gone, so don't log any errors.
		cgrpPath, err := m.getContainerCgroupPath(id, cId, pod.Status.QOSClass)
		if err != nil {
			log.Debugf("failed to get container metadata for (%s): %v", cId, err)
			continue
		}
		cgrpId, err := m.cgroupsChecker.GetCgroupID(cgrpPath)
		if err != nil {
			log.Debugf("failed to get cgroup id for cgroup path (%s): %v", cgrpPath, err)
			continue
		}
		log.Infof("aditi-debug-metadata %s %d", cgrpPath, cgrpId)
		m.containerMetadataByCgrpId[cgrpId] = &containerMetadata{
			cgroupId:    cgrpId,
			cgroupPath:  cgrpPath,
			parentPodId: id,
		}
	}
	// Clean up any pod's old containers.
	if oldPod != nil {
		for _, c := range oldPod.Status.ContainerStatuses {
			if _, ok := currContainers[c.ContainerID]; !ok {
				delete(pm.containers, c.ContainerID)
			}
		}
	}
}

func (m *Manager) dumpFiles(iskind bool) {
	dir := defaults.DefaultCgroupRoot
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		name := file.Name()
		if strings.Contains(name, "kubepods") || strings.Contains(name, "pod") {
			log.Infof("aditi-debug %s", name)
		} else {
			log.Infof("others %s", name)
		}
	}
}

func (m *Manager) deletePodMetadata(pod *v1.Pod) {
	id := string(pod.ObjectMeta.UID)

	if _, ok := m.podMetadataById[id]; !ok {
		return
	}
	for k, cm := range m.containerMetadataByCgrpId {
		if cm.parentPodId == id {
			delete(m.containerMetadataByCgrpId, k)
		}
	}
	delete(m.podMetadataById, id)
}

func (m *Manager) getParentPodMetadata(cgroupId uint64, podMetadataOut chan *PodMetadata) {
	cm, ok := m.containerMetadataByCgrpId[cgroupId]
	if !ok {
		log.Debugf("Metadata not found for container: %d", cgroupId)
		close(podMetadataOut)
		return
	}

	pm, ok := m.podMetadataById[cm.parentPodId]
	if !ok {
		log.Debugf("Parent pod metadata not found for container: %d", cgroupId)
		close(podMetadataOut)
		return
	}
	podMetadata := PodMetadata{
		Name:      pm.name,
		Namespace: pm.namespace,
	}
	podMetadata.IPs = append(podMetadata.IPs, pm.ips...)
	log.Debugf("Parent pod metadata for container (%d): %+v", cgroupId, podMetadata)

	podMetadataOut <- &podMetadata
	close(podMetadataOut)
}

func (m *Manager) baseCgroupPathForQos(path string, qos v1.PodQOSClass) string {
	if qos == v1.PodQOSGuaranteed {
		return fmt.Sprintf("%s", path)
	}
	return fmt.Sprintf("%s/%s", path, strings.ToLower(string(qos)))
}

func (m *Manager) getContainerCgroupPath(podId string, containerId string, containerQos v1.PodQOSClass) (string, error) {
	if m.templateCgroupBasePath == "" {
		return "", fmt.Errorf("failed to get cgroup path for (%s)", containerId)
	}

	return fmt.Sprintf("%s/pod%s/%s", m.baseCgroupPathForQos(m.templateCgroupBasePath, containerQos),
		podId, containerId), nil
}

func newManagerTest(fs fs, cg cgroup) *Manager {
	m := &Manager{
		podMetadataById:           make(map[string]*podMetadata),
		containerMetadataByCgrpId: make(map[uint64]*containerMetadata),
		podEvents:                 make(chan podEvent, 20),
		shutdown:                  make(chan struct{}),
	}
	m.fschecker = fs
	m.cgroupsChecker = cg
	m.checkCgroupPath = new(sync.Once)

	m.enable()

	return m
}
