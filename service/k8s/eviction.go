package k8s

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"

	"github.com/freshworks/redis-operator/log"
	"github.com/freshworks/redis-operator/metrics"
)

// Eviction knows how to list and evict pods across the cluster. It is used to free
// node headroom (e.g. evicting other RedisFailovers' slave pods co-located on a node)
// ahead of resizing a master pod in place.
type Eviction interface {
	// GetNode retrieves a Node, used to read its Status.Allocatable capacity.
	GetNode(name string) (*corev1.Node, error)
	// ListPodsOnNode lists pods across all namespaces scheduled on nodeName, matching labelSelector.
	ListPodsOnNode(nodeName, labelSelector string) (*corev1.PodList, error)
	// EvictPod evicts a pod via the eviction subresource, which honors PodDisruptionBudgets
	// (unlike a raw delete).
	EvictPod(namespace, podName string) error
}

// EvictionService is the Eviction service implementation using API calls to kubernetes.
type EvictionService struct {
	kubeClient      kubernetes.Interface
	logger          log.Logger
	metricsRecorder metrics.Recorder
}

// NewEvictionService returns a new Eviction KubeService.
func NewEvictionService(kubeClient kubernetes.Interface, logger log.Logger, metricsRecorder metrics.Recorder) *EvictionService {
	logger = logger.With("service", "k8s.eviction")
	return &EvictionService{
		kubeClient:      kubeClient,
		logger:          logger,
		metricsRecorder: metricsRecorder,
	}
}

func (e *EvictionService) GetNode(name string) (*corev1.Node, error) {
	node, err := e.kubeClient.CoreV1().Nodes().Get(context.TODO(), name, metav1.GetOptions{})
	recordMetrics(metav1.NamespaceAll, "Node", name, "GET", err, e.metricsRecorder)
	return node, err
}

func (e *EvictionService) ListPodsOnNode(nodeName, labelSelector string) (*corev1.PodList, error) {
	pods, err := e.kubeClient.CoreV1().Pods(metav1.NamespaceAll).List(context.TODO(), metav1.ListOptions{
		LabelSelector: labelSelector,
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", nodeName).String(),
	})
	recordMetrics(metav1.NamespaceAll, "Pod", metrics.NOT_APPLICABLE, "LIST", err, e.metricsRecorder)
	return pods, err
}

func (e *EvictionService) EvictPod(namespace, podName string) error {
	eviction := &policyv1.Eviction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
		},
	}
	err := e.kubeClient.CoreV1().Pods(namespace).EvictV1(context.TODO(), eviction)
	recordMetrics(namespace, "Pod", podName, "EVICT", err, e.metricsRecorder)
	if err != nil {
		e.logger.WithField("namespace", namespace).WithField("pod", podName).Errorf("evict pod failed: %v", err)
		return err
	}
	e.logger.WithField("namespace", namespace).WithField("pod", podName).Infof("pod evicted")
	return nil
}
