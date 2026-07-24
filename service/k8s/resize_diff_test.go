package k8s

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func basePodSpec() *corev1.PodSpec {
	return &corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name:  "redis",
				Image: "redis:7",
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("2Gi")},
				},
			},
		},
	}
}

func TestIsResourceOnlyChange_ResourcesOnlyDiffers(t *testing.T) {
	oldSpec := basePodSpec()
	newSpec := basePodSpec()
	newSpec.Containers[0].Resources.Requests[corev1.ResourceMemory] = resource.MustParse("4Gi")

	assert.True(t, isResourceOnlyChange(oldSpec, newSpec))
}

func TestIsResourceOnlyChange_NoDiffAtAll(t *testing.T) {
	oldSpec := basePodSpec()
	newSpec := basePodSpec()

	assert.True(t, isResourceOnlyChange(oldSpec, newSpec))
}

func TestIsResourceOnlyChange_ImageAlsoChanged(t *testing.T) {
	oldSpec := basePodSpec()
	newSpec := basePodSpec()
	newSpec.Containers[0].Resources.Requests[corev1.ResourceMemory] = resource.MustParse("4Gi")
	newSpec.Containers[0].Image = "redis:8"

	assert.False(t, isResourceOnlyChange(oldSpec, newSpec))
}

func TestIsResourceOnlyChange_CPUOnlyDiffers(t *testing.T) {
	oldSpec := basePodSpec()
	newSpec := basePodSpec()
	newSpec.Containers[0].Resources.Requests[corev1.ResourceCPU] = resource.MustParse("500m")

	assert.True(t, isResourceOnlyChange(oldSpec, newSpec))
}

func TestIsResourceOnlyChange_EnvVarAlsoChanged(t *testing.T) {
	oldSpec := basePodSpec()
	newSpec := basePodSpec()
	newSpec.Containers[0].Resources.Requests[corev1.ResourceMemory] = resource.MustParse("4Gi")
	newSpec.Containers[0].Env = []corev1.EnvVar{{Name: "FOO", Value: "bar"}}

	assert.False(t, isResourceOnlyChange(oldSpec, newSpec))
}
