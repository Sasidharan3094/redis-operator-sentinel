package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func mustQty(s string) resource.Quantity {
	return resource.MustParse(s)
}

func candidateNames(cs []evictionCandidate) []string {
	names := make([]string, len(cs))
	for i, c := range cs {
		names[i] = c.Name
	}
	return names
}

func TestSelectEvictionSet_MemoryOnly(t *testing.T) {
	// The worked example from the design: candidates {4, 3, 5, 1} GB memory, required 10 GB
	// memory, no CPU requirement. Minimal-pod-count, minimal-waste answer is {5, 4, 1} = 10
	// (waste 0), not {5, 4, 3} = 12 (waste 2), even though both are valid 3-pod covers.
	candidates := []evictionCandidate{
		{Namespace: "ns", Name: "four", Memory: mustQty("4Gi")},
		{Namespace: "ns", Name: "three", Memory: mustQty("3Gi")},
		{Namespace: "ns", Name: "five", Memory: mustQty("5Gi")},
		{Namespace: "ns", Name: "one", Memory: mustQty("1Gi")},
	}

	chosen := selectEvictionSet(candidates, mustQty("0"), mustQty("10Gi"))

	assert.Len(t, chosen, 3)
	assert.ElementsMatch(t, []string{"five", "four", "one"}, candidateNames(chosen))
}

func TestSelectEvictionSet_CPUOnly(t *testing.T) {
	// Same shape as the memory worked example, but the requirement is CPU-only (no memory
	// requested at all) - proves the CPU dimension drives selection on its own, case 1 from
	// the "cpu only / memory only / both" split.
	candidates := []evictionCandidate{
		{Namespace: "ns", Name: "four", CPU: mustQty("4")},
		{Namespace: "ns", Name: "three", CPU: mustQty("3")},
		{Namespace: "ns", Name: "five", CPU: mustQty("5")},
		{Namespace: "ns", Name: "one", CPU: mustQty("1")},
	}

	chosen := selectEvictionSet(candidates, mustQty("10"), mustQty("0"))

	assert.Len(t, chosen, 3)
	assert.ElementsMatch(t, []string{"five", "four", "one"}, candidateNames(chosen))
}

func TestSelectEvictionSet_BothRequired(t *testing.T) {
	// Case 3: both CPU and memory are short, and the best per-dimension choice differs -
	// proves the subset must satisfy both constraints together, not just one.
	//   A: cpu=2, mem=1   B: cpu=1, mem=4   C: cpu=3, mem=2
	// required: cpu=3, mem=4
	// No single candidate qualifies. Of the covering pairs, {A,B} (cpu=3,mem=5, waste 0.25)
	// beats {B,C} (cpu=4,mem=6, waste 0.833); {A,C} doesn't cover memory at all (mem=3 < 4).
	a := evictionCandidate{Namespace: "ns", Name: "a", CPU: mustQty("2"), Memory: mustQty("1Gi")}
	b := evictionCandidate{Namespace: "ns", Name: "b", CPU: mustQty("1"), Memory: mustQty("4Gi")}
	c := evictionCandidate{Namespace: "ns", Name: "c", CPU: mustQty("3"), Memory: mustQty("2Gi")}

	chosen := selectEvictionSet([]evictionCandidate{a, b, c}, mustQty("3"), mustQty("4Gi"))

	assert.Len(t, chosen, 2)
	assert.ElementsMatch(t, []string{"a", "b"}, candidateNames(chosen))
}

func TestSelectEvictionSet_NoSingleOrPairCovers(t *testing.T) {
	// Sanity check on the size-first search order: with candidates {4,3,5,1} and a
	// target of 10, no size-1 or size-2 subset should ever be returned (max pair is 5+4=9).
	candidates := []evictionCandidate{
		{Namespace: "ns", Name: "four", Memory: mustQty("4Gi")},
		{Namespace: "ns", Name: "three", Memory: mustQty("3Gi")},
		{Namespace: "ns", Name: "five", Memory: mustQty("5Gi")},
		{Namespace: "ns", Name: "one", Memory: mustQty("1Gi")},
	}

	chosen := selectEvictionSet(candidates, mustQty("0"), mustQty("10Gi"))
	assert.GreaterOrEqual(t, len(chosen), 3)
}

func TestSelectEvictionSet_Infeasible(t *testing.T) {
	// Even taking every candidate isn't enough - must return nil, not the best-effort subset.
	candidates := []evictionCandidate{
		{Namespace: "ns", Name: "a", Memory: mustQty("1Gi")},
		{Namespace: "ns", Name: "b", Memory: mustQty("2Gi")},
	}

	chosen := selectEvictionSet(candidates, mustQty("0"), mustQty("10Gi"))
	assert.Nil(t, chosen)
}

func TestSelectEvictionSet_InfeasibleOnOneDimensionOnly(t *testing.T) {
	// Memory is easily covered, but CPU never is - must still return nil overall, since
	// qualifies() requires both.
	candidates := []evictionCandidate{
		{Namespace: "ns", Name: "a", CPU: mustQty("100m"), Memory: mustQty("8Gi")},
		{Namespace: "ns", Name: "b", CPU: mustQty("100m"), Memory: mustQty("8Gi")},
	}

	chosen := selectEvictionSet(candidates, mustQty("10"), mustQty("1Gi"))
	assert.Nil(t, chosen)
}

func TestSelectEvictionSet_ExactSingleMatch(t *testing.T) {
	candidates := []evictionCandidate{
		{Namespace: "ns", Name: "small", Memory: mustQty("2Gi")},
		{Namespace: "ns", Name: "exact", Memory: mustQty("5Gi")},
		{Namespace: "ns", Name: "big", Memory: mustQty("8Gi")},
	}

	chosen := selectEvictionSet(candidates, mustQty("0"), mustQty("5Gi"))
	assert.Len(t, chosen, 1)
	assert.Equal(t, "exact", chosen[0].Name)
}

func TestSelectEvictionSetGreedy_FallsBackAboveExhaustiveCap(t *testing.T) {
	// Above maxExhaustiveCandidates, selectEvictionSet must delegate to the greedy
	// fallback rather than attempting a combinatorial search.
	var candidates []evictionCandidate
	for i := 0; i < maxExhaustiveCandidates+1; i++ {
		candidates = append(candidates, evictionCandidate{
			Namespace: "ns",
			Name:      "pod",
			Memory:    mustQty("1Gi"),
		})
	}

	chosen := selectEvictionSet(candidates, mustQty("0"), mustQty("3Gi"))
	assert.NotNil(t, chosen)
	assert.GreaterOrEqual(t, len(chosen), 3)
}

func TestBuildEvictionPool_ExcludesSameRedisFailover(t *testing.T) {
	pods := &corev1.PodList{
		Items: []corev1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "other-endpoint-slave",
					Namespace: "ns",
					Labels:    map[string]string{redisFailoverNameLabelKey: "other-endpoint"},
				},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceMemory: mustQty("2Gi")}},
				}}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "same-endpoint-slave",
					Namespace: "ns",
					Labels:    map[string]string{redisFailoverNameLabelKey: "target-endpoint"},
				},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceMemory: mustQty("2Gi")}},
				}}},
			},
		},
	}

	pool := buildEvictionPool(pods, "target-endpoint")

	assert.Len(t, pool, 1)
	assert.Equal(t, "other-endpoint-slave", pool[0].Name)
}

func TestRemoveCandidate(t *testing.T) {
	pool := []evictionCandidate{
		{Namespace: "ns", Name: "a", Memory: mustQty("1Gi")},
		{Namespace: "ns", Name: "b", Memory: mustQty("2Gi")},
	}

	remaining := removeCandidate(pool, evictionCandidate{Namespace: "ns", Name: "a"})

	assert.Len(t, remaining, 1)
	assert.Equal(t, "b", remaining[0].Name)
}
