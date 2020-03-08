package admissionserver

import (
	"sync"

	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
)

type AdmissionEvaluationContext struct {
	AdmissionRequest *v1beta1.AdmissionRequest
	PodObject        *corev1.Pod
}

type AdmissionEvaluator interface {
	Evaluate(c *AdmissionEvaluationContext) (accepted bool, errors []string)
}

type admissionHook struct {
	evaluator         AdmissionEvaluator
	reservationClient dynamic.ResourceInterface
	lock              sync.RWMutex
	initialized       bool
}

type mutationHook struct {
	evaluator         AdmissionEvaluator
	reservationClient dynamic.ResourceInterface
	lock              sync.RWMutex
	initialized       bool
}

// toAdmissionResponse is a helper function to create an AdmissionResponse
// with an embedded error
func toAdmissionResponse(err error) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}
