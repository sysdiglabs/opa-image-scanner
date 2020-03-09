package admissionserver

import (
	"image-scan-webhook/pkg/opaimagescanner"
	"sync"

	"k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
)

type admissionHook struct {
	evaluator         opaimagescanner.AdmissionEvaluator
	reservationClient dynamic.ResourceInterface
	lock              sync.RWMutex
	initialized       bool
}

type mutationHook struct {
	evaluator         opaimagescanner.AdmissionEvaluator
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
