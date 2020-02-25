# Validation admission Webhook


# Notes:

In the webhook.yaml, we cannot include "v1" in the list of admissionReviewVersions:

```
  admissionReviewVersions: ["v1", "v1beta1"]
```

or we get an error like:

```
W0224 13:42:42.303366       1 dispatcher.go:128] Failed calling webhook, failing open image-scan-policy-api.sysdig.com: failed calling webhook "image-scan-policy-api.sysdig.com": AdmissionReview in version "v1" cannot be handled as a AdmissionReview: no kind "AdmissionReview" is registered for version "admission.k8s.io/v1" in scheme "pkg/runtime/scheme.go:101"

E0224 13:42:42.303785       1 dispatcher.go:129] failed calling webhook "image-scan-policy-api.sysdig.com": AdmissionReview in version "v1" cannot be handled as a AdmissionReview: no kind "AdmissionReview" is registered for version "admission.k8s.io/v1" in scheme "pkg/runtime/scheme.go:101"
```

TODO: Check if this can be fixed