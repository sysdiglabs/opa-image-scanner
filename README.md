# Validation admission Webhook

## Usage

### Defining OPA rules

* Rules must be defined using *rego* expressions
* There must exist a package *imageadmission*
* Package imageadmission should define rejection rules like *deny_image[msg]*, where msg 
* The admission controller will evaluate the expression **imageadmission.deny_image**, and in case it does not yield an empty list (so there are one or more possible values of *msg*), pod will be rejected.
* Rules must be deployed as a configmap names **image-scan-rules** inside a **rules.rego** key, like:

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: image-scan-rules
  namespace: sysdig-image-scan
data:
  rules.rego: |
        package imageadmission

        allow_image {
                input.ScanReport.Passed == true
        }

        deny_image[msg] {
                not allow_image
                msg := sprintf("Denying images by default. Status: %s", [input.ScanReport.Status])
        }

        ...

```

### Input format

input.ScanReport.Status can be one of:

* "accepted": The image scanner verified and found no issues according to defined policies.
* "rejected": The image was rejected by the scanner, as it violated some of the defined policies-
* "scan_failed": It was not possible to trigger the scan of the image.
* "report_not_available": The scan report is not yet available. Scan has not finished yet.
* ... (make different scan failure reasons - authentication / image not found / ...)

### Examples

#### Allow if the image scanner accepted the image

```
package imageadmission

allow_image {
        input.ScanReport.Status == "accepted"
}

deny_image[msg] {
  not allow_image
  msg := sprintf("Denying images by default. Status: %s", [input.ScanReport.Status])
}
```

#### Always allow images in the "dev" namespace

```
package imageadmission

allow_image {
  input.ScanReport.Status == "accepted"
}

allow_image {
  input.AdmissionRequest.object.metadata.namespace == "dev"
}

deny_image[msg] {
  not allow_image
  msg := sprintf("Denying images by default. Status: %s", [input.ScanReport.Status])
}
```

#### Always allow images coming from a whitelisted registry

```
package imageadmission

allowedRegistry := "mysaferegistry.io/"


allow_image {
  input.ScanReport.Status == "accepted"
}

allow_image {
  startswith(input.ScanReport.ImageAndTag, allowedRegistry)
}

deny_image[msg] {
  not allow_image
  msg := sprintf("Denying images by default. Status: %s", [input.ScanReport.Status])
}
```

#### Reject images from a specific registry

```
package imageadmission

blackListedRegistry := "badregistry.io/"


allow_image {
  input.ScanReport.Status == "accepted"
}

deny_image[msg] {
  startswith(input.ScanReport.ImageAndTag, blackListedRegistry)
  msg := "Deny blacklisted registry"
}

deny_image[msg] {
  not allow_image
  msg := sprintf("Denying images by default. Status: %s", [input.ScanReport.Status])
}
```

## Implementation Notes:

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