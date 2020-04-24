# OPA Image Scanner admission controller
![CircleCI](https://circleci.com/gh/sysdiglabs/opa-image-scanner.svg?style=svg) ![last commit](https://flat.badgen.net/github/last-commit/airadier/image-scan-webhook?icon=github) ![license](https://flat.badgen.net/github/license/airadier/cloud-native-security-hub)

## Overview

Sysdig’s OPA Image Scanner combines Sysdig Secure image scanner with OPA policy-based rego language to evaluate the scan results and the admission context, providing great flexibility on the admission decision.

If you are already using an image scanner, you might be already aware of some limitations. As you need to explicitly configure the set of scanned images, you might miss some images that end up running in your cluster, or end up scanning images that are never run. Additionally, the image scanner has limited information about the image it is scanning: only registry, image name and tag. With such a narrow context, it is not possible to make more advanced decisions. Do you need a “dev” namespace with more permissive rules, and a very restrictive production one that only allows images from a trusted registry and no vulnerabilities?

Our end goal in a cluster environment is to know if we can deploy an image based on the result of the scan and some additional information. Some common image scanning use cases include:
 * Allow the image if scanner policy evaluation accepted the image
 * Always allow images in a specific (i.e. “dev”) namespace
 * Deny images from untrusted registries
 * Allow images in a namespace if they come from a trusted registry and have no vulnerabilities
 * Etc.

Using a Kubernetes extensibility to perform the image scanning on admission controller and evaluating the result addresses the previous limitations. Scan is triggered just when required, for every image that is trying to be deployed in the cluster. 

The admission decision does not rely only on the image name and tag, but also on additional context from the admission review, which includes namespace, pod metadata, etc.

Using OPA and rego language to define the admission policy rules and evaluate the scan result along with the admission context provides great flexibility for taking informed decisions and resolving the most common image scanning use cases.

## Installation

The easiest way to deploy this admission controller on your cluster is using the helm charts available in this repository, folder `helm-charts`.

The admission controller is registered as a Kubernetes aggregated API server with mutual TLS authentication, and then it registers a Dynamic Admission Control webhook to intercept the creation or update of pod resources.

Just customize the settings in the values.yaml file, create the namespace and deploy using Helm 3.

The **sysdigSecureToken** value is mandatory.

```
$ cd helm-charts
$ kubectl create ns sysdig-image-scanner
$ helm install -n sysdig-image-scanner sysdig-image-scanner . 
```

After a few seconds, this chart will deploy all the required components, which include:
 * Creating certificates for webhook service authentication.
 * Register the aggregated API Service.
 * Register the mutating admission controller webhook.
 * Create required TLS certificates secret and Secure Token secret.
 * Create a service account for the webhook service pod(s).
 * Roles and permissions to allow the SA authenticate the API server, as well as permissions to delegate auth decisions to the Kubernetes core API server.
 * Create the webhook deployment and service
 * Create a ConfigMap with a predefined set of rules to cover most common use cases (if **scanPolicies.autoGenerate** is set to *true*)
 * Create a ConfigMap with a JSON dump of the **scanPolicies** settings in *values.yaml*. The value of these **scanPolicies** change the evaluation of the OPA rules.

### Mutating admission controller

You might wonder, why mutate the pod spec to use the image digest instead? Using the tag in the scan and then in the pod scheduling you are exposed to a TOCTOU (Time-of-check Time-of-use) issue. Basically the image that is scanned can differ from the image that is pulled for the container when the pod is scheduled, in different version of the image is pushed to the registry under the same tag.

The admission controller mutates the pod to use the image digest instead, preventing this issue by making sure that the same image that is scanned is deployed in the cluster whatever scheduling events occur in the future. The image and tag names are kept as annotations in the pod, in case you want to know the retrieve the original image tag.

### Customize the settings

The default settings in *values.yaml* should be right for most cases, but you need to provide at least:

* **sysdigSecureToken** - The Sysdig Secure Token for your account
* **sysdigSecureApiUrl** - if the default SaS URL does not fit your environment (in case you are using the onPrem version of Sysdig Secure
  
If you set the value **verboseLog** to *true*, the OPA engine will include additional information in the output logs, like the input (AdmissionReview and ScanReport), the data, and the rules being evaluated. This can help debugging issues with the rule by copying the information and testing in the [Rego Playground](https://play.openpolicyagent.org/).

### Evaluation rules

In the *values.yaml* you will find a **scanPolicies** section where you can set default policies for evaluating the images and scan reports and a **customRules** section:

```yaml
scanPolicies:
  # If set to "true", a default set of rules will be generated from this YAML values.
  # Otherwise, no rules will be generated, and only "customRules" below will apply
  autoGenerate: true
 
  # Default admission policy to apply: [accept | reject | scan-result]
  defaultPolicy: scan-result
 
  # What should we do if the Scan Result is not yet available (scan in progress): [accept | reject]
  reportPending: reject
 
  # What should we do if the Scan has failed (wrong credentials, misconfiguration, etc.): [accept | reject]
  scanFailed: reject
 
  alwaysAccept: []
 
  # These 2 registries will always be rejected unless 
  alwaysReject:
    - "bad-registry.com/"
    - "malware-registry.io/"
  
  alwaysScanResult: []
 
  byNamespace: {}
  #  ns-dev:
  #    # By default, images will be accepted in this NS regardless of the scan result
  #    defaultPolicy: accept
  #  ns-prod:
  #    # All images rejected by default in this namespace
  #    defaultPolicy: reject
  #    # Images from "my-trusted-registry.com/" will be always accepted
  #    alwasyAccept:
  #      - "my-trusted-registry.com/"
  #  ns-playground:
  #    defaultPolicy: accept
  #    alwaysReject: []

# Define a set of custom rego rules. If scanPolicies.autoGenerate is true, 
# these customRules are appended to the set of generated rules. 
# Otherwise, these customRules are the only rules definition,
customRules: |
      ###### Begin: Custom rules ######
      my_example_rule {
          # Some conditions... 
          false
      }
 
      other_rule {
          # Some other conditions...
          true
      }
 
      deny_image["This is a custom deny message"] {
          my_example_rule
          other_rule
      }
      ###### End: Custom rules ######
```

### Defining custom OPA rules

Deploying via Helm charts will create a Configmap with a default set of rules that behave according to the *scanPolicies* defined in the chart values.yaml (which are put into another ConfigMap). When the OPA rules are evaluated, the *scanPolicies* defined in the values.yaml are passed as data.policies, and the rules are evaluated according to this policies, and according to the input (AdmissionReview and ScanReport).

You can disable the auto generated set of rules by setting *autoGenerate* false, and the Helm chart will only create the package directive, define the *namespace* variable, and assign the *policies* variable with the value of the defined policies, so you can write your own rules in the *customRules* key of the values.yaml.

In case you want to edit the ConfigMap manually or define your own rules, the following requirements apply:

* Rules must be deployed as a ConfigMap named **image-scan-rules** inside a **rules.rego** key.
* Rules must be defined using *rego* expressions.
* They must be declared inside a package named *imageadmission*.
* Package *imageadmission* should define rejection rules like *deny_image[msg]*, where *msg* is the rejection message.
* The admission controller will evaluate the expression **imageadmission.deny_image**, and in case it does not yield an empty list (so there are one or more possible values of *msg*), pod will be rejected. Otherwise, if the evaluation of **imageadmission.deny_image** yields no results, the pod will be admited.

An example configmap:

```yaml
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

input.ScanReport.InnerReport contains the full JSON (converted to rego object) of the scan report, for example:

```json
{
    "ImageAndTag": "nginx:1.17.9",
    "Status": "accepted",
    "InnerReport": {
        "detail": {
            "policy": {
                                    ...
                ],
                "name": "Default Sysdig policy bundle",
                "policies": [
                    {
                        "comment": "System default policy",
                        "id": "default",
                        "name": "DefaultPolicy",
                        "rules": [
                            {
                                "action": "WARN",
                                "gate": "dockerfile",
                                "id": "rule_1FlJOnK9qdRSRcTNrfz3IUZXbou",
                                "params": [
                                    {
                                        "name": "instruction",
                                        "value": "HEALTHCHECK"
                                    },
                                    {
                                        "name": "check",
                                        "value": "not_exists"
                                    }
                                ],
                                "trigger": "instruction"
                            },
                            ...
                        ],
                        "version": "1_0"
                    },
                    ...
                ],
                "version": "1_0",
                "whitelisted_images": [],
                "whitelists": [
                    {
                        "comment": "Default global whitelist",
                        "id": "global",
                        "items": [],
                        "name": "Global Whitelist",
                        "version": "1_0"
                    }
                ]
            },
            "result": {
                "bundle": {
                    ...
                },
                "created_at": 1582633822,
                "evaluation_problems": [],
                "final_action": "warn",
                "final_action_reason": "policy_evaluation",
                "image_id": "c7460dfcab502275e9c842588df406444069c00a48d9a995619c243079a4c2f7",
                "last_modified": 1582633822,
                "matched_blacklisted_images_rule": false,
                "matched_mapping_rule": {
                    "id": "mapping_1CI5tw3zxNL9b344sSsXBfth3dW",
                    "image": {
                        "type": "tag",
                        "value": "*"
                    },
                    "name": "default",
                    "policy_ids": [
                        "default"
                    ],
                    "registry": "*",
                    "repository": "*",
                    "whitelist_ids": [
                        "global"
                    ]
                },
                "matched_whitelisted_images_rule": false,
                "result": {
                    "c7460dfcab502275e9c842588df406444069c00a48d9a995619c243079a4c2f7": {
                        "result": {
                            "final_action": "warn",
                            "header": [
                                "Image_Id",
                                "Repo_Tag",
                                "Trigger_Id",
                                "Gate",
                                "Trigger",
                                "Check_Output",
                                "Gate_Action",
                                "Whitelisted",
                                "Policy_Id"
                            ],
                            "row_count": 17,
                            "rows": [
                                [
                                    "c7460dfcab502275e9c842588df406444069c00a48d9a995619c243079a4c2f7",
                                    "docker.io/nginx:1.17.7",
                                    "41cb7cdf04850e33a11f80c42bf660b3",
                                    "dockerfile",
                                    "instruction",
                                    "Dockerfile directive 'HEALTHCHECK' not found, matching condition 'not_exists' check",
                                    "warn",
                                    false,
                                    "default"
                                ],
                                [
                                    "c7460dfcab502275e9c842588df406444069c00a48d9a995619c243079a4c2f7",
                                    "docker.io/nginx:1.17.7",
                                    "1571e70ee221127984dcf585a56d4cff",
                                    "dockerfile",
                                    "instruction",
                                    "Dockerfile directive 'USER' not found, matching condition 'not_exists' check",
                                    "warn",
                                    false,
                                    "default"
                                ],
                                ...
                            ]
                        }
                    },
                    "policy_data": [],
                    "policy_name": "",
                    "whitelist_data": [],
                    "whitelist_names": []
                },
                "tag": "docker.io/nginx:1.17.7",
                "user_id": "tenant_1TqQxfrhMuzrTAkZ5X7smleHiRe"
            }
        },
        "last_evaluation": "2020-02-25T12:30:22Z",
        "policyId": "default",
        "status": "pass"
    }
}

```

input.AdmissionRequest contains a Kubernetes Admission Request object, like:

```json
 
  "uid": "6870143b-55da-40be-b42f-3fc64799bd5d",
  "kind": {
    "group": "",
    "version": "v1",
    "kind": "Pod"
  },
  "resource": {
    "group": "",
    "version": "v1",
    "resource": "pods"
  },
...
```

you can find more info in https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#request and the full specification in https://godoc.org/k8s.io/api/admission/v1beta1#AdmissionRequest.

#### Rule Examples

##### Allow if the image scanner accepted the image

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

##### Always allow images in the "dev" namespace

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


##### Deny images from untrusted registries or with vulnerabilities

```
package imageadmission

allowedRegistry := "mysaferegistry.io/"


allow_image {
  input.ScanReport.Status == "accepted"
  startswith(input.ScanReport.ImageAndTag, allowedRegistry)

}

deny_image[msg] {
  not allow_image
  msg := sprintf("Denying images by default. Status: %s", [input.ScanReport.Status])
}
```

##### Always allow images coming from a trusted registry, and also "safe" images

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

##### Reject images from a specific registry

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

## Implementation Notes / TO-DO:

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