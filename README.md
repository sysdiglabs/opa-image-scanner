# OPA Image Scanner admission controller
![CircleCI](https://circleci.com/gh/sysdiglabs/opa-image-scanner.svg?style=svg) ![last commit](https://flat.badgen.net/github/last-commit/airadier/image-scan-webhook?icon=github) ![license](https://flat.badgen.net/github/license/airadier/cloud-native-security-hub)

Table of contents:
* [Overview](#overview)
* [Installation](#installation)
* [Evaluation Engine](#evaluation-engine)
* [Configuration Examples](#configuration-examples)

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

### Mutating admission controller

Apart from the image scanning evaluation, the admission controller is not just validating, but also **mutating** the Pod by changing the image tag to use the sha256 digest of the image manifest instead.

You might wonder, why mutate the pod spec to use the image digest instead? Using the tag in the scan and then in the pod scheduling you are exposed to a TOCTOU (Time-of-check Time-of-use) issue. Basically, the image that is scanned can differ from the image that is pulled for the container when the pod is scheduled, if a different version of the image is pushed to the registry under the same tag between the check (scan) and the use (pod scheduling and image pull).

The admission controller mutates the pod to use the image digest instead of the tag name, preventing this issue by making sure that the same image that is scanned is deployed in the cluster whatever scheduling events occur in the future. The image and tag names are kept as annotations in the pod, in case you want to know the retrieve the original image tag.


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
 * Create the webhook deployment and service.
 * Create two ConfigMap(s) with a predefined set of rules to cover most common use cases:
   * RELEASENAME-pre-scan-rules for the pre-scan rules (if **preScanPolicies.autoGenerate** is set to *true*).
   * RELEASENAME-post-scan-rules for the post-scan rules (if **scanPolicies.autoGenerate** is set to *true*).
 * Create a *RELEASENAME-policy* ConfigMap with a JSON dump of the **scanPolicies** and **preScanPolicies** settings in *values.yaml*. The value of these JSON settings change the evaluation of the OPA rules.

### Customize the settings

The default settings in *values.yaml* should be right for most cases, but you need to provide at least:

* **sysdigSecureToken** - The Sysdig Secure Token for your account
* **sysdigSecureApiUrl** - if the default SaS URL does not fit your environment (in case you are using the onPrem version of Sysdig Secure
  
If you set the value **verboseLog** to *true*, the OPA engine will include additional information in the output logs, like the input (AdmissionReview and ScanReport), the data, and the rules being evaluated. This can help debugging issues with the rule by copying the information and testing in the [Rego Playground](https://play.openpolicyagent.org/).

### Evaluation rules

In the *values.yaml* you will some sections that define the policies applied when evaluating whether to admit or reject the images in the cluster, and allow further customization of the evaluation rules.

To fully understand all the available options, please check the [Evaluation Engine](#evaluation-engine) section.

#### preScanPolicies

This section defines the behavior (general, per namespace, or per registry/repository/tag) to apply for images before they are sent to the image scanner.

```yaml
preScanPolicies:

  autoGenerate: true

  defaultPolicy: scan

  customPolicies:
    - prefix: "some-registry.com/whitelistedrepo"
      action: accept
    - prefix: "bad-registry.com/"
      action: reject
  
  byNamespace:
    playground:
      defaultPolicy: accept
      customPolicies: []
```

Setting the *autoGenerate* value to true will automatically generate some OPA rules for the evaluation engine that make pre-scan decissions based on the values of this section. If *autoGenerate* is set to false, the following does not apply. See [Evaluation Engine](#evaluation-engine) for more information.

In this example we set the *defaultPolicy* to *scan*, so by default, in any namespace, images would be scanned. Then, for namespace *playground* we override the *defaultPolicy* to *accept* all images by default.

We also define a *customPolicies* list so for images prefixed with *some-registry.com/whitelistedrepo* we accept images without scanning them (this could be a trusted repository from an internal registry). But we also add *bad-registry.com/* to the custom policies so all images from this registry are rejected without scanning them.

For namespace *playground* we set *customPolicies* as an empty list. Otherwise the top-level *customPolicies* would apply instead, so we override this setting by defining it again in the namespace.

#### scanPolicies

The *scanPolicies* section defines the behavior for images being scanned (if they are not accepted/rejected in the pre-scan phase).

```yaml
scanPolicies:

  autoGenerate: true

  # Default admission policy to apply: [accept | reject | scan-result]
  defaultPolicy: scan-result
  # What should we do if the Scan Result is not yet available (scan in progress): [accept | reject]
  reportPending: reject
  # What should we do if the Scan has failed (wrong credentials, misconfiguration, etc.): [accept | reject]
  scanFailed: reject

  customPolicies:
    - prefix: "my-totally-trusted-registry.com/"
      action: accept
    - prefix: "bad-registry.com/"
      action: reject

  byNamespace:
    ns-prod:
      defaultPolicy: reject
      customPolicies:
      - prefix: "my-totally-trusted-registry.com/"
        action: accept
      - prefix: "docker.io/"
        action: scan-result
    ns-playground:
      defaultPolicy: accept
      customPolicies: []
```

Again, the *autoGenerate* value enables generation of some OPA rules for post-scan decissions. The settings on this section will have no effect otherwise. See [Evaluation Engine](#evaluation-engine) for more information.

Similar to the *preScanRules* section, we can define a general *defaultPolicy* behavior. **scan-result** in the example menas that the decission will depend on the image scanning report result. We override this in the *ns-playground* namespace to always *accept* images (although they will be scanned, and the scan report could be *failed*), and then in *ns-prod* to *reject* by default.

We can also define *customPolicies* for specific registries, repositories and tags. In the example we always *accept* images coming from *my-totally-trusted-registry.com*, and we always *reject* images coming from *bad-registry.com/*. We override the behavior in *ns-playground* by defining an empty list of *customPolicies* (so **all** images are always accepted), and for *ns-prod* namespace we override the *customPolicies* to also force evaluation of the scan report for images coming from *docker.io/*.

#### preCustomRules

This section allows you to define a raw string of rego rules for the pre-scan evaluation phase. This will be appended to the *autoGenerated* rules, in case the *autoGenerated* option is enabled for *preScanPolicies*.

```yaml
preCustomRules: |
      my_example_rule {
          # Some conditions... 
          false
      }

      other_rule {
          # Some other conditions...
          true
      }

      allow_pod {
          # Put conditions in here
          false
      }

      deny_pod["This is a custom deny message"] {
          my_example_rule
          other_rule
      }
```

the [Evaluation Engine](#evaluation-engine) will evalute *allow_pod* and *deny_pod[msg]* rules during the **pre-scan phase**, so these need to be defined.

#### customRules

Similarly, this section allows you to define a raw string of rego rules for the scan evaluation phase. This will be appended to the *autoGenerated* rules, in case the *autoGenerated* option is enabled for *scanPolicies*.

```yaml
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

the [Evaluation Engine](#evaluation-engine) will evalute *deny_image[msg]* rules during the **scan phase**, so these need to be defined.

### Changing settings after deploying with Helm

The *preScanPolicies* and *scanPolicies* values defined in the YAML files will be used by Helm templating system to create a ConfigMap named ***RELEASENAME*-policy**, where *RELEASENAME* is your Helm release name:

```yaml
apiVersion: v1
kind: ConfigMap
data:
  policy.json: |
    {
      "policies":
      {
        "autoGenerate": true,
        "byNamespace": {

...

        },
        "defaultPolicy": "scan-result",
        "reportPending": "reject",
        "scanFailed": "reject",
        "scanPolicyId": "policy_xxxx"
      },
      "preScanPolicies":
      {
        "autoGenerate": true,

...

        "defaultPolicy": "scan"
      }
    }
```

You can modify this ConfigMap and adjust the settings as you need, and the changes will be reflected after 1-2 minutes (https://kubernetes.io/docs/tasks/configure-pod-container/configure-pod-configmap/#mounted-configmaps-are-updated-automatically).

Also, two ConfigMaps are created for storing the *autoGenerate* OPA rules and your defined custom rules. It shouldn't be necessary to make any changes to these ConfigMaps unless you are writing or customizing the OPA rules.

* RELEASENAME-pre-scan-rules:

```yaml
kind: ConfigMap
apiVersion: v1
data:
  pre-scan-rules.rego: |
    package imageadmission
    # Helper variables
    namespace := input.AdmissionRequest.namespace
    policies := data.preScanPolicies

    ...

    ###### Begin: Custom rules ######

    my_example_rule {
        # Some conditions...
        false
    }

    ...

    ###### End: Custom rules ######

```

* RELEASENAME-post-scan-rules

```yaml
kind: ConfigMap
apiVersion: v1
data:
  pre-scan-rules.rego: |
    package imageadmission
    # Helper variables
    namespace := input.AdmissionRequest.namespace
    policies := data.policies

    ...

```

## Evaluation engine

When a pod is created or updated, a new *AdmissionRequest* is analyzed by the admission controller.

The admission controller will evaluate if the pod is admited or not in two phases: **pre-scan** and **scan** phase. On each phase, it will evaluate a set of OPA (written using rego language) rules using the available context, and then make a decision. 

Most of the inner details of the OPA engine are abstracted by a JSON configuration (stored in ***RELEASENAME-policy* ConfigMap**), so for most use cases it will enough understanding how the engine and phases work, and what are the available policy settings. Changing the JSON in this ConfigMap should covert most common use cases, and writing customized OPA rules should be necessary only for very specific cases.

### Evaluation phases

#### Pre-Scan phase

In this phase, the pod is evaluated as a whole. The final decision on this phase will be one of:
* **accept**: The pod is accepted, and no scan is required for any of the images.
* **reject**: The pod is rejected, and no scan is performed on any of the images.
* **scan**: No admission decision is done, and the pod progresses to the **scan phase**.

The engine will evaluate the rego rules from the *RELEASENAME-pre-scan-rules* ConfigMap, with the *preScanPolicies* settings from the *RELEASENAME-policy* ConfigMap, and the pod *AdmissionRequest* as input.

* If any *allow_pod* rule evaluates to *true*, then the Pod is **accepted**
* If any *deny_pod[reason]* rule is *true* for any *reason*, then the Pod is **rejected** and the list of *reason*(s) is included in the reject message.
* If no *allow_pod* or *deny_pod[reason]* evaluate to true, then the pod progresses to the **scan phase**.

In most cases, **you don't need to tackle with these rego rules**, as they are automatically generated and stored in the  *RELEASENAME-pre-scan-rules* ConfigMap. The settings, in JSON format, from the ***RELEASENAME-policy* ConfigMap** will modify the behavior of these rules, so you can change the values in the ***RELEASENAME-policy* ConfigMap** to customize the general behavior, or the per-namespace or per-prefix specific behavior.

The automatically generated rego rules will evaluate the pod, and *reject* if any of the images is rejected according to the settings, *accept* it if **all** the images are accepted, and move the pod to the **Scan phase** in case there is no accept/reject criteria.

#### Scan phase

In this phase, a image scan is triggered for every container inside the pod. Then, a decision is made for each image. All the images for the containers in a pod need to be accepted for the pod to be accepted. Otherwise, the pod will be rejected.

For each container image composing the pod, the engine will evaluate the rego rules from the *RELEASENAME-post-scan-rules* ConfigMap, with the *scanPolicies* settings from the ***RELEASENAME-policy* ConfigMap**, and the pod *AdmissionRequest* as well as the *scan report* as input.

* If any *deny_image[reason]* rule evalutes to *true*, then the Pod is **rejected** and the list of *reason*(s) is included in the reject message.
* Otherwise, the Pod is **accepted**

In most cases, **you don't need to tackle with these rego rules**, as they are automatically generated, and stored in the *RELEASENAME-pre-scan-rules* ConfigMap. The settings, in JSON format, from the ***RELEASENAME-policy* ConfigMap** will modify the behavior of these rules, so you can change the values in the ***RELEASENAME-policy* ConfigMap** to customize the general behavior, or the per-namespace or per-prefix specific behavior.

*Pod mutation*: When the scan is triggered, the digest of the image being scanned is recovered, and the pod specification is mutated to replace the tag with the sha256 digest of the image, making sure that the tag cannot be altered to point to a different image.

### Evaluation policies configuration

The ***RELEASENAME-policy* ConfigMap** contains a *policy.json* key (which is mapped to a file inside the image scanner pod) containing the raw JSON policies configuration:

```json
apiVersion: v1
kind: ConfigMap
data:
  policy.json: |
    {
      "policies":
      {
        ...
      },
      "preScanPolicies":
      {
        ...
      }
    }
```
...

the JSON contains a dictionary with a *preScanPolicies* key, and a *scanPolicies* key.

#### *preScanPolicies* configuration (Pre-scan Phase)

Example:

```json
    {
      ...,
      "preScanPolicies":
      {
        "defaultPolicy": "scan",
        "customPolicies": [
          {
            "prefix": "some-registry.com/whitelistedrepo/",
            "action": "accept"
          },
          {
            "prefix": "bad-registry.com/",
            "action": "reject"
          }
        ],
        "byNamespace": {
          "playground": {
            "customPolicies": [],
            "defaultPolicy": "accept"
          }
        }
      }
    }
```

* **defaultPolicy**: The *defaultPolicy* top-level definition sets the default behavior for any container image that does not match any more specific rule. Possible values are:
  * **accept**: the image will be accepted
  * **reject**: the image will rejected
  * **scan**: the image will be evaluated in **Scan Phase**
* **customPolicies**: The top-level *customPolicies* list sets specific behavior for images matching prefixes from the list. For each element in the list, the image name (composed of registry + repository:tag) is compared to the *prefix*. If the *prefix* matches the image (image name starts with this prefix), then the *action* is applied to that image, overriding the *defaultPolicy* action.
  * As *action* overrides the *defaultPolicy*, it can take the same values: **accept**, **reject** or **scan**. 
  * If the image name does not match any element in the *customPolicies* list, the *defaultPolicy* will be applied.
  * In the example, images from *some-registry.com/whitelistedrepo/* will be always accepted, and images from *bad-registry.com/* will always be rejected. Other images would progress to **Scan phase**.
* **byNamespace**: The *byNamespace* dictionary might contain entries for namespaces that want to override the top-level policies. For each namespace, the *defaultPolicy* setting or the *customPolicies* list can be specified, overriding the top-level settings for images deployed in that namespace.
  * If no *defaultPolicy* is defined for a namespace, the top-level setting is used.
  * If no *customPolicies* is defined for a namespac, the top-level list applies. You can define an empty list, like in the example's namespace *playground* 
  * In this example, for *playground* namespace all images would be accepted, and the top-level *customPolicies* would not apply inside that namespace.

⚠️ Please note that *customPolicies* have the highest priority. So, if a namespace defines a *defaultPolicy* but does not define *customPolicies*, then an image deployed in that namespace could match entries in the top-level *customPolicies* before the namespace *defaultPolicy* applies.


#### *policies* configuration (Scan Phase)

Example:

```json
    {
      "policies":
      {
        "defaultPolicy": "scan-result",
        "reportPending": "reject",
        "scanFailed": "reject",
        "customPolicies": [
          {
            "action": "accept",
            "prefix": "my-totally-trusted-registry.com/"
          },
          {
            "action": "reject",
            "prefix": "bad-registry.com/"
          }
        ],
        "byNamespace": {
          "ns-playground": {
            "customPolicies": [],
            "defaultPolicy": "accept"
          },
          "ns-prod": {
            "customPolicies": [
              {
                "action": "accept",
                "prefix": "my-totally-trusted-registry.com/"
              },
              {
                "action": "scan-result",
                "prefix": "docker.io/"
              }
            ],
            "defaultPolicy": "reject"
          }
        }
      },

      ...
    }
```

The settings for the Scan Phase are stored in the *policies* key inside the JSON, and are very similar to the *preScanPolicies* settings described in the previous section, so only the differences are described in here.

In the **Scan Phase**, a scan is triggered for the image, and then the scan report is retrieved. It can happen that:
* The scan report is already available and ready to evaluate.
* The scan failed, because the image does not exist, the scanner does not have the required credentials, etc.
* The scan is not yet available (scan is in progress).

So this conditions also impact the evaluation and need to be considered in the settings:

* **defaultPolicy**: Possible values are:
  * **accept**: image will be accepted, despite the scanning result.
  * **reject**: image will rejected, despite the scanning result.
  * **scan-result**: image will be accepted or rejected depending on the scanning result from the scan report.
* **reportPending**: What to do if the report is not yet available:
  * **accept**: accept the image. Once the image is admited, the admission control won't be triggered again until the pod is recreated.
  * **reject**: reject the image (default if not specified).
* **scanFailed**: Behavior in case the scan failed (wrong credentials, wrong image, etc):
  * **accept**
  * **reject** (default if not specified).
* **customPolicies**: Same behavior as the *customPolicies* list for *preScanPolicies*, but the *action* key can take any of the following values, with same meaning as *defaultPolicy* values:
  * **accept**
  * **reject**
  * **scan-result**
* **byNamespace**: Same as *byNamespace* for *preScanPolicies*, overrides the top-level behavior for *defaultPolicy* *reportPending*, *scanFailed* or *customPolicies* for specific namespaces.

Same priority as *preScanPolicies* applies: Namespace *customPolicies* have the highest priority, followed by top-level *customPolicies*, then namespace *defaultPolicy* and finally top-level *defaultPolicy*.

⚠️ **IMPORTANT NOTE** ⚠️: If an image is rejected, the pod creation will fail, and the corresponding Owner (Deployment, ReplicaSet, DaemonSet, etc.) will retry the creation, first after a few seconds, then slower, according to the exponential backoff retry mechanism. This means that, for example, pod creation could fail because the scan report is in progress, fail multiple times in a row, and then succeed a few minutes later, once the report is available and the exponential backoff mechanism retries the creation.


## Configuration examples

### Common use cases

#### List of valid registries

* Specify a list of “valid” registries. 
* Definition of “valid”: invalid registries will be DENIED always.
* “Valid” registries will be scanned
* Depending on the scan result, accept / reject image

⚠️ **Beware** ⚠️: you need to include per-namespace policies for *kube-system* or other critical namespaces.

```json
    {
      "preScanPolicies":
      {
        "defaultPolicy": "reject",
        "byNamespace": {
          "kube-system": {
            "customPolicies": [],
            "defaultPolicy": "accept"
          }
        },
        "customPolicies": [
          {
            "prefix": "valid-registry1.com/",
            "action": "scan"
          },
          {
            "prefix": "valid-registry2.com/",
            "action": "scan"
          }
        ],
      },
      "policies":
      {
        "defaultPolicy": "scan-result",
        "reportPending": "reject",
        "scanFailed": "reject"
      }
    }
```

#### Trigger scan, but always accept

All images should be accepted, but trigger an scan so you can configure alerts in the image scanner to detect vulnerabilities

```json
    {
      "preScanPolicies":
      {
        "defaultPolicy": "scan"
      },
      "policies":
      {
        "defaultPolicy": "accept"
      }
    }
```

#### Image whitelisting

* Some critical images are critical, and should be accepted (scan or not).
* Rest of images, depending on the scan result.

⚠️ **Beware** ⚠️: you need to include per-namespace policies for *kube-system* or other critical namespaces.

```json
    {
      "preScanPolicies":
      {
        "defaultPolicy": "scan",
        "byNamespace": {
          "kube-system": {
            "customPolicies": [],
            "defaultPolicy": "accept"
          }
        },
        "customPolicies": [
          {
            "prefix": "docker.io/some-critical-image",
            "action": "accept"
          }
        ]
      },
      "policies":
      {
        "defaultPolicy": "scan-result",
        "reportPending": "reject",
        "scanFailed": "reject"
      }
    }
```

or alternatively, if you want to also trigger a scan for the "critical images", although they will always be accepted no matter the scan result:

```json
    {
      "preScanPolicies":
      {
        "defaultPolicy": "scan"
      },
      "policies":
      {
        "defaultPolicy": "scan-result",
        "reportPending": "reject",
        "scanFailed": "reject",
        "byNamespace": {
          "kube-system": {
            "customPolicies": [],
            "defaultPolicy": "accept"
          }
        },
        "customPolicies": [
          {
            "prefix": "docker.io/some-critical-image",
            "action": "accept"
          }
        ]
      }
    }
```

### Defining custom OPA rules

Deploying via Helm charts and setting *autoGenerate* to *true* will create two Configmaps with a default set of rules for **Pre-Scan phase** and for **Scan phase** that behave according to the *preScanPolicies* and *scanPolicies* defined in the chart values.yaml (which are put into another ConfigMap). 

When the OPA rules are evaluated, the *scanPolicies* (or *preScanPolicies* for the Pre-Scan phase) defined in the values.yaml are passed as data.policies, and the rules are evaluated according to this policies, and according to the input (AdmissionReview and ScanReport).

You can disable the auto generated set of rules by setting *autoGenerate* false, and the Helm chart will only create the package directive, define the *namespace* variable, and assign the *policies* variable with the value of the defined policies, so you can write your own rules in the *customRules* key of the values.yaml.

In case you want to edit the ConfigMap manually or define your own rules, the following requirements apply:

For both Pre-Scan and Post-Scan rules:
* Rules must be defined using *rego* expressions.
* They must be declared inside a package named *imageadmission*.

For Pre-scan rules:
* Rules are deployed as a ConfigMap named **RELEASE-NAME-pre-scan.rules** inside a **pre-scan-rules.rego** key.
* Package *imageadmission* should define rejection rules like *allow_pod* or *deny_pod[msg]*, where *msg* is the rejection message.
* The admission controller will:
  * First evaluate the expression **imageadmission.allow_pod**, and if it evalutes to *true*, the pod will be admited.
  * Otherwise, it will evaluate the expression **imageamission.deny_pod[msg]** and in case it does not yield an empty list (so there are one or more possible values of *msg*), pod will be rejected.
  * It neither **imageadmission.allow_pod** or **imageadmission.deny_pod** yields any results, the pod will be go into the **Scan phase**.

For Post-scan rules:
* Rules are deployed as a ConfigMap named **RELEASE-NAME-post-scan.rules** inside a **post-scan-rules.rego** key.
* Package *imageadmission* should define rejection rules like *deny_image[msg]*, where *msg* is the rejection message.
* The admission controller will evaluate the expression **imageadmission.deny_image**, and in case it does not yield an empty list (so there are one or more possible values of *msg*), pod will be rejected. Otherwise, if the evaluation of **imageadmission.deny_image** yields no results, the pod will be admited.

An example configmap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sysdig-image-scanner-post-scan-rules
  namespace: sysdig-image-scanner
data:
  post-scan-rules.rego: |
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

#### Input format

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