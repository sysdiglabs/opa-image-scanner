# Sysdig Admission Controller
![CircleCI](https://circleci.com/gh/draios/sysdig-admission-controller.svg?style=svg) ![last commit](https://flat.badgen.net/github/last-commit/draios/sysdig-admission-controller?icon=github) ![license](https://flat.badgen.net/github/license/draios/sysdig-admission-controller)

Table of contents:
* [Overview](#overview)
* [Installation](#installation)
* [Evaluation Engine](#evaluation-engine)
* [Configuration Examples](#configuration-examples)

## Overview

Sysdig’s Admission Controller combines Sysdig Secure image scanner with the rego based policy language to evaluate the scan results and the admission context, providing great flexibility on the admission decision.

Using native Kubernetes API extensions to perform the image scanning on admission enables major threat prevention and hardening use case: “Only the images that are explicitly approved will be allowed to run on your cluster”. 

The admission decision does not only rely on the image name and tag, but also on additional context from the admission review, which includes namespace, pod metadata, etc.

### Features

 * Registry and repository whitelist
 * Global and per-namespace admission configuration
 * Configurable pre-scan and post-scan behavior, i.e. :
   * Accept only the images that pass the scan (default)
   * Directly reject non-whitelisted registries / repos, without scanning
   * Accept the image even if it doesn’t pass the scan
   * Do not accept any image that hasn’t been scanned already
 * Pod mutation: image tag is replaced by digest to prevent TOCTOU issue if the tag is updated between the scan and the pod scheduling.

### Common use cases

* Customer doesn't want to admit any image that doesn't pass the scanning policy
* Customer only wants to admit images from his own internal, curated repositories
* Customer wants to apply different admission and scanning policies depending on the namespace

### Why this is valuable for Sysdig

* Extends the scanning use cases to enable a prevention mode, as opposed to detection & reaction. Lack of prevention mechanisms has always been a pain point exploited by our competitors
* Reinforces our "shift left" and "integrate with CI/CD" stories, if a user tries to bypass the pipeline, it will be stopped in its tracks
* Unblocks several customer conversations that were waiting for this feature. Additionally, behaviour rules are easily modifiable to accommodate for custom requests

### How to demo

* Sysdig Admission Controller is deployed in the default (`+kube`) demo account, `demo-kube-aws` cluster
* Only performing admission decisions on the admission namespace, to avoid disturbing the other applications in the cluster
* Once a day, we will try to deploy an image in that namespace that doesn’t pass the scanning policy check.
* Events sections in Sysdig Monitor
* Use the free text search to look for `REJECTED`
* You will find an event similar to this:

```
Error creating: admission webhook "imagechecks.admission.sysdig.com" denied the request: Image 'docker.io/airadier/test:bad' for container 'test' failed scan policy check: Image 'docker.io/airadier/test:bad' REJECTED. Global default policy - policy action is 'reject'
```
* It is important to note that you can create an alert that triggers every time a pod is rejected.
* More advanced and flexible demos can be enabled, but so far they require `kubectl` access to the Kubernetes API.
  
### Limitations

The first version requires directly managing and applying YAMLS using kubectl, deployment and rule maintenance is an involved process

### Future milestones

* Improve *how to demo* by providing some additional examples or automations (maybe a Jenkins job)
* Publish helm charts in our own helm chart repository and provide instructions to install from there, no need to clone the Github repo
* Integrate the admission controller with the Sysdig Secure UI: mock https://jsfiddle.net/airadier/uh2jk94n/
* Create an API to sync the admission controller components with the configuration stored in Sysdig Secure
* Integrate with Node Image Analyzer to trigger inline scan before the pod is accepted
* Integrate admission controller events with Sysdig Secure Event Feed

### Additional links

[Blogpost](https://sysdig.com/blog/image-scanning-admission-controller/) (Slightly outdated since this was focused on our OPA integration, but contains the most important concepts)

## Installation

Create a values.yaml overriding the desired values from the [values.yaml file in the repository](https://github.com/draios/sysdig-admission-controller/blob/master/helm-charts/values.yaml):

```yaml
# Uncomment the following line and set URL for On-Prem
# sysdigSecureApiUrl: https://HOSTNAME
# Put your <Sysdig-Secure-Secret-Token> in this value
sysdigSecureToken: xxxx-xxxxx-xxx

#Set to true to increase verbosity and output OPA input and rules in the log
verboseLog: false

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

  # customPolicies:
  #   - prefix: "my.totally-trusted-registry.com/"
  #     action: accept
  #   - prefix: "bad-registry.com/specific-repo/"
  #     action: scan-result
  #   - prefix: "bad-registry.com/"
  #     action: reject
  #   - prefix: "malware-registry.io/"
  #     action: reject


  byNamespace: {}
  # byNamespace:
  #  ns-dev:
  #    # By default, images will be accepted in this NS regardless of the scan result
  #    defaultPolicy: accept
  #  ns-prod:
  #    # All images rejected by default in this namespace
  #    defaultPolicy: reject
  #    # Images from "my-trusted-registry.com/" will be always accepted
  #    customPolicies:
  #      - prefix: "my-trusted-registry.com/"
  #        action: accept
  #      - prefix: "docker.io/"
  #        action: scan-result
  #  ns-playground:
  #    defaultPolicy: accept
  #    customPolicies: []

preScanPolicies:

  autoGenerate: true

  defaultPolicy: accept

  # customPolicies:
  #   - prefix: "my.totally-trusted-registry.com/"
  #     action: accept
  #   - prefix: "bad-registry.com/specific-repo/"
  #     action: scan
  #   - prefix: "bad-registry.com/"
  #     action: reject
  #   - prefix: "malware-registry.io/"
  #     action: reject
  
  byNamespace:
    ns-prod:
      defaultPolicy: accept
      customPolicies:
        - prefix: "docker.io/"
          action: scan

```
The **sysdigSecureToken** value is mandatory, but if the defaults are ok for you, all other settings are optional. 

In this example values.yaml we accept all images by default in *preScanPolicies*, but we force images coming from docker.io/ in *ns-prod* namespace to be scanned. Then in *scanPolicies* we rely on the scan-result of the image to admit or deny the pod admission.

Once the values.yaml is ready, just create the namespace and deploy using Helm 3, adding the sysdiglabs Helm Chart repository.


```
$ kubectl create ns sysdig-admission-controller
$ helm repo add sysdiglabs https://sysdiglabs.github.io/charts/
$ helm install -n sysdig-admission-controller sysdig-admission-controller -f values.yaml sysdiglabs/sysdig-admission-controller
```

After a few seconds, this chart will deploy all the required components:
 * Register the aggregated API Service and admission controller webhook.
 * Admission Controller deployment and service.
 * Secure Token secret.
 * Required service account, TLS certificates, roles and permissions.
 * Configmaps, including *sysdig-admission-controller-policy* to store the policy configuration.

### Basic settings

The default settings in *values.yaml* should be right for most cases, but you need to provide at least:

* **sysdigSecureToken** - The Sysdig Secure Token for your account
* **sysdigSecureApiUrl** - if the default SaS URL does not fit your environment (in case you are using the onPrem version of Sysdig Secure
  
If you set the value **verboseLog** to *true*, the admission controller will include additional information in the output logs.

### Evaluation rules

In the *values.yaml* you will find a couple of sections that define the policies that apply when evaluating images.

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

*autoGenerate* value must be *true*.

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

*autoGenerate* value must be *true*.

Similar to the *preScanRules* section, we can define a general *defaultPolicy* behavior. **scan-result** in the example means that the decision will depend on the image scanning report result. We override this in the *ns-playground* namespace to always *accept* images (although they will be scanned, and the scan report could be *failed*), and then in *ns-prod* to *reject* by default.

We can also define *customPolicies* for specific registries, repositories and tags. In the example we always *accept* images coming from *my-totally-trusted-registry.com*, and we always *reject* images coming from *bad-registry.com/*. We override the behavior in *ns-playground* by defining an empty list of *customPolicies* (so **all** images are always accepted), and for *ns-prod* namespace we override the *customPolicies* to also force evaluation of the scan report for images coming from *docker.io/*.

### Changing settings after deploying with Helm

The *preScanPolicies* and *scanPolicies* values defined in the YAML files will be used by Helm templating system to create a ConfigMap named ***sysdig-admission-controller-policy***:

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

## Evaluation engine

When a pod is created or updated, a new *AdmissionRequest* is analyzed by the admission controller.

The admission controller will evaluate if the pod is admited or not in two phases: **pre-scan** and **scan** phase.

On each phase, it will evaluate a set of rules using the available context, and then make a decision. 

The configuration from the ***sysdig-admission-controller-policy*** ConfigMap will modify the evaluation criteria.

### Evaluation phases

#### Pre-Scan phase

In this phase, the pod is evaluated as a whole. The final decision on this phase will be one of:

* **accept**: The pod is accepted, and no scan is required for any of the images.
* **reject**: The pod is rejected, and no scan is performed on any of the images.
* **scan**: No admission decision is done, and the pod progresses to the **scan phase**.

#### Scan phase

In this phase, a image scan is triggered for every container inside the pod. Then, a decision is made for each image. All the images for the containers in a pod need to be accepted for the pod to be accepted. Otherwise, the pod will be rejected.

For each container image composing the pod, the engine will evaluate the rego rules, with the *scanPolicies* settings, the pod *AdmissionRequest* and the *scan report* .

* If any image is denied, then the Pod is **rejected** and the list of *reason*(s) is included in the reject message.
* Otherwise, the Pod is **accepted**

*Pod mutation*: When the scan is triggered, the digest of the image being scanned is recovered, and the pod specification is mutated to replace the tag with the sha256 digest of the image, making sure that the tag cannot be altered to point to a different image.

### Evaluation policies configuration

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
