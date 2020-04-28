package prescanimageadmission

input_example_ns := data.common.mock_input_for_ns("example")
input_dev_ns := data.common.mock_input_for_ns("dev")

input_example_custom_registry := {
    "AdmissionRequest": {
        "namespace": "example",
        "object": {
            "metadata": {
                "namespace": "example"
            },
            "spec": {
                "containers": [
                    {
                    "image": "myregistry.com/myrepo/myimage"
                    }
                ]
            }
        }
    }
}

input_example_multiple_images := {
    "AdmissionRequest": {
        "namespace": "example",
        "object": {
            "metadata": {
                "namespace": "example"
            },
            "spec": {
                "containers": [
                    {
                    "image": "myregistry1.com/myrepo/myimage",
                    },
                    {
                    "image": "myregistry2.com/myrepo/myimage",
                    },
                    {
                    "image": "myregistry3.com/myrepo/myimage",
                    },
                ]
            }
        }
    }
}

policy_accept_in_ns_dev := {
    "defaultPolicy": "reject",
    "byNamespace": {
        "dev": {
            "defaultPolicy": "accept"
        }
    }
}

policy_reject_in_ns_dev := {
    "defaultPolicy": "accept",
    "byNamespace": {
        "dev": {
            "defaultPolicy": "reject"
        }
    }
}

policy_scan_in_ns_dev := {
    "defaultPolicy": "reject",
    "byNamespace": {
        "dev": {
            "defaultPolicy": "scan"
        }
    }
}

###############################
# Helper rules

pod_rejected[msg] {
    not pre_allow_pod
    pre_deny_pod[msg] 
}

pod_rejected_any_message {
    not pre_allow_pod
    pre_deny_pod[_]
}

pod_accepted {
    not pod_rejected_any_message
}

pod_to_be_scanned {
    not pre_allow_pod
    not pod_rejected_any_message
}

###############################
# Tests

#Empty admission request should reject with an error message
test_empty_admission_request {
    pod_rejected["AdmissionRequest is missing in input"] with input as {} with data.policies as {}
}

#Empty configuration (no default policy) should reject with an error message
test_empty_config {
    pod_rejected["Invalid value for defaultPolicy - '<empty>'"] with input as {} with data.policies as {}
}

#Wrong defaultPolicy value should reject with error message
test_wrong_config {
    pod_rejected["Invalid value for defaultPolicy - 'wrongvalue'"] with input as {} with data.policies as {"defaultPolicy": "wrongvalue"}
}

#Wrong defaultPolicy in current namespace should reject admission
test_ns_wrong_config_current_namespace {
    pod_rejected["Invalid value for defaultPolicy for namespace 'example' - 'wrongnsvalue'"] with input as input_example_ns with 
        data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "wrongnsvalue"
                }
            }
        }
}

#Wrong defaultPolicy in a different namespace should be ignored (avoid breaking everything due to namespace wrong configuration)
test_ns_wrong_config_other_namespace {
    pod_accepted with input as input_example_ns with 
        data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "test-ns": {
                    "defaultPolicy": "wrongnsvalue"
                }
            }
        }
}


#Pod should be accepted if defaultPolicy=accept
test_default_policy_accept {
    pod_accepted with input as input_example_ns with data.policies as { "defaultPolicy": "accept"}
}

#Pod should be rejected if defaultPolicy=reject
test_default_policy_reject {
    pod_rejected["Pod rejected by default policy for image 'docker.io/myrepo/myimage'"] with input as input_example_ns with data.policies as { "defaultPolicy": "reject"}
}

#Pod should be scanned (not accepted either rejected) if defaultPolicy=scan
test_default_policy_scan {
    pod_to_be_scanned with input as input_example_ns with data.policies as { "defaultPolicy": "scan" }
}

#Pod should be accepted if defaultPolicy=accept for pod namespace, otherwise rejected (as global defaultPolicy=reject)
test_ns_default_policy_accept {
    pod_accepted with input as input_dev_ns with data.policies as policy_accept_in_ns_dev
    pod_rejected["Pod rejected by default policy for image 'docker.io/myrepo/myimage'"] with input as input_example_ns with data.policies as policy_accept_in_ns_dev
}

#Pod should be rejected if defaultPolicy=reject for pod namespace, otherwise accepted (as global defaultPolicy=accept)
test_ns_default_policy_reject {
    pod_rejected["Namespace 'dev' policy - Pod rejected by namespace policy"] with input as input_dev_ns with data.policies as policy_reject_in_ns_dev
    pod_accepted with input as input_example_ns with data.policies as policy_reject_in_ns_dev
}

#Pod should be scanned (not accepted or rejected) if defaultPolicy=accept for pod namespace, otherwise rejected (as global defaultPolicy=reject)
test_ns_default_policy_scan {
    pod_to_be_scanned with input as input_dev_ns with data.policies as policy_scan_in_ns_dev
    pod_rejected["Pod rejected by default policy for image 'docker.io/myrepo/myimage'"] with input as input_example_ns with data.policies as policy_scan_in_ns_dev
}

#Pod should be accepted if customPolicy is accept for that prefix
test_custom_policy_accept {
    policy_accept_my_registry := {
            "defaultPolicy": "reject",
            "customPolicies": [
                {"prefix": "myregistry.com/", "action": "accept"}
            ]
        }
    pod_rejected["Pod rejected by default policy for image 'docker.io/myrepo/myimage'"] with input as input_example_ns with data.policies as policy_accept_my_registry
    pod_accepted with input as input_example_custom_registry with data.policies as policy_accept_my_registry
}

#Pod should be rejected if customPolicy is reject for that prefix
test_custom_policy_reject {
    policy_reject_my_registry := {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "myregistry.com/", "action": "reject"}
            ]
        }
    pod_accepted with input as input_example_ns with data.policies as policy_reject_my_registry
    pod_rejected["Pod rejected by custom policy by prefix 'myregistry.com/' for image 'myregistry.com/myrepo/myimage'"] with input as input_example_custom_registry with data.policies as policy_reject_my_registry
}


#Pod should be rejected if no policy is specified for that prefix
test_custom_policy_reject_empty_config {
    policy_missing_action_my_registry := {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "myregistry.com/"}
            ]
        }
    pod_accepted with input as input_example_ns with data.policies as policy_missing_action_my_registry
    pod_rejected["Invalid value for customPolicy with prefix 'myregistry.com/' - '<empty>'"] with input as input_example_custom_registry with data.policies as policy_missing_action_my_registry
}

#Pod should be rejected if wrong policy is detected for that prefix
test_custom_policy_reject_wrong_config {
    policy_wrong_action_my_registry := {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "myregistry.com/", "action": "wrong"}
            ]
        }
    pod_accepted with input as input_example_ns with data.policies as policy_wrong_action_my_registry
    pod_rejected["Invalid value for customPolicy with prefix 'myregistry.com/' - 'wrong'"] with input as input_example_custom_registry with data.policies as policy_wrong_action_my_registry
}


#Pod should be scanned if customPolicy is scan
test_custom_policy_scan {
    policy_scan_my_registry := {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "myregistry.com/", "action": "scan"}
            ]
        }
    pod_accepted with input as input_example_ns with data.policies as policy_scan_my_registry
    pod_to_be_scanned with input as input_example_custom_registry with data.policies as policy_scan_my_registry
}
