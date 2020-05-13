package prescanimageadmission

##############################################################
# Imput examples

input_example_ns := {
    "AdmissionRequest": {
        "namespace": "irrelevant",
        "object": {
            "metadata": {
                "namespace": "example"
            },
            "spec": {
                "containers": [
                    {
                    "image": "docker.io/myrepo/myimage"
                    }
                ]
            }
        }
    }
}

input_example_multiple_images := {
    "AdmissionRequest": {
        "namespace": "irrelevant",
        "object": {
            "metadata": {
                "namespace": "example"
            },
            "spec": {
                "containers": [
                    {
                    "image": "myregistry1.com/myrepo/myimage"
                    },
                    {
                    "image": "myregistry2.com/myrepo/myimage"
                    },
                    {
                    "image": "myregistry3.com/myrepo/myimage"
                    }
                ]
            }
        }
    }
}


##############################################################
# Helper rules

pod_rejected[msg] {
    not allow_pod
    deny_pod[msg] 
}

pod_rejected_any_message {
    deny_pod[_]
}

pod_rejected_other_msg[msg] {
	pod_rejected[msg]
    other_msg != msg
    pod_rejected[other_msg]
}

pod_rejected_only_with_msg[msg] {
    pod_rejected[msg]
	not pod_rejected_other_msg[msg]
}

pod_accepted {
    allow_pod
    not pod_rejected_any_message
}

pod_to_be_scanned {
    not allow_pod
    not pod_rejected_any_message
}

##############################################################
# Tests: Gelobal scope, default policy

#Empty admission request should reject with an error message
test_empty_admission_request {
    pod_rejected_only_with_msg["AdmissionRequest is missing in input"]
        with input as {}
        with data.policies as {"defaultPolicy": "accept"}
}

#Empty configuration (no default policy) should reject with an error message
test_empty_config {
    pod_rejected_only_with_msg["Invalid value for defaultPolicy - '<empty>'"]
        with input as input_example_ns
        with data.policies as {}
}

#Wrong defaultPolicy value should reject with error message
test_wrong_config {
    pod_rejected_only_with_msg["Invalid value for defaultPolicy - 'wrongvalue'"] 
        with input as input_example_ns
        with data.policies as {"defaultPolicy": "wrongvalue"}
}

#Pod should be accepted if defaultPolicy=accept
test_default_policy_accept {
    pod_accepted 
        with input as input_example_ns 
        with data.policies as { "defaultPolicy": "accept"}
}

#Pod should be rejected if defaultPolicy=reject
test_default_policy_reject {
    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy"]
        with input as input_example_ns 
        with data.policies as { "defaultPolicy": "reject"}
}

#Pod should be scanned (not accepted either rejected) if defaultPolicy=scan
test_default_policy_scan {
    pod_to_be_scanned 
        with input as input_example_ns 
        with data.policies as { "defaultPolicy": "scan" }
}

##############################################################
# Tests: Global scope, custom policies

#Pod should be accepted if customPolicy is accept for that prefix
test_custom_policy_accept {
    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy"] 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "reject",
            "customPolicies": [
                {"prefix": "---docker.io/", "action": "accept"}
            ]
        }

    pod_accepted 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "reject",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "accept"}
            ]
        }
}

#Pod should be accepted if customPolicy is accept for all the containers
test_custom_policy_accept_multiple_containers {
    policy_accept_my_registries := {
            "defaultPolicy": "reject",
            "customPolicies": [
                {"prefix": "myregistry1.com/", "action": "accept"},
                {"prefix": "myregistry2.com/", "action": "accept"},
                {"prefix": "myregistry3.com/", "action": "accept"}
            ]
        }

    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy"] 
        with input as input_example_ns 
        with data.policies as policy_accept_my_registries

    pod_accepted 
        with input as input_example_multiple_images 
        with data.policies as policy_accept_my_registries
}

#Pod should be rejected if customPolicy is reject for that prefix
test_custom_policy_reject {
    pod_accepted 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "---docker.io/", "action": "reject"}
            ]
        }

    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global custom policy (prefix 'docker.io/')"] 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "reject"}
            ]
        }
}

#Pod should be rejected if customPolicy is reject for that prefix for one of the containers
test_custom_policy_reject_multiple_containers_default_accept {
    policy_reject_my_registry := {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "myregistry2.com/", "action": "reject"}
            ]
        }

    pod_accepted 
        with input as input_example_ns 
        with data.policies as policy_reject_my_registry

    pod_rejected_only_with_msg["Image 'myregistry2.com/myrepo/myimage' REJECTED. Global custom policy (prefix 'myregistry2.com/')"] 
        with input as input_example_multiple_images 
        with data.policies as policy_reject_my_registry
}


#Pod should be rejected if any of the containers is rejected by global default policy
test_custom_policy_reject_multiple_containers_default_reject {
    policy_accept_my_registry := {
            "defaultPolicy": "reject",
            "customPolicies": [
                {"prefix": "myregistry2.com/", "action": "accept"}
            ]
        }

    pod_rejected["Image 'myregistry1.com/myrepo/myimage' REJECTED. Global default policy"] 
        with input as input_example_multiple_images 
        with data.policies as policy_accept_my_registry
   
    not pod_rejected["Image 'myregistry2.com/myrepo/myimage' REJECTED. Global default policy"] 
        with input as input_example_multiple_images 
        with data.policies as policy_accept_my_registry
    
    pod_rejected["Image 'myregistry3.com/myrepo/myimage' REJECTED. Global default policy"] 
        with input as input_example_multiple_images 
        with data.policies as policy_accept_my_registry
}

#Pod should be rejected if no policy is specified for that prefix
test_custom_policy_reject_empty_config {
    policy_missing_action_my_registry := {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "docker.io/"}
            ]
        }

    pod_accepted 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "---docker.io/"}
            ]
        }

    pod_rejected_only_with_msg["Invalid value for customPolicy with prefix 'docker.io/' - '<empty>'"] 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "docker.io/"}
            ]
        }
}

#Pod should be rejected if wrong policy is detected for that prefix
test_custom_policy_reject_wrong_config {
    pod_accepted 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "---docker.io/", "action": "wrong"}
            ]
        }

    pod_rejected_only_with_msg["Invalid value for customPolicy with prefix 'docker.io/' - 'wrong'"] 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "wrong"}
            ]
        }
}

#Pod should be scanned if customPolicy is scan
test_custom_policy_scan {

    pod_accepted 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "---docker.io/", "action": "scan"}
            ]
        }

    pod_to_be_scanned 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "scan"}
            ]
        }
}

#Pod should be scan if customPolicy is scan for at least the prefix of one of the containers, an no containers are rejected
test_custom_policy_scan_multiple_containers {
    policy_scan_my_registries := {
            "defaultPolicy": "reject",
            "customPolicies": [
                {"prefix": "myregistry1.com/", "action": "scan"},
                {"prefix": "myregistry2.com/", "action": "accept"},
                {"prefix": "myregistry3.com/", "action": "accept"}
            ]
        }
    
    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy"] 
        with input as input_example_ns 
        with data.policies as policy_scan_my_registries
        
    pod_to_be_scanned 
        with input as input_example_multiple_images 
        with data.policies as policy_scan_my_registries
}

##############################################################
# Tests: Namespace scope, default policy

#Wrong defaultPolicy in current namespace should reject admission
test_ns_wrong_config_current_namespace {
    pod_rejected_only_with_msg["Invalid value for defaultPolicy for namespace 'example' - 'wrongnsvalue'"] 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "wrongnsvalue"
                }
            }
        }
}

test_ns_wrong_config_other_namespace {
    pod_accepted 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "other": {
                    "defaultPolicy": "wrongnsvalue"
                }
            }
        }
}

#Pod should be accepted if defaultPolicy=accept for pod namespace, otherwise rejected (as global defaultPolicy=reject)
test_ns_default_policy_accept {
    policy_accept_in_ns_other := {
        "defaultPolicy": "reject",
        "byNamespace": {
            "other": {
                "defaultPolicy": "accept"
            }
        }
    }    

    policy_accept_in_ns_example := {
        "defaultPolicy": "reject",
        "byNamespace": {
            "example": {
                "defaultPolicy": "accept"
            }
        }
    }

    pod_accepted 
        with input as input_example_ns 
        with data.policies as policy_accept_in_ns_example

    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy"] 
        with input as input_example_ns 
        with data.policies as policy_accept_in_ns_other
}

#Pod should be rejected if defaultPolicy=reject for pod namespace, otherwise accepted (as global defaultPolicy=accept)
test_ns_default_policy_reject {
    policy_reject_in_ns_other := {
        "defaultPolicy": "accept",
        "byNamespace": {
            "other": {
                "defaultPolicy": "reject"
            }
        }
    }

    policy_reject_in_ns_example := {
        "defaultPolicy": "accept",
        "byNamespace": {
            "example": {
                "defaultPolicy": "reject"
            }
        }
    }

    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy"] 
        with input as input_example_ns 
        with data.policies as policy_reject_in_ns_example

    pod_accepted 
        with input as input_example_ns 
        with data.policies as policy_reject_in_ns_other
}

#Pod should be scanned (not accepted or rejected) if defaultPolicy=accept for pod namespace, otherwise rejected (as global defaultPolicy=reject)
test_ns_default_policy_scan {

    policy_scan_in_ns_other := {
        "defaultPolicy": "reject",
        "byNamespace": {
            "other": {
                "defaultPolicy": "scan"
            }
        }
    }

    policy_scan_in_ns_example := {
        "defaultPolicy": "reject",
        "byNamespace": {
            "example": {
                "defaultPolicy": "scan"
            }
        }
    }

    pod_to_be_scanned 
        with input as input_example_ns 
        with data.policies as policy_scan_in_ns_example

    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy"] 
        with input as input_example_ns 
        with data.policies as policy_scan_in_ns_other
}

##############################################################
# Tests: Namespace scope, custom policies

#Pod should be accepted if customPolicy is accept for that prefix in that namespace
test_ns_custom_policy_accept_current_namespace {
 
    pod_accepted 
        with input as input_example_ns
        with data.policies as {
            "defaultPolicy": "reject",
            "customPolicies": [
                {"prefix": "someregistry.com/", "action": "accept"}
            ],
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        {"prefix": "docker.io/", "action": "accept"}
                    ],
                }
            }
        }

    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy"] 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "reject",
            "customPolicies": [
                {"prefix": "someregistry.com/", "action": "accept"}
            ],
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        {"prefix": "---docker.io/", "action": "accept"}
                    ],
                }
            }
        }
}

test_ns_custom_policy_accept_other_namespace {
    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy"] 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "reject",
            "customPolicies": [
                {"prefix": "someregistry.com/", "action": "accept"}
            ],
            "byNamespace": {
                "other": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        {"prefix": "docker.io/", "action": "accept"}
                    ],
                }
            }
        }
}

#Pod should be accepted if customPolicy is accept for all the containers in that namespace
test_ns_custom_policy_accept_multiple_containers_current_namespace {
    policy := {
            "defaultPolicy": "reject",
            "customPolicies": [
                {"prefix": "someregistry.com/", "action": "accept"}
            ],
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        {"prefix": "myregistry1.com/", "action": "accept"},
                        {"prefix": "myregistry2.com/", "action": "accept"},
                        {"prefix": "myregistry3.com/", "action": "accept"}
                    ]
                }
            }
        }

    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy"] 
        with input as input_example_ns 
        with data.policies as policy

    pod_accepted 
        with input as input_example_multiple_images 
        with data.policies as policy
}

test_ns_custom_policy_accept_multiple_containers_other_namespace {

    policy := {
            "defaultPolicy": "reject",
            "customPolicies": [
                {"prefix": "someregistry.com/", "action": "accept"}
            ],
            "byNamespace": {
                "other": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        {"prefix": "myregistry1.com/", "action": "accept"},
                        {"prefix": "myregistry2.com/", "action": "accept"},
                        {"prefix": "myregistry3.com/", "action": "accept"}
                    ]
                }
            }
        }

    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy"] 
        with input as input_example_ns 
        with data.policies as policy

    pod_rejected["Image 'myregistry1.com/myrepo/myimage' REJECTED. Global default policy"]
        with input as input_example_multiple_images 
        with data.policies as policy

    pod_rejected["Image 'myregistry2.com/myrepo/myimage' REJECTED. Global default policy"]
        with input as input_example_multiple_images 
        with data.policies as policy

    pod_rejected["Image 'myregistry3.com/myrepo/myimage' REJECTED. Global default policy"]
        with input as input_example_multiple_images 
        with data.policies as policy
}

#Pod should be rejected if customPolicy is reject for that prefix
test_ns_custom_policy_reject_current_namespace {


    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy"] 
        with input as input_example_ns
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "reject"}
            ],
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        {"prefix": "---docker.io/", "action": "reject"}
                    ]
                }
            }
        }

    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' custom policy (prefix 'docker.io/')"]
        with input as input_example_ns
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "reject"}
            ],
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        {"prefix": "docker.io/", "action": "reject"}
                    ]
                }
            }
        }

}

test_ns_custom_policy_reject_other_namespace {
    pod_accepted 
        with input as input_example_ns
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "someregistry.com/", "action": "accept"}
            ],
            "byNamespace": {
                "other": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        {"prefix": "docker.io/", "action": "reject"}
                    ]
                }
            }
        }

}

#Pod should be rejected if customPolicy is reject for that prefix for one of the containers
test_ns_custom_policy_reject_multiple_containers_default_accept {
    policy_reject_in_ns_example_my_registries := {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "someregistry.com/", "action": "accept"}
            ],
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        {"prefix": "myregistry2.com/", "action": "reject"}
                    ]
                }
            }
        }

    policy_reject_in_ns_other_my_registries := {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "someregistry.com/", "action": "accept"}
            ],
            "byNamespace": {
                "other": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        {"prefix": "myregistry2.com/", "action": "reject"}
                    ]
                }
            }
        }

    pod_accepted
        with input as input_example_ns
        with data.policies as policy_reject_in_ns_example_my_registries

    pod_accepted
        with input as input_example_ns
        with data.policies as policy_reject_in_ns_other_my_registries

    pod_rejected_only_with_msg["Image 'myregistry2.com/myrepo/myimage' REJECTED. Namespace 'example' custom policy (prefix 'myregistry2.com/')"] 
        with input as input_example_multiple_images 
        with data.policies as policy_reject_in_ns_example_my_registries

    pod_accepted
        with input as input_example_multiple_images 
        with data.policies as policy_reject_in_ns_other_my_registries
}


#Pod should be rejected if any of the containers is rejected by global default policy
test_ns_custom_policy_reject_multiple_containers_default_reject {
    policy_accept_in_ns_example_my_registries := {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "someregistry.com/", "action": "accept"}
            ],
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        {"prefix": "myregistry2.com/", "action": "accept"}
                    ]
                }
            }
        }

    policy_accept_in_ns_other_my_registries := {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "someregistry.com/", "action": "accept"}
            ],
            "byNamespace": {
                "other": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        {"prefix": "myregistry2.com/", "action": "accept"}
                    ]
                }
            }
        }

    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy"] 
        with input as input_example_ns
        with data.policies as policy_accept_in_ns_example_my_registries

    pod_accepted
        with input as input_example_ns
        with data.policies as policy_accept_in_ns_other_my_registries

    pod_rejected["Image 'myregistry1.com/myrepo/myimage' REJECTED. Namespace 'example' default policy"] 
        with input as input_example_multiple_images 
        with data.policies as policy_accept_in_ns_example_my_registries
    not pod_rejected["Image 'myregistry2.com/myrepo/myimage' REJECTED. Namespace 'example' default policy"] 
        with input as input_example_multiple_images 
        with data.policies as policy_accept_in_ns_example_my_registries
    pod_rejected["Image 'myregistry3.com/myrepo/myimage' REJECTED. Namespace 'example' default policy"]
        with input as input_example_multiple_images
        with data.policies as policy_accept_in_ns_example_my_registries

    pod_accepted
        with input as input_example_multiple_images 
        with data.policies as policy_accept_in_ns_other_my_registries
}

#Pod should be rejected if no policy is specified for that prefix
test_ns_custom_policy_reject_empty_config_current_namespace {

    pod_accepted 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        {"prefix": "---docker.io/"}
                    ]
                }
            }
        }

    pod_rejected_only_with_msg["Invalid value for namespace 'example' customPolicy with prefix 'docker.io/' - '<empty>'"]
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        {"prefix": "docker.io/"}
                    ]
                }
            }
        }
}

test_ns_custom_policy_reject_empty_config_other_namespace {
    pod_accepted 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "accept"}
            ],
            "byNamespace": {
                "other": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        {"prefix": "docker.io/"}
                    ]
                }
            }
        }
}

#Pod should be rejected if wrong policy is detected for that prefix
test_ns_custom_policy_reject_wrong_config_current_namespace {
    pod_accepted 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        {"prefix": "---docker.io/", "action": "wrong"}
                    ]
                }
            }
        }

    pod_rejected_only_with_msg["Invalid value for namespace 'example' customPolicy with prefix 'docker.io/' - 'wrong'"] 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        {"prefix": "docker.io/", "action": "wrong"}
                    ]
                }
            }
        }
}

test_ns_custom_policy_reject_wrong_config_other_namespace {
    pod_accepted 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "other": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        {"prefix": "docker.io/", "action": "wrong"}
                    ]
                }
            }
        }

}

#Pod should be scanned if customPolicy is scan
test_ns_custom_policy_scan_current_namespace {

    pod_accepted 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "reject",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        {"prefix": "---docker.io/", "action": "scan"}
                    ]
                }
            }
        }

    pod_to_be_scanned 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "reject",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        {"prefix": "docker.io/", "action": "scan"}
                    ]
                }
            }
        }

}

test_ns_custom_policy_scan_other_namespace {
    pod_accepted 
        with input as input_example_ns 
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "other": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        {"prefix": "docker.io/", "action": "scan"}
                    ]
                }
            }
        }
}

#Pod should be scan if customPolicy is scan for at least the prefix of one of the containers, an no containers are rejected
test_ns_custom_policy_scan_multiple_containers_current_namespace {
    policy_scan_my_registries_in_ns_example := {
            "defaultPolicy": "reject",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "reject"},
            ],
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        {"prefix": "myregistry1.com/", "action": "scan"},
                        {"prefix": "myregistry2.com/", "action": "accept"},
                        {"prefix": "myregistry3.com/", "action": "accept"}
                    ]
                }
            }
        }

    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy"] 
        with input as input_example_ns
        with data.policies as policy_scan_my_registries_in_ns_example

    pod_to_be_scanned
        with input as input_example_multiple_images
        with data.policies as policy_scan_my_registries_in_ns_example
}

test_ns_custom_policy_scan_multiple_containers_other_namespace {
    policy := {
            "defaultPolicy": "reject",
            "byNamespace": {
                "other": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        {"prefix": "myregistry1.com/", "action": "scan"},
                        {"prefix": "myregistry2.com/", "action": "accept"},
                        {"prefix": "myregistry3.com/", "action": "accept"}
                    ]
                }
            }
        }

    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy"] 
        with input as input_example_ns
        with data.policies as policy

    pod_rejected["Image 'myregistry1.com/myrepo/myimage' REJECTED. Global default policy"] 
        with input as input_example_multiple_images
        with data.policies as policy
    pod_rejected["Image 'myregistry2.com/myrepo/myimage' REJECTED. Global default policy"] 
        with input as input_example_multiple_images
        with data.policies as policy
    pod_rejected["Image 'myregistry3.com/myrepo/myimage' REJECTED. Global default policy"] 
        with input as input_example_multiple_images
        with data.policies as policy
}

##############################################################
# Tests: Policy inherintance

test_inheritance_ns_omit_default_policy {
    pod_accepted 
        with input as input_example_ns
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "customPolicies": [
                        {"prefix": "---docker.io/", "action": "reject"}
                    ]
                }
            }
        }

    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' custom policy (prefix 'docker.io/')"]
        with input as input_example_ns
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "customPolicies": [
                        {"prefix": "docker.io/", "action": "reject"}
                    ]
                }
            }
        }

    pod_to_be_scanned
        with input as input_example_ns
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "customPolicies": [
                        {"prefix": "docker.io/", "action": "scan"}
                    ]
                }
            }
        }
}

test_inheritance_ns_omit_custom_policies {
    pod_accepted 
        with input as input_example_ns
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                        {"prefix": "---docker.io/", "action": "reject"}
                    ],
            "byNamespace": {
                "example": {
                }
            }
        }

    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global custom policy (prefix 'docker.io/')"] 
        with input as input_example_ns
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                        {"prefix": "docker.io/", "action": "reject"}
                    ],
            "byNamespace": {
                "example": {
                }
            }
        }

}

test_inheritance_custom_over_defaults {
    pod_accepted 
        with input as input_example_ns
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                        {"prefix": "docker.io/", "action": "accept"}
                    ],
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject"
                }
            }
        }

    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global custom policy (prefix 'docker.io/')"] 
        with input as input_example_ns
        with data.policies as {
            "defaultPolicy": "reject",
            "customPolicies": [
                        {"prefix": "docker.io/", "action": "reject"}
                    ],
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept"
                }
            }
        }

    pod_to_be_scanned
        with input as input_example_ns
        with data.policies as {
            "defaultPolicy": "reject",
            "customPolicies": [
                        {"prefix": "docker.io/", "action": "scan"}
                    ],
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept"
                }
            }
        }

}

test_inheritance_override_custom_in_namespace {
    pod_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy"]
        with input as input_example_ns
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                        {"prefix": "docker.io/", "action": "accept"}
                    ],
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject",
                    "customPolicies": []
                }
            }
        }

    pod_rejected_only_with_msg["Image 'myregistry2.com/myrepo/myimage' REJECTED. Namespace 'example' custom policy (prefix 'myregistry2.com/')"]
        with input as input_example_multiple_images
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                        {"prefix": "myregistry1.com/", "action": "reject"},
                        {"prefix": "myregistry3.com/", "action": "reject"}
                    ],
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        {"prefix": "myregistry2.com/", "action": "reject"}
                    ]
                }
            }
        } 
}
