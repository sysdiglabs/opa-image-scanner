package postscanimageadmission

##############################################################
# Input examples

input_example_ns_scan_rejected := {
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
    },
    "ScanReport": {
        "ImageAndTag": "docker.io/myrepo/myimage",
        "Status": "rejected"
    }
}

input_example_ns_scan_accepted := {
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
    },
    "ScanReport": {
        "ImageAndTag": "docker.io/myrepo/myimage",
        "Status": "accepted"
    }
}

input_example_ns_scan_wrongreport := {
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
    },
    "ScanReport": {
        "ImageAndTag": "docker.io/myrepo/myimage",
        "Status": "wrongreport"
    }
}

input_example_ns_scan_pending := {
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
    },
    "ScanReport": {
        "ImageAndTag": "docker.io/myrepo/myimage",
        "Status": "report_not_available"
    }
}


input_example_ns_scan_failed := {
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
    },
    "ScanReport": {
        "ImageAndTag": "docker.io/myrepo/myimage",
        "Status": "scan_failed"
    }
}

##############################################################
# Helper rules

image_accepted {
    not image_rejected_any_message
}

image_rejected[msg] {
    deny_image[msg] 
}

image_rejected_any_message {
    deny_image[_]
}

image_rejected_other_msg[msg] {
	image_rejected[msg]
    other_msg != msg
    image_rejected[other_msg]
}

image_rejected_only_with_msg[msg] {
    image_rejected[msg]
	not image_rejected_other_msg[msg]
}


##############################################################
# Tests: input validation

#Empty configuration (no default policy) should reject with an error message
test_empty_input {

    image_rejected["AdmissionRequest is missing in input"]
        with input as {}
        with data.policies as {}

    image_rejected["ScanReport is missing in input"]
        with input as {}
        with data.policies as {}
}

#Empty admission request should reject with an error message
test_missing_admission_request {
    image_rejected_only_with_msg["AdmissionRequest is missing in input"]
        with input as {
             "ScanReport": {}
        }
        with data.policies as {
            "defaultPolicy": "scan-result",
            "reportPending": "reject",
            "scanFailed": "reject"
        }
}

#Empty scan report should reject with an error message
test_missing_scan_report {
    image_rejected_only_with_msg["ScanReport is missing in input"]
        with input as {
             "AdmissionRequest": {}
        }
        with data.policies as {
            "defaultPolicy": "scan-result",
            "reportPending": "reject",
            "scanFailed": "reject"
        }
}

##############################################################
# Tests: Global scope, default policy

test_empty_config {
    image_rejected_only_with_msg["Invalid value for defaultPolicy - '<empty>'"]
        with input as {
             "AdmissionRequest": {},
             "ScanReport": {}
        }
        with data.policies as {}
}

test_empty_config_default_policy {
    #If reportPending is ommited, it defaults to reject
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - scan report is pending"] 
        with input as input_example_ns_scan_pending
        with data.policies as {"defaultPolicy": "scan-result"}

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - scan failed"] 
        with input as input_example_ns_scan_failed
        with data.policies as {"defaultPolicy": "scan-result"}
}

#Wrong defaultPolicy value should reject with error message
test_wrong_config_default_policy {
    image_rejected_only_with_msg["Invalid value for defaultPolicy - 'wrongvalue'"] 
        with input as input_example_ns_scan_rejected
        with data.policies as {"defaultPolicy": "wrongvalue"}
}

test_wrong_config_report_pending {
    image_rejected_only_with_msg["Invalid value for reportPending - 'wrongvalue'"] 
        with input as input_example_ns_scan_accepted
        with data.policies as {"defaultPolicy": "scan-result", "reportPending": "wrongvalue"}
}

test_wrong_config_scan_failed {
    image_rejected_only_with_msg["Invalid value for scanFailed - 'wrongvalue'"] 
        with input as input_example_ns_scan_accepted
        with data.policies as {"defaultPolicy": "scan-result", "scanFailed": "wrongvalue"}
}

#Pod should be accepted if defaultPolicy=accept
test_default_policy_accept {
    image_accepted 
        with input as input_example_ns_scan_rejected
        with data.policies as {"defaultPolicy": "accept"}
}

#Pod should be rejected if defaultPolicy=reject
test_default_policy_reject {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"]
        with input as input_example_ns_scan_rejected 
        with data.policies as { 
            "defaultPolicy": "reject"
        }
}

#When policy is scan-result, image should be accepted if the scan result is "accepted"
test_default_policy_scan_result_accepted {
    image_accepted 
        with input as input_example_ns_scan_accepted
        with data.policies as { 
            "defaultPolicy": "scan-result",
            "reportPending": "reject",
            "scanFailed": "reject"
        }
}

#When policy is scan-result, image should be rejected if the scan result is "rejected"
test_default_policy_scan_result_rejected {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - scan result is 'reject'"]
        with input as input_example_ns_scan_rejected 
        with data.policies as { 
            "defaultPolicy": "scan-result",
            "reportPending": "accept",
            "scanFailed": "accept"
        }
}

#When policy is scan-result, image should be rejected if the scan result is an unexpected value
test_default_policy_scan_result_unexpected {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - unexpected ScanReport.Status value 'wrongreport'"]  
        with input as input_example_ns_scan_wrongreport
        with data.policies as { 
            "defaultPolicy": "scan-result",
            "reportPending": "accept",
            "scanFailed": "accept"
        }
}

#When report is pending image should be rejected because defaultPolicy is reject (makes no sense to wait for scan result)
test_report_pending_reject_by_default_policy {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"] 
        with input as input_example_ns_scan_pending
        with data.policies as { 
            "defaultPolicy": "reject"
        }
}

#When report is pending image should be accepted because defaultPolicy is accept (makes no sense to wait for scan result)
test_report_pending_accept_by_default_policy {
    image_accepted
        with input as input_example_ns_scan_pending
        with data.policies as { 
            "defaultPolicy": "accept"
        }
}

#When report is pending, and reportPending policy is accept, image should be accepted
test_report_pending_accept {
    image_accepted 
        with input as input_example_ns_scan_pending
        with data.policies as { 
            "defaultPolicy": "scan-result",
            "reportPending": "accept",
            "scanFailed": "reject"
        }
}

#When scan has failed, and scanFailed policy is reject, image should be rejected
test_report_pending_reject {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - scan report is pending"] 
        with input as input_example_ns_scan_pending
        with data.policies as { 
            "defaultPolicy": "scan-result",
            "reportPending": "reject",
            "scanFailed": "accept"
        }
}

#When scan has failed, and scanFailed policy is accept, image should be accepted
test_scan_failed_accept_by_default_policy {
    image_accepted 
        with input as input_example_ns_scan_failed
        with data.policies as { 
            "defaultPolicy": "accept"
        }
}

#When scan has failed, and defaultPolicy is reject, image should be rejected
test_scan_failed_reject_by_default_policy {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"] 
        with input as input_example_ns_scan_failed
        with data.policies as { 
            "defaultPolicy": "reject"
        }
}

#When scan has failed, and scanFailed policy is accept, image should be accepted
test_scan_failed_accept {
    image_accepted 
        with input as input_example_ns_scan_failed
        with data.policies as { 
            "defaultPolicy": "scan-result",
            "reportPending": "reject",
            "scanFailed": "accept"
        }
}

#When scan has failed, and scanFailed policy is reject, image should be rejected
test_scan_failed_reject {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - scan failed"]  
        with input as input_example_ns_scan_failed
        with data.policies as { 
            "defaultPolicy": "scan-result",
            "reportPending": "accept",
            "scanFailed": "reject"
        }
}

##############################################################
# Tests: Global scope, custom policies

test_custom_empty_action {
    image_rejected_only_with_msg["Invalid value for customPolicy with prefix 'docker.io/' - '<empty>'"]
        with input as input_example_ns_scan_accepted
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "docker.io/"}
            ]
        }
}

#Wrong customPolicy action should reject with error message
test_custom_wrong_action {
    image_rejected_only_with_msg["Invalid value for customPolicy with prefix 'docker.io/' - 'wrongvalue'"] 
        with input as input_example_ns_scan_accepted
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "wrongvalue"}
            ]
        }
}

#Pod should be accepted if customPolicy=accept
test_custom_policy_accept {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"] 
        with input as input_example_ns_scan_rejected
        with data.policies as {
            "defaultPolicy": "reject",
            "customPolicies": [
                {"prefix": "---docker.io/", "action": "accept"}
            ]
        }

    image_accepted 
        with input as input_example_ns_scan_rejected
        with data.policies as {
            "defaultPolicy": "reject",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "accept"}
            ]
        }
}

#Pod should be rejected if customPolicy=reject
test_custom_policy_reject {
    image_accepted
        with input as input_example_ns_scan_rejected 
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "---docker.io/", "action": "reject"}
            ]
        }

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global custom policy (prefix 'docker.io/') - policy action is 'reject'"]
        with input as input_example_ns_scan_rejected 
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "reject"}
            ]
        }
}

#When customPolicy is scan-result, image should be accepted if the scan result is "accepted"
test_custom_policy_scan_result_accepted {

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"] 
        with input as input_example_ns_scan_accepted
        with data.policies as {
            "defaultPolicy": "reject",
            "reportPending": "reject",
            "scanFailed": "reject",
            "customPolicies": [
                {"prefix": "---docker.io/", "action": "scan-result"}
            ]
        }

    image_accepted 
        with input as input_example_ns_scan_accepted
        with data.policies as {
            "defaultPolicy": "reject",
            "reportPending": "reject",
            "scanFailed": "reject",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "scan-result"}
            ]
        }
}

#When customPolicy is scan-result, image should be rejected if the scan result is "rejected"
test_custom_policy_scan_result_rejected {
    image_accepted
        with input as input_example_ns_scan_rejected 
        with data.policies as {
            "defaultPolicy": "accept",
            "reportPending": "accept",
            "scanFailed": "accept",
            "customPolicies": [
                {"prefix": "---docker.io/", "action": "scan-result"}
            ]
        }


    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global custom policy (prefix 'docker.io/') - scan result is 'reject'"]
        with input as input_example_ns_scan_rejected 
        with data.policies as {
            "defaultPolicy": "accept",
            "reportPending": "accept",
            "scanFailed": "accept",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "scan-result"}
            ]
        }
}

#When customPolicy is scan-result, image should be rejected if the scan result is an unexpected value
test_custom_policy_scan_result_unexpected {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global custom policy (prefix 'docker.io/') - unexpected ScanReport.Status value 'wrongreport'"]  
        with input as input_example_ns_scan_wrongreport
        with data.policies as {
            "defaultPolicy": "accept",
            "reportPending": "accept",
            "scanFailed": "accept",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "scan-result"}
            ]
        }
}

#When report is pending image should be rejected because customPolicy is reject (makes no sense to wait for scan result)
test_report_pending_reject_by_custom_policy {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global custom policy (prefix 'docker.io/') - policy action is 'reject'"] 
        with input as input_example_ns_scan_pending
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "reject"}
            ]
        }
}

#When report is pending image should be accepted because customPolicy is accept (makes no sense to wait for scan result)
test_report_pending_accept_by_custom_policy {
    image_accepted
        with input as input_example_ns_scan_pending
        with data.policies as {
            "defaultPolicy": "reject",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "accept"}
            ]
        }
}

test_missing_report_pending_custom_policy_scan_result {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global custom policy (prefix 'docker.io/') - scan report is pending"]
        with input as input_example_ns_scan_pending
        with data.policies as {
            "defaultPolicy": "reject",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "scan-result"}
            ]
        }
}

# Check that if scan-result is an action for a custom policy, then reportPending must be defined
test_wrong_report_pending_custom_policy_scan_result {
    image_rejected_only_with_msg["Invalid value for reportPending - 'wrong'"]
        with input as input_example_ns_scan_accepted
        with data.policies as {
            "defaultPolicy": "accept",
            "reportPending": "wrong",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "scan-result"}
            ]
        }
}

#When report is pending, and reportPending policy is accept, image should be accepted
test_custom_report_pending_accept {
    image_accepted 
        with input as input_example_ns_scan_pending
        with data.policies as { 
            "defaultPolicy": "reject",
            "reportPending": "accept",
            "scanFailed": "reject",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "scan-result"}
            ]
        }
}

#When scan has failed, and scanFailed policy is reject, image should be rejected
test_custom_report_pending_reject {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global custom policy (prefix 'docker.io/') - scan report is pending"] 
        with input as input_example_ns_scan_pending
        with data.policies as { 
            "defaultPolicy": "reject",
            "reportPending": "reject",
            "scanFailed": "accept",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "scan-result"}
            ]
        }
}

test_missing_scan_failed_custom_policy_scan_result {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global custom policy (prefix 'docker.io/') - scan failed"]
        with input as input_example_ns_scan_failed
        with data.policies as {
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "scan-result"}
            ]
        }
}

# Check that if scan-result is an action for a custom policy, then reportPending must be defined
test_wrong_scan_failed_custom_policy_scan_result {
    image_rejected_only_with_msg["Invalid value for scanFailed - 'wrong'"]
        with input as input_example_ns_scan_accepted
        with data.policies as {
            "defaultPolicy": "accept",
            "scanFailed": "wrong",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "scan-result"}
            ]
        }
}

#When scan has failed, and scanFailed policy is accept, image should be accepted
test_scan_failed_accept_by_custom_policy {
    image_accepted 
        with input as input_example_ns_scan_failed
        with data.policies as { 
            "defaultPolicy": "reject",
            "reportPending": "reject",
            "scanFailed": "accept",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "scan-result"}
            ]
        }
}

#When scan has failed, and scanFailed policy is reject, image should be rejected
test_scan_failed_reject_by_custom_policy {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global custom policy (prefix 'docker.io/') - policy action is 'reject'"] 
        with input as input_example_ns_scan_failed
        with data.policies as { 
            "defaultPolicy": "accept",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "reject"}
            ]
        }
}


#When scan has failed, and scanFailed policy is accept, image should be accepted
test_custom_scan_failed_accept {
    image_accepted 
        with input as input_example_ns_scan_failed
        with data.policies as { 
            "defaultPolicy": "reject",
            "reportPending": "reject",
            "scanFailed": "accept",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "scan-result"}
            ]
        }
}

#When scan has failed, and scanFailed policy is reject, image should be rejected
test_custom_scan_failed_reject {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global custom policy (prefix 'docker.io/') - scan failed"]  
        with input as input_example_ns_scan_failed
        with data.policies as { 
            "defaultPolicy": "accept",
            "reportPending": "accept",
            "scanFailed": "reject",
            "customPolicies": [
                {"prefix": "docker.io/", "action": "scan-result"}
            ]
        }
}

##############################################################
# Tests: Namespace scope, default policy

#Wrong defaultPolicy in current namespace should reject admission
test_ns_wrong_config_current_namespace {
    image_rejected_only_with_msg["Invalid value for defaultPolicy for namespace 'example' - 'wrongnsvalue'"]
        with input as input_example_ns_scan_rejected 
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
    image_accepted 
        with input as input_example_ns_scan_rejected 
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "other": {
                    "defaultPolicy": "wrongnsvalue"
                }
            }
        }
}

test_ns_wrong_config_report_pending {
   image_rejected_only_with_msg["Invalid value for reportPending for namespace 'example' - 'wrongnsvalue'"]
        with input as input_example_ns_scan_accepted 
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "scan-result", "reportPending": "wrongnsvalue"
                }
            }
        }
}

test_ns_wrong_config_scan_failed {
   image_rejected_only_with_msg["Invalid value for scanFailed for namespace 'example' - 'wrongnsvalue'"]
        with input as input_example_ns_scan_accepted 
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "scan-result", "scanFailed": "wrongnsvalue"
                }
            }
        }
}


test_ns_empty_config_report_pending {
   image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy - scan report is pending"]
        with input as input_example_ns_scan_pending 
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "scan-result"
                }
            }
        }
}

test_ns_empty_config_scan_failed {
   image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy - scan failed"]
        with input as input_example_ns_scan_failed 
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "scan-result"
                }
            }
        }
}

#Image should be accepted if defaultPolicy=accept for pod namespace, otherwise rejected (as global defaultPolicy=reject)
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

    image_accepted 
        with input as input_example_ns_scan_rejected
        with data.policies as policy_accept_in_ns_example

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"] 
        with input as input_example_ns_scan_rejected 
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

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy - policy action is 'reject'"]
        with input as input_example_ns_scan_rejected
        with data.policies as policy_reject_in_ns_example

    image_accepted
        with input as input_example_ns_scan_rejected 
        with data.policies as policy_reject_in_ns_other

}

#When policy is scan-result for pod namespace, image should be accepted if the scan result is "accepted"
test_ns_default_policy_scan_result_accepted {
      policy_scan_result_in_ns_other := {
        "defaultPolicy": "reject",
        "byNamespace": {
            "other": {
                "defaultPolicy": "scan-result",
                "reportPending": "reject",
                "scanFailed": "reject"
            }
        }
    }  

    policy_scan_result_in_ns_example := {
        "defaultPolicy": "reject",
        "byNamespace": {
            "example": {
                "defaultPolicy": "scan-result",
                "reportPending": "reject",
                "scanFailed": "reject"
            }
        }
    }  

    image_accepted 
        with input as input_example_ns_scan_accepted
        with data.policies as policy_scan_result_in_ns_example

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"]
        with input as input_example_ns_scan_accepted
        with data.policies as policy_scan_result_in_ns_other
}

#When policy is scan-result for pod namespace, image should be rejected if the scan result is "rejected"
test_ns_default_policy_scan_result_rejected {
      policy_scan_result_in_ns_other := {
        "defaultPolicy": "accept",
        "reportPending": "accept",
        "scanFailed": "accept",
        "byNamespace": {
            "other": {
                "defaultPolicy": "scan-result",
                "reportPending": "accept",
                "scanFailed": "accept"
            }
        }
    }  

    policy_scan_result_in_ns_example := {
        "defaultPolicy": "accept",
        "byNamespace": {
            "example": {
                "defaultPolicy": "scan-result",
                "reportPending": "accept",
                "scanFailed": "accept"
            }
        }
    }

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy - scan result is 'reject'"] 
        with input as input_example_ns_scan_rejected
        with data.policies as policy_scan_result_in_ns_example

    image_accepted
        with input as input_example_ns_scan_rejected
        with data.policies as policy_scan_result_in_ns_other
}


#When policy is scan-result for current, image should be rejected if the scan result is an unexpected value
test_ns_default_policy_scan_result_unexpected {
      policy_scan_result_in_ns_other := {
        "defaultPolicy": "accept",
        "byNamespace": {
            "other": {
                "defaultPolicy": "scan-result",
                "reportPending": "accept",
                "scanFailed": "accept"
            }
        }
    }  

    policy_scan_result_in_ns_example := {
        "defaultPolicy": "accept",
        "byNamespace": {
            "example": {
                "defaultPolicy": "scan-result",
                "reportPending": "accept",
                "scanFailed": "accept"
            }
        }
    }

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy - unexpected ScanReport.Status value 'wrongreport'"] 
        with input as input_example_ns_scan_wrongreport
        with data.policies as policy_scan_result_in_ns_example

    image_accepted
        with input as input_example_ns_scan_wrongreport
        with data.policies as policy_scan_result_in_ns_other
}

#When report is pending image should be rejected because defaultPolicy is reject for current namespace(makes no sense to wait for scan result)
test_ns_report_pending_reject_by_default_policy {
      policy_ns_other := {
        "defaultPolicy": "accept",
        "byNamespace": {
            "other": {
                "defaultPolicy": "reject"
            }
        }
    }  

    policy_ns_example := {
        "defaultPolicy": "accept",
        "byNamespace": {
            "example": {
                "defaultPolicy": "reject"
            }
        }
    }


    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy - policy action is 'reject'"] 
        with input as input_example_ns_scan_pending
        with data.policies as policy_ns_example

    image_accepted
        with input as input_example_ns_scan_pending
        with data.policies as policy_ns_other
}

#When report is pending image should be accepted because defaultPolicy is accept for current namespace (makes no sense to wait for scan result)
test_ns_report_pending_accept_by_default_policy {
      policy_ns_other := {
        "defaultPolicy": "reject",
        "byNamespace": {
            "other": {
                "defaultPolicy": "accept"
            }
        }
    }  

    policy_ns_example := {
        "defaultPolicy": "reject",
        "byNamespace": {
            "example": {
                "defaultPolicy": "accept"
            }
        }
    }

    image_accepted
        with input as input_example_ns_scan_pending
        with data.policies as policy_ns_example

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"] 
        with input as input_example_ns_scan_pending
        with data.policies as policy_ns_other
}

#When report is pending, and reportPending policy is accept for current namespace, image should be accepted
test_ns_report_pending_accept {
      policy_ns_other := {
        "defaultPolicy": "reject",
        "byNamespace": {
            "other": {
                "defaultPolicy": "scan-result",
                "reportPending": "accept",
                "scanFailed": "reject"
            }
        }
    }  

    policy_ns_example := {
        "defaultPolicy": "reject",
        "byNamespace": {
            "example": {
                "defaultPolicy": "scan-result",
                "reportPending": "accept",
                "scanFailed": "reject"
            }
        }
    }

    image_accepted
        with input as input_example_ns_scan_pending
        with data.policies as policy_ns_example

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"] 
        with input as input_example_ns_scan_pending
        with data.policies as policy_ns_other
}

#When scan has failed, and scanFailed policy is reject for current namespace, image should be rejected
test_ns_report_pending_reject {
      policy_ns_other := {
        "defaultPolicy": "accept",
        "byNamespace": {
            "other": {
                "defaultPolicy": "scan-result",
                "reportPending": "reject",
                "scanFailed": "accept"
            }
        }
    }  

    policy_ns_example := {
        "defaultPolicy": "accept",
        "byNamespace": {
            "example": {
                "defaultPolicy": "scan-result",
                "reportPending": "reject",
                "scanFailed": "accept"
            }
        }
    }

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy - scan report is pending"] 
        with input as input_example_ns_scan_pending
        with data.policies as policy_ns_example

    image_accepted
        with input as input_example_ns_scan_pending
        with data.policies as policy_ns_other
}

#When scan has failed, and defaultPolicy is accept for current namespace, image should be accepted
test_ns_scan_failed_accept_by_default_policy {
      policy_ns_other := {
        "defaultPolicy": "reject",
        "byNamespace": {
            "other": {
                "defaultPolicy": "accept"
            }
        }
    }  

    policy_ns_example := {
        "defaultPolicy": "reject",
        "byNamespace": {
            "example": {
                "defaultPolicy": "accept"
            }
        }
    }

    image_accepted
        with input as input_example_ns_scan_failed
        with data.policies as policy_ns_example

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"] 
        with input as input_example_ns_scan_failed
        with data.policies as policy_ns_other
}


#When scan has failed, and defaultPolicy is reject for current namespace, image should be rejected
test_ns_scan_failed_reject_by_default_policy {
      policy_ns_other := {
        "defaultPolicy": "accept",
        "byNamespace": {
            "other": {
                "defaultPolicy": "reject"
            }
        }
    }  

    policy_ns_example := {
        "defaultPolicy": "accept",
        "byNamespace": {
            "example": {
                "defaultPolicy": "reject"
            }
        }
    }

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy - policy action is 'reject'"] 
        with input as input_example_ns_scan_failed
        with data.policies as policy_ns_example

    image_accepted
        with input as input_example_ns_scan_failed
        with data.policies as policy_ns_other

}


#When scan has failed, and scanFailed policy is accept for current namespace, image should be accepted
test_ns_scan_failed_accept {
      policy_ns_other := {
        "defaultPolicy": "reject",
        "byNamespace": {
            "other": {
                "defaultPolicy": "scan-result",
                "reportPending": "reject",
                "scanFailed": "accept"
            }
        }
    }  

    policy_ns_example := {
        "defaultPolicy": "reject",
        "byNamespace": {
            "example": {
                "defaultPolicy": "scan-result",
                "reportPending": "reject",
                "scanFailed": "accept"
            }
        }
    }

    image_accepted
        with input as input_example_ns_scan_failed
        with data.policies as policy_ns_example

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"] 
        with input as input_example_ns_scan_failed
        with data.policies as policy_ns_other
}


#When scan has failed, and scanFailed policy is reject for current namespace, image should be rejected
test_ns_scan_failed_reject {
      policy_ns_other := {
        "defaultPolicy": "accept",
        "byNamespace": {
            "other": {
                "defaultPolicy": "scan-result",
                "reportPending": "accept",
                "scanFailed": "reject"
            }
        }
    }  

    policy_ns_example := {
        "defaultPolicy": "accept",
        "byNamespace": {
            "example": {
                "defaultPolicy": "scan-result",
                "reportPending": "accept",
                "scanFailed": "reject"
            }
        }
    }

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy - scan failed"] 
        with input as input_example_ns_scan_failed
        with data.policies as policy_ns_example

    image_accepted
        with input as input_example_ns_scan_failed
        with data.policies as policy_ns_other
}

##############################################################
# Tests: Namespace scope, custom policies

test_ns_custom_empty_action_current_namespace {
    image_rejected_only_with_msg["Invalid value for namespace 'example' customPolicy with prefix 'docker.io/' - '<empty>'"]
        with input as input_example_ns_scan_accepted
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "customPolicies": [
                        { "prefix": "docker.io/" }
                    ]
                }
            }
        }
}

test_ns_custom_empty_action_other_namespace {
    image_accepted
        with input as input_example_ns_scan_accepted
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "other": {
                    "customPolicies": [
                        { "prefix": "docker.io/" }
                    ]
                }
            }
        }
}

#Wrong customPolicy action should reject with error message
test_ns_custom_wrong_action_current_namespace {
    image_rejected_only_with_msg["Invalid value for namespace 'example' customPolicy with prefix 'docker.io/' - 'wrongvalue'"]
        with input as input_example_ns_scan_accepted
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "wrongvalue" }
                    ]
                }
            }
        }
}

test_ns_custom_wrong_action_other_namespace {
    image_accepted
        with input as input_example_ns_scan_accepted
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "other": {
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "wrongvalue" }
                    ]
                }
            }
        }
}

test_ns_custom_no_report_pending_if_action_is_scan_result {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' custom policy (prefix 'docker.io/') - scan report is pending"]
        with input as input_example_ns_scan_pending
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }
}

test_ns_custom_policy_accept_current_namespace {

    image_accepted 
        with input as input_example_ns_scan_rejected
        with data.policies as {
            "defaultPolicy": "reject",
            "byNamespace": {
                "example": {
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "accept" }
                    ]
                }
            }
        }

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"] 
        with input as input_example_ns_scan_rejected
        with data.policies as {
            "defaultPolicy": "reject",
            "byNamespace": {
                "example": {
                    "customPolicies": [
                        { "prefix": "---docker.io/", "action": "accept" }
                    ]
                }
            }
        }
}

test_ns_custom_policy_accept_other_namespace {

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"] 
        with input as input_example_ns_scan_rejected
        with data.policies as {
            "defaultPolicy": "reject",
            "byNamespace": {
                "other": {
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "accept" }
                    ]
                }
            }
        }
}

test_ns_custom_policy_reject_current_namespace {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' custom policy (prefix 'docker.io/') - policy action is 'reject'"] 
        with input as input_example_ns_scan_rejected
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "reject" }
                    ]
                }
            }
        }

    image_accepted
        with input as input_example_ns_scan_rejected
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "customPolicies": [
                        { "prefix": "---docker.io/", "action": "reject" }
                    ]
                }
            }
        }
}

test_ns_custom_policy_reject_other_namespace {

    image_accepted
        with input as input_example_ns_scan_rejected
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "other": {
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "reject" }
                    ]
                }
            }
        }
}

test_ns_custom_policy_scan_result_accepted_current_namespace {
    image_accepted
        with input as input_example_ns_scan_accepted
        with data.policies as {
            "defaultPolicy": "reject",
            "reportPending": "reject",
            "scanFailed": "reject",
            "byNamespace": {
                "example": {
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"]
        with input as input_example_ns_scan_accepted
        with data.policies as {
            "defaultPolicy": "reject",
            "byNamespace": {
                "example": {
                    "customPolicies": [
                        { "prefix": "---docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }
}

test_ns_custom_policy_scan_result_accepted_other_namespace {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"]
        with input as input_example_ns_scan_accepted
        with data.policies as {
            "defaultPolicy": "reject",
            "byNamespace": {
                "other": {
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }
}

test_ns_custom_policy_scan_result_rejected_current_namespace {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' custom policy (prefix 'docker.io/') - scan result is 'reject'"]
        with input as input_example_ns_scan_rejected
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }

    image_accepted
        with input as input_example_ns_scan_rejected
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "customPolicies": [
                        { "prefix": "---docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }
}

test_ns_custom_policy_scan_result_rejected_other_namespace {
    image_accepted
        with input as input_example_ns_scan_rejected
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "other": {
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }
}


test_ns_custom_policy_scan_result_unexpected_current_namespace {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' custom policy (prefix 'docker.io/') - unexpected ScanReport.Status value 'wrongreport'"]
        with input as input_example_ns_scan_wrongreport
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }

    image_accepted
        with input as input_example_ns_scan_wrongreport
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "example": {
                    "customPolicies": [
                        { "prefix": "---docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }
}

test_ns_custom_policy_scan_result_unexpected_other_namespace {
    image_accepted
        with input as input_example_ns_scan_wrongreport
        with data.policies as {
            "defaultPolicy": "accept",
            "byNamespace": {
                "other": {
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }
}


test_ns_custom_policy_report_pending_reject_by_custom_policy_current_namespace {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' custom policy (prefix 'docker.io/') - policy action is 'reject'"]
        with input as input_example_ns_scan_pending
        with data.policies as {
            "defaultPolicy": "accept",
            "reportPending": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "reject" }
                    ]
                }
            }
        }

    image_accepted
        with input as input_example_ns_scan_pending
        with data.policies as {
            "defaultPolicy": "accept",
            "reportPending": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        { "prefix": "---docker.io/", "action": "reject" }
                    ]
                }
            }
        }
}

test_ns_custom_policy_report_pending_reject_by_custom_policy_other_namespace {
    image_accepted
        with input as input_example_ns_scan_pending
        with data.policies as {
            "defaultPolicy": "accept",
            "reportPending": "accept",
            "byNamespace": {
                "other": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "reject" }
                    ]
                }
            }
        }
}


test_ns_custom_policy_report_pending_accept_by_custom_policy_current_namespace {
    image_accepted
        with input as input_example_ns_scan_pending
        with data.policies as {
            "defaultPolicy": "reject",
            "reportPending": "reject",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "accept" }
                    ]
                }
            }
        }

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy - policy action is 'reject'"]
        with input as input_example_ns_scan_pending
        with data.policies as {
            "defaultPolicy": "reject",
            "reportPending": "reject",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        { "prefix": "---docker.io/", "action": "accept" }
                    ]
                }
            }
        }
}

test_ns_custom_policy_report_pending_accept_by_custom_policy_other_namespace {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"]
        with input as input_example_ns_scan_pending
        with data.policies as {
            "defaultPolicy": "reject",
            "reportPending": "reject",
            "byNamespace": {
                "other": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "accept" }
                    ]
                }
            }
        }
}


test_ns_custom_policy_report_pending_reject_current_namespace {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' custom policy (prefix 'docker.io/') - scan report is pending"]
        with input as input_example_ns_scan_pending
        with data.policies as {
            "defaultPolicy": "accept",
            "reportPending": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "reportPending": "reject",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }

    image_accepted
        with input as input_example_ns_scan_pending
        with data.policies as {
            "defaultPolicy": "accept",
            "reportPending": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "reportPending": "reject",
                    "customPolicies": [
                        { "prefix": "---docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }
}

test_ns_custom_policy_report_pending_reject_other_namespace {
    image_accepted
        with input as input_example_ns_scan_pending
        with data.policies as {
            "defaultPolicy": "accept",
            "reportPending": "accept",
            "byNamespace": {
                "other": {
                    "defaultPolicy": "accept",
                    "reportPending": "reject",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }
}


test_ns_custom_policy_report_pending_accept_current_namespace {
    image_accepted
        with input as input_example_ns_scan_pending
        with data.policies as {
            "defaultPolicy": "reject",
            "reportPending": "reject",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject",
                    "reportPending": "accept",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy - policy action is 'reject'"]
        with input as input_example_ns_scan_pending
        with data.policies as {
            "defaultPolicy": "reject",
            "reportPending": "reject",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject",
                    "reportPending": "accept",
                    "customPolicies": [
                        { "prefix": "---docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }
}

test_ns_custom_policy_report_pending_accept_other_namespace {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"]
        with input as input_example_ns_scan_pending
        with data.policies as {
            "defaultPolicy": "reject",
            "reportPending": "reject",
            "byNamespace": {
                "other": {
                    "defaultPolicy": "reject",
                    "reportPending": "accept",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }
}

test_ns_custom_policy_scan_failed_reject_by_custom_policy_current_namespace {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' custom policy (prefix 'docker.io/') - policy action is 'reject'"]
        with input as input_example_ns_scan_failed
        with data.policies as {
            "defaultPolicy": "accept",
            "scanFailed": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "reject" }
                    ]
                }
            }
        }

    image_accepted
        with input as input_example_ns_scan_failed
        with data.policies as {
            "defaultPolicy": "accept",
            "scanFailed": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        { "prefix": "---docker.io/", "action": "reject" }
                    ]
                }
            }
        }
}

test_ns_custom_policy_scan_failed_reject_by_custom_policy_other_namespace {
    image_accepted
        with input as input_example_ns_scan_failed
        with data.policies as {
            "defaultPolicy": "accept",
            "scanFailed": "accept",
            "byNamespace": {
                "other": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "reject" }
                    ]
                }
            }
        }
}


test_ns_custom_policy_scan_failed_accept_by_custom_policy_current_namespace {
    image_accepted
        with input as input_example_ns_scan_failed
        with data.policies as {
            "defaultPolicy": "reject",
            "scanFailed": "reject",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "accept" }
                    ]
                }
            }
        }

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy - policy action is 'reject'"]
        with input as input_example_ns_scan_failed
        with data.policies as {
            "defaultPolicy": "reject",
            "scanFailed": "reject",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        { "prefix": "---docker.io/", "action": "accept" }
                    ]
                }
            }
        }
}

test_ns_custom_policy_scan_failed_accept_by_custom_policy_other_namespace {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"]
        with input as input_example_ns_scan_failed
        with data.policies as {
            "defaultPolicy": "reject",
            "scanFailed": "reject",
            "byNamespace": {
                "other": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "accept" }
                    ]
                }
            }
        }
}


test_ns_custom_policy_scan_failed_reject_current_namespace {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' custom policy (prefix 'docker.io/') - scan failed"]
        with input as input_example_ns_scan_failed
        with data.policies as {
            "defaultPolicy": "accept",
            "scanFailed": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "scanFailed": "reject",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }

    image_accepted
        with input as input_example_ns_scan_failed
        with data.policies as {
            "defaultPolicy": "accept",
            "scanFailed": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "scanFailed": "reject",
                    "customPolicies": [
                        { "prefix": "---docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }
}

test_ns_custom_policy_scan_failed_reject_other_namespace {
    image_accepted
        with input as input_example_ns_scan_failed
        with data.policies as {
            "defaultPolicy": "accept",
            "scanFailed": "accept",
            "byNamespace": {
                "other": {
                    "defaultPolicy": "accept",
                    "scanFailed": "reject",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }
}


test_ns_custom_policy_scan_failed_accept_current_namespace {
    image_accepted
        with input as input_example_ns_scan_failed
        with data.policies as {
            "defaultPolicy": "reject",
            "scanFailed": "reject",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject",
                    "scanFailed": "accept",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy - policy action is 'reject'"]
        with input as input_example_ns_scan_failed
        with data.policies as {
            "defaultPolicy": "reject",
            "scanFailed": "reject",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject",
                    "scanFailed": "accept",
                    "customPolicies": [
                        { "prefix": "---docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }
}

test_ns_custom_policy_scan_failed_accept_other_namespace {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global default policy - policy action is 'reject'"]
        with input as input_example_ns_scan_failed
        with data.policies as {
            "defaultPolicy": "reject",
            "reportPending": "reject",
            "byNamespace": {
                "other": {
                    "defaultPolicy": "reject",
                    "reportPending": "accept",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }
}

# Tests: Inheritance


test_report_pending_inherited {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' custom policy (prefix 'docker.io/') - scan report is pending"]
        with input as input_example_ns_scan_pending
        with data.policies as {
            "defaultPolicy": "accept",
            "reportPending": "reject",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }

    image_accepted
        with input as input_example_ns_scan_pending
        with data.policies as {
            "defaultPolicy": "reject",
            "reportPending": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }

}

test_scan_failed_inherited {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' custom policy (prefix 'docker.io/') - scan failed"]
        with input as input_example_ns_scan_failed
        with data.policies as {
            "defaultPolicy": "accept",
            "scanFailed": "reject",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "accept",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }

    image_accepted
        with input as input_example_ns_scan_failed
        with data.policies as {
            "defaultPolicy": "reject",
            "scanFailed": "accept",
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject",
                    "customPolicies": [
                        { "prefix": "docker.io/", "action": "scan-result" }
                    ]
                }
            }
        }

}


########


test_inheritance_ns_omit_default_policy {
    image_accepted 
        with input as input_example_ns_scan_rejected
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

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' custom policy (prefix 'docker.io/') - policy action is 'reject'"]
        with input as input_example_ns_scan_accepted
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

    image_accepted
        with input as input_example_ns_scan_accepted
        with data.policies as {
            "defaultPolicy": "reject",
            "byNamespace": {
                "example": {
                    "customPolicies": [
                        {"prefix": "docker.io/", "action": "scan-result"}
                    ]
                }
            }
        }
}

test_inheritance_ns_omit_custom_policies {
    image_accepted 
        with input as input_example_ns_scan_rejected
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

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global custom policy (prefix 'docker.io/') - policy action is 'reject'"] 
        with input as input_example_ns_scan_accepted
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
    image_accepted 
        with input as input_example_ns_scan_rejected
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

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Global custom policy (prefix 'docker.io/') - policy action is 'reject'"] 
        with input as input_example_ns_scan_accepted
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

    image_accepted
        with input as input_example_ns_scan_accepted
        with data.policies as {
            "defaultPolicy": "reject",
            "customPolicies": [
                        {"prefix": "docker.io/", "action": "scan-result"}
                    ],
            "byNamespace": {
                "example": {
                    "defaultPolicy": "reject"
                }
            }
        }

}

test_inheritance_override_custom_in_namespace {
    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' default policy - policy action is 'reject'"]
        with input as input_example_ns_scan_accepted
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

    image_rejected_only_with_msg["Image 'docker.io/myrepo/myimage' REJECTED. Namespace 'example' custom policy (prefix 'docker.io/') - policy action is 'reject'"]
        with input as input_example_ns_scan_accepted
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
                        {"prefix": "docker.io/", "action": "reject"}
                    ]
                }
            }
        } 
}
