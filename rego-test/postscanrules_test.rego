package postscanimageadmission

input_example_ns_scan_rejected := {
    "AdmissionRequest": {
        "namespace": "example",
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
        "namespace": "example",
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
        "namespace": "example",
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
        "namespace": "example",
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
        "namespace": "example",
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

###############################
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


###############################
# Tests

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

test_empty_config {
    image_rejected["Invalid value for defaultPolicy - '<empty>'"]
        with input as {}
        with data.policies as {}
}

test_empty_config_default_policy {
    image_rejected["Invalid value for reportPending - '<empty>'"] 
        with input as input_example_ns_scan_rejected
        with data.policies as {"defaultPolicy": "scan-result"}

    image_rejected["Invalid value for scanFailed - '<empty>'"] 
        with input as input_example_ns_scan_rejected
        with data.policies as {"defaultPolicy": "scan-result"}
}

#Wrong defaultPolicy value should reject with error message
test_wrong_config_default_policy {
    image_rejected["Invalid value for defaultPolicy - 'wrongvalue'"] 
        with input as input_example_ns_scan_rejected
        with data.policies as {"defaultPolicy": "wrongvalue"}
}

test_wrong_config_report_pending {
    image_rejected["Invalid value for reportPending - 'wrongvalue'"] 
        with input as input_example_ns_scan_rejected
        with data.policies as {"defaultPolicy": "scan-result", "reportPending": "wrongvalue"}
}

test_wrong_config_scan_failed {
    image_rejected["Invalid value for scanFailed - 'wrongvalue'"] 
        with input as input_example_ns_scan_rejected
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
    image_rejected_only_with_msg["Image rejected by default policy for image 'docker.io/myrepo/myimage'"]
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
    image_rejected_only_with_msg[_] 
        with input as input_example_ns_scan_rejected 
        with data.policies as { 
            "defaultPolicy": "scan-result",
            "reportPending": "accept",
            "scanFailed": "accept"
        }
}


#When policy is scan-result, image should be rejected if the scan result is an unexpected value
test_default_policy_scan_result_unexpected {
    image_rejected_only_with_msg["Image rejected - Unexpected ScanReport status value 'wrongreport' for image 'docker.io/myrepo/myimage'"]  
        with input as input_example_ns_scan_wrongreport
        with data.policies as { 
            "defaultPolicy": "scan-result",
            "reportPending": "accept",
            "scanFailed": "accept"
        }
}

#When report is pending image should be rejected because defaultPolicy is reject (makes no sense to wait for scan result)
test_report_pending_reject_by_default_policy {
    image_rejected_only_with_msg["Image rejected by default policy for image 'docker.io/myrepo/myimage'"] 
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
    image_rejected_only_with_msg["Image rejected - scan report is pending for image 'docker.io/myrepo/myimage'"] 
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


#When scan has failed, and scanFailed policy is reject, image should be rejected
test_scan_failed_reject_by_default_policy {
    image_rejected_only_with_msg["Image rejected by default policy for image 'docker.io/myrepo/myimage'"] 
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
    image_rejected_only_with_msg["Image rejected - scan failed for image 'docker.io/myrepo/myimage'"]  
        with input as input_example_ns_scan_failed
        with data.policies as { 
            "defaultPolicy": "scan-result",
            "reportPending": "accept",
            "scanFailed": "reject"
        }
}

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
   image_rejected["Invalid value for reportPending for namespace 'example' - 'wrongnsvalue'"]
        with input as input_example_ns_scan_rejected 
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
   image_rejected["Invalid value for scanFailed for namespace 'example' - 'wrongnsvalue'"]
        with input as input_example_ns_scan_rejected 
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
   image_rejected["Invalid value for reportPending for namespace 'example' - '<empty>'"]
        with input as input_example_ns_scan_rejected 
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
   image_rejected["Invalid value for scanFailed for namespace 'example' - '<empty>'"]
        with input as input_example_ns_scan_rejected 
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

    image_rejected_only_with_msg["Image rejected by default policy for image 'docker.io/myrepo/myimage'"] 
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

    image_rejected_only_with_msg["Image rejected by namespace 'example' default policy for image 'docker.io/myrepo/myimage'"]
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

    image_rejected_only_with_msg["Image rejected by default policy for image 'docker.io/myrepo/myimage'"]
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

    image_rejected_only_with_msg["Image rejected by namespace 'example' by scan result for image 'docker.io/myrepo/myimage'"] 
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

    image_rejected_only_with_msg["Image rejected by namespace 'example' - Unexpected ScanReport status value 'wrongreport' for image 'docker.io/myrepo/myimage'"] 
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


    image_rejected_only_with_msg["Image rejected by namespace 'example' default policy for image 'docker.io/myrepo/myimage'"] 
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

    image_rejected_only_with_msg["Image rejected by default policy for image 'docker.io/myrepo/myimage'"] 
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

    image_rejected_only_with_msg["Image rejected by default policy for image 'docker.io/myrepo/myimage'"] 
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

    image_rejected_only_with_msg["Image rejected by namespace 'example' - scan report is pending for image 'docker.io/myrepo/myimage'"] 
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

    image_rejected_only_with_msg["Image rejected by default policy for image 'docker.io/myrepo/myimage'"] 
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

    image_rejected_only_with_msg["Image rejected by namespace 'example' default policy for image 'docker.io/myrepo/myimage'"] 
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

    image_rejected_only_with_msg["Image rejected by default policy for image 'docker.io/myrepo/myimage'"] 
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

    image_rejected_only_with_msg["Image rejected by namespace 'example' - scan failed for image 'docker.io/myrepo/myimage'"] 
        with input as input_example_ns_scan_failed
        with data.policies as policy_ns_example

    image_accepted
        with input as input_example_ns_scan_failed
        with data.policies as policy_ns_other
}
