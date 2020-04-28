package postscanimageadmission

empty_input := {}
policies_no_defaults := {}

policies_1 := {
        "defaultPolicy": "scan-result",
        "reportPending": "reject",
        "scanFailed": "reject"
    }


input_accepted := {
    "AdmissionRequest": {
        "namespace": "dev",
        "object": {
            "metadata": {
                "namespace": "dev"
            }
        }
    },
    "ScanReport": {
        "ImageAndTag": "some-registry.com/myimage:mytag",
        "Status": "accepted"
    }
}

input_rejected := {
    "AdmissionRequest": {
        "namespace": "dev",
        "object": {
            "metadata": {
                "namespace": "dev"
            }
        }
    },
    "ScanReport": {
        "ImageAndTag": "some-registry.com/myimage:mytag",
        "Status": "rejected"
    }
}

test_empty_config {
    deny_image["AdmissionRequest is missing in input"] with input as empty_input with data.policies as policies_no_defaults
    deny_image["ScanReport is missing in input"] with input as empty_input with data.policies as policies_no_defaults
    deny_image["Invalid value for defaultPolicy - '<empty>'"] with input as empty_input with data.policies as policies_no_defaults
    deny_image["Invalid value for reportPending - '<empty>'"] with input as empty_input with data.policies as policies_no_defaults
    deny_image["Invalid value for scanFailed - '<empty>'"] with input as empty_input with data.policies as policies_no_defaults
}


test_missing_admission_request {
    deny_image["AdmissionRequest is missing in input"] with input as empty_input with data.policies as policies_no_defaults
}

test_missing_scan_report {
    deny_image["ScanReport is missing in input"] with input as empty_input with data.policies as policies_no_defaults
}

test_rejected_by_scan_result {
    some msg
    deny_image[msg] with input as input_rejected with data.policies as policies_1
}

image_denied {
    deny_image[_]
}

test_accepted_by_scan_result {
    not image_denied with input as input_accepted with data.policies as policies_1
}
