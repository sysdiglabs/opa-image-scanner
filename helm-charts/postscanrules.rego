
##############################
# Post-Scan rules
##############################

valid_policy_values := ["accept", "reject", "scan-result"]

# Configuration errors

invalid_scan_failed_policy[value] {
        default_get("defaultPolicy") == "scan-result"
        not default_get("scanFailed") == "accept"
        not default_get("scanFailed") == "reject"
        value := default_get("scanFailed")
}

invalid_scan_failed_policy["<empty>"] {
        default_get("defaultPolicy") == "scan-result"
        not default_get("scanFailed")
}

invalid_report_pending_policy[value] {
        default_get("defaultPolicy") == "scan-result"
        not default_get("reportPending") == "accept"
        not default_get("reportPending") == "reject"
        value := default_get("reportPending")
}

invalid_report_pending_policy["<empty>"] {
        default_get("defaultPolicy") == "scan-result"
        not default_get("reportPending")
}

invalid_ns_report_pending_policy[value] {
        defined_in_namespace["reportPending"]
        not ns_get("reportPending") == "accept"
        not ns_get("reportPending") == "reject"
        value := ns_get("reportPending")
}

invalid_ns_report_pending_policy["<empty>"] {
        ns_get("defaultPolicy") == "scan-result"
        not ns_get("reportPending")
}

invalid_ns_scan_failed_policy[value] {
        defined_in_namespace["scanFailed"]
        not ns_get("scanFailed") == "accept"
        not ns_get("scanFailed") == "reject"
        value := ns_get("scanFailed")
}

invalid_ns_scan_failed_policy["<empty>"] {
        ns_get("defaultPolicy") == "scan-result"
        not ns_get("scanFailed")
}

config_error["ScanReport is missing in input"] {
        not input.ScanReport
}

config_error[msg] {
        some value
        invalid_report_pending_policy[value]
        msg :=  sprintf("Invalid value for reportPending - '%s'", [value])
}

config_error[msg] {
        some value
        invalid_scan_failed_policy[value]
        msg := sprintf("Invalid value for scanFailed - '%s'", [value])
}

config_error[msg] {
        some value
        invalid_ns_report_pending_policy[value]
        msg := sprintf("Invalid value for reportPending for namespace '%s' - '%s'", [namespace, value])
}

config_error[msg] {
        some value
        invalid_ns_scan_failed_policy[value]
        msg := sprintf("Invalid value for scanFailed for namespace '%s' - '%s'", [namespace, value])
}

# Scan result helpers

scan_result_rejected {
        input.ScanReport.Status == "rejected"
}

scan_result_failed {
        input.ScanReport.Status == "scan_failed"
}

scan_result_not_available {
        input.ScanReport.Status == "report_not_available"
}

scan_result_unexpected[value] {
        value = input.ScanReport.Status 
        not value == "accepted"
        not value == "rejected"
        not value == "scan_failed"
        not value == "report_not_available"
}

##############################
# Decission policies

# Default policies



# Per-namespace and registry black/white list settings

# ns_always_accept {
#         defined_in_namespace["alwaysAccept"]
#         some i
#         prefix := ns_get("alwaysAccept")[i]
#         startswith(input.ScanReport.ImageAndTag, prefix)
# }

# ns_always_scan_result {
#         defined_in_namespace["alwaysScanResult"]
#         some i
#         prefix := ns_get("alwaysScanResult")[i]
#         startswith(input.ScanReport.ImageAndTag, prefix)
# }

# ns_check_scan_result {
#         ns_always_scan_result
# }

# ns_always_reject[msg] {
#         defined_in_namespace["alwaysReject"]
#         some i
#         prefix := ns_get("alwaysReject")[i]
#         startswith(input.ScanReport.ImageAndTag, prefix)
#         msg := sprintf("Image rejected - prefix '%s' is blacklisted", [prefix])
# }

# ns_deny_image[msg] {
#         ns_always_reject[msg]
# }


# Final decision

image := input.ScanReport.ImageAndTag
imagePolicy := final_image_policy(image)

image_action_scan_result[[ns, prefix]] {
        imagePolicy = {"ns": ns, "prefix": prefix, "action": "scan-result"}
} 

image_action_reject[[ns, prefix]] {
        imagePolicy = {"ns": ns, "prefix": prefix, "action": "reject"}
}

deny_image[msg] {
        image_action_scan_result[[false,_]]
        scan_result_unexpected[value]
        msg := sprintf("Image rejected - Unexpected ScanReport status value '%s' for image '%s'", [value, image])
}


deny_image[msg] {
        image_action_scan_result[[true,_]]
        scan_result_unexpected[value]
        msg := sprintf("Image rejected by namespace '%s' - Unexpected ScanReport status value '%s' for image '%s'", [namespace, value, image])
}

deny_image[msg] {
        image_action_scan_result[[false,_]]
        scan_result_not_available
        default_get("reportPending") == "reject"
        msg := sprintf("Image rejected - scan report is pending for image '%s'", [image])
}

deny_image[msg] {
        image_action_scan_result[[true,_]]
        scan_result_not_available
        ns_get("reportPending") == "reject"
        msg := sprintf("Image rejected by namespace '%s' - scan report is pending for image '%s'", [namespace, image])
}

deny_image[msg] {
        image_action_scan_result[[false,_]]
        scan_result_failed
        default_get("scanFailed") == "reject"
        msg := sprintf("Image rejected - scan failed for image '%s'", [image])
}

deny_image[msg] {
        image_action_scan_result[[true,_]]
        scan_result_failed
        ns_get("scanFailed") == "reject"
        msg := sprintf("Image rejected by namespace '%s' - scan failed for image '%s'", [namespace, image])
}

deny_image[msg] {
        image_action_scan_result[[false,_]]
        scan_result_rejected
        msg := sprintf("Image rejected by scan result for image '%s'", [image])
}

deny_image[msg] {
        image_action_scan_result[[true,_]]
        scan_result_rejected
        msg := sprintf("Image rejected by namespace '%s' by scan result for image '%s'", [namespace, image])
}

deny_image[msg] {
        image_action_reject[[false, null]]
        msg := sprintf("Image rejected by default policy for image '%s'", [image])
}

deny_image[msg] {
        image_action_reject[[true, null]]
        msg := sprintf("Image rejected by namespace '%s' default policy for image '%s'", [namespace, image])
}


deny_image[msg] {
        prefix != null
        image_action_reject[[false, prefix]]
        msg := sprintf("Image rejected by custom policy by prefix '%s' for image '%s'", [prefix, image])
}

deny_image[msg] {
        prefix != null
        image_action_reject[[true, prefix]]
        msg := sprintf("Image rejected by namespace '%s' custom policy by prefix '%s' for image '%s'", [namespace, prefix, image])
}

deny_image[msg] {
        config_error[msg]
}
