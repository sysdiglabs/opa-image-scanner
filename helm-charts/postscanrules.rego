
##############################
# Post-Scan rules
##############################

valid_policy_values := ["accept", "reject", "scan-result"]

# Configuration errors

scan_result_final_value(policyKey) = value {
        value := ns_get(policyKey)
}  else = value {
        value := global_get(policyKey)
} else = value {
        # Default value is reject if not specified
        value := "reject"
}

valid_scan_result_value[value] {
        value = ["accept", "reject"][_]
}

invalid_report_pending_policy[value] {
        imagePolicy.action == "scan-result"
        not imagePolicy.ns
        value := scan_result_final_value("reportPending")
        not valid_scan_result_value[value]
}

invalid_ns_report_pending_policy[value] {
        imagePolicy.action == "scan-result"
        imagePolicy.ns
        value := scan_result_final_value("reportPending")
        not valid_scan_result_value[value]
}

invalid_scan_failed_policy[value] {
        imagePolicy.action == "scan-result"
        not imagePolicy.ns
        value := scan_result_final_value("scanFailed")
        not valid_scan_result_value[value]
}

invalid_ns_scan_failed_policy[value] {
        imagePolicy.action == "scan-result"
        imagePolicy.ns
        value := scan_result_final_value("scanFailed")
        not valid_scan_result_value[value]
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

config_error[msg] {
        policy := imagePolicy
        not policy.ns
        not policy.prefix == null
        not valid_policy_value[policy.action]
        msg := sprintf("Invalid value for customPolicy with prefix '%s' - '%s'", [policy.prefix, policy.action])
}

config_error[msg] {
        policy := imagePolicy
        policy.ns
        not policy.prefix == null
        not valid_policy_value[policy.action]
        msg := sprintf("Invalid value for namespace '%s' customPolicy with prefix '%s' - '%s'", [namespace, policy.prefix, policy.action])
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
        image_action_scan_result[[false,null]]
        scan_result_unexpected[value]
        msg := sprintf("Image rejected - Unexpected ScanReport status value '%s' for image '%s'", [value, image])
}


deny_image[msg] {
        image_action_scan_result[[true,null]]
        scan_result_unexpected[value]
        msg := sprintf("Image rejected by namespace '%s' - Unexpected ScanReport status value '%s' for image '%s'", [namespace, value, image])
}

deny_image[msg] {
        image_action_scan_result[[false,prefix]]
        prefix != null
        scan_result_unexpected[value]
        msg := sprintf("Image rejected - Unexpected ScanReport status value '%s' by prefix '%s' for image '%s'", [value, prefix, image])
}

deny_image[msg] {
        image_action_scan_result[[true,prefix]]
        prefix != null
        scan_result_unexpected[value]
        msg := sprintf("Image rejected by namespace '%s' - Unexpected ScanReport status value '%s' by prefix '%s' for image '%s'", [namespace, value, prefix, image])
}

deny_image[msg] {
        image_action_scan_result[[false,null]]
        scan_result_not_available
        scan_result_final_value("reportPending") == "reject"
        msg := sprintf("Image rejected - scan report is pending for image '%s'", [image])
}

deny_image[msg] {
        image_action_scan_result[[true,null]]
        scan_result_not_available
        scan_result_final_value("reportPending") == "reject"
        msg := sprintf("Image rejected by namespace '%s' - scan report is pending for image '%s'", [namespace, image])
}

deny_image[msg] {
        image_action_scan_result[[false,prefix]]
        prefix != null
        scan_result_not_available
        scan_result_final_value("reportPending") == "reject"
        msg := sprintf("Image rejected - scan report is pending by prefix '%s' for image '%s'", [prefix, image])
}

deny_image[msg] {
        image_action_scan_result[[true,prefix]]
        prefix != null
        scan_result_not_available
        scan_result_final_value("reportPending") == "reject"
        msg := sprintf("Image rejected by namespace '%s' - scan report is pending by prefix '%s' for image '%s'", [namespace, prefix, image])
}

deny_image[msg] {
        image_action_scan_result[[false,null]]
        scan_result_failed
        scan_result_final_value("scanFailed") == "reject"
        msg := sprintf("Image rejected - scan failed for image '%s'", [image])
}

deny_image[msg] {
        image_action_scan_result[[true,null]]
        scan_result_failed
        scan_result_final_value("scanFailed") == "reject"
        msg := sprintf("Image rejected by namespace '%s' - scan failed for image '%s'", [namespace, image])
}


deny_image[msg] {
        image_action_scan_result[[false,prefix]]
        prefix != null
        scan_result_failed
        scan_result_final_value("scanFailed") == "reject"
        msg := sprintf("Image rejected - scan failed by prefix '%s' for image '%s'", [prefix, image])
}

deny_image[msg] {
        image_action_scan_result[[true,prefix]]
        prefix != null
        scan_result_failed
        scan_result_final_value("scanFailed") == "reject"
        msg := sprintf("Image rejected by namespace '%s' - scan failed by prefix '%s' for image '%s'", [namespace, prefix, image])
}

deny_image[msg] {
        image_action_scan_result[[false,null]]
        scan_result_rejected
        msg := sprintf("Image rejected by scan result for image '%s'", [image])
}

deny_image[msg] {
        image_action_scan_result[[true,null]]
        scan_result_rejected
        msg := sprintf("Image rejected by namespace '%s' by scan result for image '%s'", [namespace, image])
}

deny_image[msg] {
        image_action_scan_result[[false,prefix]]
        prefix != null
        scan_result_rejected
        msg := sprintf("Image rejected by scan result by prefix '%s' for image '%s'", [prefix, image])
}

deny_image[msg] {
        image_action_scan_result[[true,prefix]]
        prefix != null
        scan_result_rejected
        msg := sprintf("Image rejected by namespace '%s' by prefix '%s' by scan result for image '%s'", [namespace, prefix, image])
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
