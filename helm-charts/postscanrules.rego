##############################
# Post-Scan rules
##############################

valid_policy_values := ["accept", "reject", "scan-result"]

# Configuration errors

scan_result_final_value(policyKey) = value {
        value := policies.byNamespace[namespace][policyKey]
}  else = value {
        value := policies[policyKey]
} else = value {
        # Default value is reject if not specified
        value := "reject"
}

report_pending_action = value {
        value := scan_result_final_value("reportPending")
}

scan_failed_action = value {
        value := scan_result_final_value("scanFailed")
}

valid_scan_result_value[value] {
        value = ["accept", "reject"][_]
}

config_error["ScanReport is missing in input"] {
        not input.ScanReport
}

config_error[msg] {
        imagePolicy.action == "scan-result"
        not imagePolicy.ns
        not valid_scan_result_value[report_pending_action]
        msg :=  sprintf("Invalid value for reportPending - '%s'", [report_pending_action])
}

config_error[msg] {
        imagePolicy.action == "scan-result"
        imagePolicy.ns
        not valid_scan_result_value[report_pending_action]
        msg := sprintf("Invalid value for reportPending for namespace '%s' - '%s'", [namespace, report_pending_action])
}

config_error[msg] {
        imagePolicy.action == "scan-result"
        imagePolicy.ns == false
        not valid_scan_result_value[scan_failed_action]
        msg := sprintf("Invalid value for scanFailed - '%s'", [scan_failed_action])
}

config_error[msg] {
        imagePolicy.action == "scan-result"
        imagePolicy.ns == true
        not valid_scan_result_value[scan_failed_action]
        msg := sprintf("Invalid value for scanFailed for namespace '%s' - '%s'", [namespace, scan_failed_action])
}

config_error[msg] {
        imagePolicy.ns == false
        not imagePolicy.prefix == null
        not valid_policy_value[imagePolicy.action]
        msg := sprintf("Invalid value for customPolicy with prefix '%s' - '%s'", [imagePolicy.prefix, imagePolicy.action])
}

config_error[msg] {
        imagePolicy.ns == true
        not imagePolicy.prefix == null
        not valid_policy_value[imagePolicy.action]
        msg := sprintf("Invalid value for namespace '%s' customPolicy with prefix '%s' - '%s'", [namespace, imagePolicy.prefix, imagePolicy.action])
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

deny_image_reason[[ns, custom_policy_prefix, reason]] {
        image_action_scan_result[[ns,custom_policy_prefix]]
        scan_result_unexpected[value]
        reason := sprintf("unexpected ScanReport.Status value '%s'", [value])
}

deny_image_reason[[ns, custom_policy_prefix, "scan report is pending"]] {
        image_action_scan_result[[ns,custom_policy_prefix]]
        scan_result_not_available
        report_pending_action == "reject"
}

deny_image_reason[[ns, custom_policy_prefix, "scan failed"]] {
        image_action_scan_result[[ns,custom_policy_prefix]]
        scan_result_failed
        scan_failed_action == "reject"
}

deny_image_reason[[ns, custom_policy_prefix, "scan result is 'reject'"]] {
        image_action_scan_result[[ns,custom_policy_prefix]]
        scan_result_rejected
}

deny_image_reason[[ns, custom_policy_prefix, "policy action is 'reject'"]] {
        image_action_reject[[ns, custom_policy_prefix]]
}

deny_image[msg] {
        config_error[msg]
}

# Message is composed as "Image '<image>' REJECTED. <scope> - <reason>"
# <scope> is composed of "<namespace> <policy>"
# <namespace> is either:
# - Global
# - Namespace '<namespace>'
# <policy> is either:
# - default policy
# - custom policy (prefix '<prefix>')

deny_image[msg] {
        deny_image_reason[[ns, prefix, reason_msg]]
        msg :=  sprintf("Image '%s' REJECTED. %s - %s", [image, scope_str(ns, prefix), reason_msg])
}
