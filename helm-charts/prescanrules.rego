##############################
# Pre-Scan rules
##############################

valid_policy_values := ["accept", "reject", "scan"]

# Configuration errros

config_error[msg] {
        policy := final_image_policies[{"ns": false, "prefix": _, "image": _, "action": _}]
        not policy.prefix == null
        not valid_policy_value[policy.action]
        msg := sprintf("Invalid value for customPolicy with prefix '%s' - '%s'", [policy.prefix, policy.action])
}

config_error[msg] {
        policy := final_image_policies[{"ns": true, "prefix": _, "image": _, "action": _}]
        not policy.prefix == null
        not valid_policy_value[policy.action]
        msg := sprintf("Invalid value for namespace '%s' customPolicy with prefix '%s' - '%s'", [namespace, policy.prefix, policy.action])
}

# Final decision

final_image_policies[{"ns": ns, "prefix": prefix, "image": image, "action": action}] {
        image := input.AdmissionRequest.object.spec.containers[_].image
        policy := final_image_policy(image)
        ns := policy.ns
        prefix := policy.prefix
        action := policy.action
}

image_action_reject[[ns, prefix, image]] {
        final_image_policies[{"ns": ns, "prefix": prefix, "image": image, "action": "reject"}]
}

any_image_action_scan {
        final_image_policies[{"ns": _, "prefix": _, "image": _, "action": "scan"}]
}

no_denied_pod {
        deny_reasons := { reason | deny_pod[reason] }
        count(deny_reasons) == 0
}

allow_pod {
        not any_image_action_scan
        no_denied_pod
}

deny_pod[msg] {
        config_error[msg]
}

deny_pod[msg] {
        image_action_reject[[ns, prefix, image]]
        msg :=  sprintf("Image '%s' REJECTED. %s", [image, scope_str(ns, prefix)])
}
