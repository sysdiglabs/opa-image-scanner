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

any_image_action_accept {
        final_image_policies[{"ns": _, "prefix": _, "image": _, "action": "accept"}]
}

any_image_action_reject {
        image_action_reject[[_,_,_]]
}

allow_pod {
        any_image_action_accept
        not any_image_action_scan
        not any_image_action_reject
        not some_deny_pod
}

some_deny_pod {
        deny_pod[_]
}

deny_pod[msg] {
        image_action_reject[[false, null, image]]
        msg := sprintf("Pod rejected by default policy for image '%s'", [image])
}

deny_pod[msg] {
        prefix != null
        image_action_reject[[false, prefix, image]]
        msg := sprintf("Pod rejected by custom policy by prefix '%s' for image '%s'", [prefix, image])
}

deny_pod[msg] {
        image_action_reject[[true, null, image]]
        msg := sprintf("Pod rejected by namespace '%s' default policy for image '%s'", [namespace, image])
}

deny_pod[msg] {
        prefix != null
        image_action_reject[[true, prefix, image]]
        msg := sprintf("Pod rejected by namespace '%s' custom policy by prefix '%s' for image '%s'", [namespace, prefix, image])
}

deny_pod[msg] {
        config_error[msg]
}
