##############################
# Pre-Scan rules
##############################

valid_policy_values = ["accept", "reject", "scan"]

policy_action_or_empty(policy) = action {
        action := policy.action
} {
        not policy.action
        action := "<empty>"
}

##############################
# Decission policies

first_matching_custom_policy(policies, image) = [c | 
        c := policies[_]
        startswith(image, c.prefix)
][0]


custom_image_policy(image) = policy {
        data.policies.byNamespace[namespace].customPolicies
        p := first_matching_custom_policy(data.policies.byNamespace[namespace].customPolicies, image)
        policy := {"ns": true, "prefix": p.prefix, "action": policy_action_or_empty(p)}
} {
        not data.policies.byNamespace[namespace].customPolicies
        data.policies.customPolicies
        p := first_matching_custom_policy(data.policies.customPolicies, image)
        policy := {"ns": false, "prefix": p.prefix, "action": policy_action_or_empty(p)}
}

def_image_policy(image) = policy {
        data.policies.byNamespace[namespace].defaultPolicy
        policy := {"ns": true, "prefix": null, "action": data.policies.byNamespace[namespace].defaultPolicy}
} {
        not data.policies.byNamespace[namespace].defaultPolicy
        data.policies.defaultPolicy
        policy := {"ns": false, "prefix": null, "action": data.policies.defaultPolicy}
}

final_image_policy(image) = policy {
        policy := custom_image_policy(image)
} {
        not custom_image_policy(image)
        policy :=  def_image_policy(image)
}

final_image_policies[{"ns": ns, "prefix": prefix, "image": image, "action": action}] {
        image := input.AdmissionRequest.object.spec.containers[_].image
        policy := final_image_policy(image)
        ns := policy.ns
        prefix := policy.prefix
        action := policy.action
}

any_image_action_scan {
        final_image_policies[{"ns": ns, "prefix": _, "image": _, "action": "scan"}]
}

any_image_action_accept {
        final_image_policies[{"ns": ns, "prefix": _, "image": _, "action": "accept"}]
}

image_action_reject[[ns, prefix, image]] {
        final_image_policies[{"ns": ns, "prefix": prefix, "image": image, "action": "reject"}]
}

any_image_action_reject {
        image_action_reject[[_,_,_]]
}

# Configuration errors

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

allow_pod {
        any_image_action_accept
        not any_image_action_scan
        not any_image_action_reject
        not some_deny_pod
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

some_deny_pod {
        deny_pod[_]
}

deny_pod[msg] {
        config_error[msg]
}
