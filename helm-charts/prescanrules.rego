valid_policy_values = ["accept", "reject", "scan"]

##############################
# Decission policies

# Custom policies

#common?
default_first_matching_custom_policy(image) = [c |
        c := data.policies.customPolicies[_]
        startswith(image, c.prefix)
][0]

#common?
default_image_policy(image) = policy {
        not defined_in_namespace[[namespace, "customPolicies"]]
        policy :=  default_first_matching_custom_policy(image)
} {
        not defined_in_namespace[[namespace, "defaultPolicy"]]
        not default_first_matching_custom_policy(image)
        policy := {"prefix": null, "action": default_get("defaultPolicy")}
}

policy_action_or_empty(policy) = action {
        action := policy.action
} {
        not policy.action
        action := "<empty>"
}

#common?
default_image_policies[{"prefix": prefix, "image": image, "action": action}] {
        image := input.AdmissionRequest.object.spec.containers[_].image
        policy := default_image_policy(image)
        prefix := policy.prefix
        action := policy_action_or_empty(policy)
}

#common?
default_some_image_action_scan {
        default_image_policies[{"prefix": _, "image": _, "action": "scan"}]
}

#common?
default_some_image_action_allow {
        default_image_policies[{"prefix": _, "image": _, "action": "accept"}]
}

#common?
default_image_action_reject[[prefix, image]] {
        default_image_policies[{"prefix": prefix, "image": image, "action": "reject"}]
}

default_some_image_action_reject {
        default_image_action_reject[[_,_]]
}

#common?
config_error[msg] {
        policy := default_image_policies[{"prefix": _, "image": _, "action": _}]
        not policy.prefix == null
        not valid_policy_value[policy.action]
        msg := sprintf("Invalid value for customPolicy with prefix '%s' - '%s'", [policy.prefix, policy.action])
}


#common?
default_allow_pod {
        default_some_image_action_allow
        not default_some_image_action_scan
        not default_some_image_action_reject
}

#common?
default_deny_pod[msg] {
        default_image_action_reject[[null, image]]
        msg := sprintf("Pod rejected by default policy for image '%s'", [image])
}

default_deny_pod[msg] {
        prefix != null
        default_image_action_reject[[prefix, image]]
        msg := sprintf("Pod rejected by custom policy by prefix '%s' for image '%s'", [prefix, image])
}

# Per-namespace policies

ns_first_matching_custom_policy(image) = [c |
        c := data.policies.byNamespace[namespace].customPolicies[_]
        startswith(image, c.prefix)
][0]

ns_image_policy(image) = policy {
        defined_in_namespace[[namespace, "customPolicies"]]
        policy :=  ns_first_matching_custom_policy(image)
} {
        defined_in_namespace[[namespace, "defaultPolicy"]]
        not ns_first_matching_custom_policy(image)
        policy := {"prefix": null, "action": data.policies.byNamespace[namespace].defaultPolicy}
}

ns_image_policies[{"prefix": prefix, "image": image, "action": action}] {
        image := input.AdmissionRequest.object.spec.containers[_].image
        policy := ns_image_policy(image)
        prefix := policy.prefix
        action := policy_action_or_empty(policy)
}

#common?
ns_some_image_action_scan {
        ns_image_policies[{"prefix": _, "image": _, "action": "scan"}]
}

#common?
ns_some_image_action_allow {
        ns_image_policies[{"prefix": _, "image": _, "action": "accept"}]
}

#common?
ns_image_action_reject[[prefix, image]] {
        ns_image_policies[{"prefix": prefix, "image": image, "action": "reject"}]
}

ns_some_image_action_reject {
        ns_image_action_reject[[_,_]]
}

#common?
config_error[msg] {
        policy := ns_image_policies[{"prefix": _, "image": _, "action": _}]
        not policy.prefix == null
        not valid_policy_value[policy.action]
        msg := sprintf("Invalid value for namespace '%s' customPolicy with prefix '%s' - '%s'", [namespace, policy.prefix, policy.action])
}

ns_allow_pod {
        ns_some_image_action_allow
        not ns_some_image_action_scan
        not ns_some_image_action_reject
}

ns_deny_pod[msg] {
        ns_image_action_reject[[null, image]]
        msg := sprintf("Pod rejected by namespace '%s' default policy for image '%s'", [namespace, image])
}


ns_deny_pod[msg] {
        prefix != null
        ns_image_action_reject[[prefix, image]]
        msg := sprintf("Pod rejected by namespace '%s' custom policy by prefix '%s' for image '%s'", [namespace, prefix, image])
}


# Final decission


pre_allow_pod {
        not some_pre_deny_pod
        default_allow_pod
}

pre_allow_pod {
        not some_pre_deny_pod
        ns_allow_pod
}

some_pre_deny_pod {
        pre_deny_pod[_]
}

pre_deny_pod[msg] {
        config_error[msg]
}

pre_deny_pod[msg] {
        default_deny_pod[msg]
}

pre_deny_pod[msg] {
        ns_deny_pod[msg]
}
