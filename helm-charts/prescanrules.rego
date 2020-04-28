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
        policy :=  default_first_matching_custom_policy(image)
} {
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
        not defined_in_namespace[[namespace, "defaultPolicy"]]
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
default_some_image_action_reject[[prefix, image]] {
        default_image_policies[{"prefix": prefix, "image": image, "action": "reject"}]
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
        default_some_image_action_reject[[null, image]]
        msg := sprintf("Pod rejected by default policy for image '%s'", [image])
}

default_deny_pod[msg] {
        prefix != null
        default_some_image_action_reject[[prefix, image]]
        msg := sprintf("Pod rejected by custom policy by prefix '%s' for image '%s'", [prefix, image])
}


# Per-namespace policies

ns_allow_pod {
        defined_in_namespace[[namespace, "defaultPolicy"]]
        ns_get(namespace, "defaultPolicy") == "accept"
}

ns_deny_pod["Pod rejected by namespace policy"] {
        defined_in_namespace[[namespace, "defaultPolicy"]]
        ns_get(namespace, "defaultPolicy") == "reject"
}

# Final decission


pre_allow_pod {
        not pre_deny_pod
        default_allow_pod
}

pre_allow_pod {
        not pre_deny_pod
        ns_allow_pod
}
 
pre_deny_pod[msg] {
        config_error[msg]
}

pre_deny_pod[msg] {
        default_deny_pod[msg]
}

pre_deny_pod[msg] {
        some ns_msg
        ns_deny_pod[ns_msg]
        msg := sprintf("Namespace '%s' policy - %s", [namespace, ns_msg])
}
