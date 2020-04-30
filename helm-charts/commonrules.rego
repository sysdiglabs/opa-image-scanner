##############################
# Common rules
##############################

##############################
# helper functions

policy_action_or_empty(policy) = action {
        action := policy.action
} else = action {
        action := "<empty>"
}

namespace_str(ns) = str{ 
        ns == true
        str := sprintf("Namespace '%s'", [namespace])
} else = str {
        str := "Global"
}

policy_str(prefix) = str {
        prefix == null
        str := "default policy"
} else = str {
        str := sprintf("custom policy (prefix '%s')", [prefix])
}

scope_str(ns, prefix) = str {
        str := sprintf("%s %s", [namespace_str(ns), policy_str(prefix)])
}

##############################
# helper rules

valid_policy_value[value] {
        value = valid_policy_values[_]
}

##############################
# common configuration errors

config_error["AdmissionRequest is missing in input"] {
        not input.AdmissionRequest
}

invalid_default_policy[value] {
        value := policies.defaultPolicy
        not valid_policy_value[value]
}

invalid_default_policy["<empty>"] {
        not policies.defaultPolicy
}

config_error[msg] {
        invalid_default_policy[value]
        msg = sprintf("Invalid value for defaultPolicy - '%s'", [value])
}

config_error[msg] {
        value := policies.byNamespace[namespace].defaultPolicy
        not valid_policy_value[value]
        msg := sprintf("Invalid value for defaultPolicy for namespace '%s' - '%s'", [namespace, value])
}

# Per-Image policy computation

first_matching_custom_policy(policies, image) = [c | 
        c := policies[_]
        startswith(image, c.prefix)
][0]

custom_image_policy(image) = policy {
        p := first_matching_custom_policy(policies.byNamespace[namespace].customPolicies, image)
        policy := {"ns": true, "prefix": p.prefix, "action": policy_action_or_empty(p)}
} else = policy {
        not policies.byNamespace[namespace].customPolicies
        p := first_matching_custom_policy(policies.customPolicies, image)
        policy := {"ns": false, "prefix": p.prefix, "action": policy_action_or_empty(p)}
}

default_image_policy(image) = policy {
        policy := {"ns": true, "prefix": null, "action": policies.byNamespace[namespace].defaultPolicy}
} else = policy {
        policy := {"ns": false, "prefix": null, "action": policies.defaultPolicy}
}

final_image_policy(image) = policy {
        policy := custom_image_policy(image)
} else = policy {
        policy :=  default_image_policy(image)
}
