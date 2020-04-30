##############################
# Common rules
##############################

##############################
# Common helper functions

global_get(attr) = value {
        value := policies[attr]
}

ns_get(attr) = value {
        value := global_get("byNamespace")[namespace][attr]
}

policy_action_or_empty(policy) = action {
        action := policy.action
} else = action {
        action := "<empty>"
}

##############################
# Common helper rules

defined_in_namespace[attr] {
        global_get("byNamespace")
        global_get("byNamespace")[namespace]
        global_get("byNamespace")[namespace][attr]
}

valid_policy_value[value] {
        value = valid_policy_values[_]
}

invalid_default_policy[value] {
        value := global_get("defaultPolicy")
        not valid_policy_value[value]
}

invalid_default_policy["<empty>"] {
        not global_get("defaultPolicy")
}

invalid_ns_default_policy[value] {
        defined_in_namespace["defaultPolicy"]
        value := ns_get("defaultPolicy")
        not valid_policy_value[value]
}

# Configuration errors

config_error["AdmissionRequest is missing in input"] {
        not input.AdmissionRequest
}

config_error[msg] {
        invalid_default_policy[value]
        msg = sprintf("Invalid value for defaultPolicy - '%s'", [value])
}

config_error[msg] {
        some value
        invalid_ns_default_policy[value]
        msg := sprintf("Invalid value for defaultPolicy for namespace '%s' - '%s'", [namespace, value])
}

# Per-Image policy computation

first_matching_custom_policy(policies, image) = [c | 
        c := policies[_]
        startswith(image, c.prefix)
][0]

custom_image_policy(image) = policy {
        p := first_matching_custom_policy(data.policies.byNamespace[namespace].customPolicies, image)
        policy := {"ns": true, "prefix": p.prefix, "action": policy_action_or_empty(p)}
} else = policy {
        not data.policies.byNamespace[namespace].customPolicies
        p := first_matching_custom_policy(data.policies.customPolicies, image)
        policy := {"ns": false, "prefix": p.prefix, "action": policy_action_or_empty(p)}
}

def_image_policy(image) = policy {
        policy := {"ns": true, "prefix": null, "action": data.policies.byNamespace[namespace].defaultPolicy}
} else = policy {
        policy := {"ns": false, "prefix": null, "action": data.policies.defaultPolicy}
}

final_image_policy(image) = policy {
        policy := custom_image_policy(image)
} else = policy {
        policy :=  def_image_policy(image)
}
