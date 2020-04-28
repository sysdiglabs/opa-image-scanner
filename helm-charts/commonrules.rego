##############################
# Common helper functions

default_get(attr) = value {
        value := policies[attr]
}

ns_get(ns, attr) = value {
        value := default_get("byNamespace")[ns][attr]
}

##############################
# Common helper rules

defined_in_namespace[[ns, attr]] {
        default_get("byNamespace")
        default_get("byNamespace")[ns]
        default_get("byNamespace")[ns][attr]
}

valid_policy_value[value] {
        value = valid_policy_values[_]
}

invalid_default_policy[value] {
        value := default_get("defaultPolicy")
        not valid_policy_value[value]
}

invalid_default_policy["<empty>"] {
        not default_get("defaultPolicy")
}

invalid_ns_default_policy[[ns,value]] {
        defined_in_namespace[[ns, "defaultPolicy"]]
        value := ns_get(ns, "defaultPolicy")
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
        invalid_ns_default_policy[[namespace,value]]
        msg := sprintf("Invalid value for defaultPolicy for namespace '%s' - '%s'", [namespace, value])
}

