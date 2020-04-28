package common

mock_input_for_ns(ns) = value {
    value := {
        "AdmissionRequest": {
            "namespace": ns,
            "object": {
                "metadata": {
                    "namespace": ns
                },
                "spec": {
                    "containers": [
                        {
                        "image": "docker.io/myrepo/myimage"
                        }
                    ]
                }
            }
        }
    }   
}