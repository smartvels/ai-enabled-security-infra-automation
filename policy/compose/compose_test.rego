package compose

import rego.v1

hardened := {"services": {"svc": {
	"read_only": true,
	"cap_drop": ["ALL"],
	"security_opt": ["no-new-privileges:true"],
	"ports": ["127.0.0.1:5050:5050"],
	"mem_limit": "256m",
}}}

with_change(change) := {"services": {"svc": object.union(hardened.services.svc, change)}}

test_hardened_service_passes if {
	count(deny) == 0 with input as hardened
}

test_writable_root_is_denied if {
	count(deny) > 0 with input as with_change({"read_only": false})
}

test_capabilities_kept_is_denied if {
	count(deny) > 0 with input as with_change({"cap_drop": []})
}

test_privileged_is_denied if {
	count(deny) > 0 with input as with_change({"privileged": true})
}

test_host_network_is_denied if {
	count(deny) > 0 with input as with_change({"network_mode": "host"})
}

test_public_port_is_denied if {
	count(deny) > 0 with input as with_change({"ports": ["5050:5050"]})
}

test_docker_socket_is_denied if {
	count(deny) > 0 with input as with_change({"volumes": ["/var/run/docker.sock:/var/run/docker.sock"]})
}
