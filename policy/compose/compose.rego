# Runtime policy: every service in a docker-compose file must be hardened.
package compose

import rego.v1

services := object.get(input, "services", {})

deny contains msg if {
	some name, svc in services
	not object.get(svc, "read_only", false)
	msg := sprintf("Service %q must use a read-only root filesystem (read_only: true)", [name])
}

deny contains msg if {
	some name, svc in services
	not "ALL" in object.get(svc, "cap_drop", [])
	msg := sprintf("Service %q must drop all Linux capabilities (cap_drop: [ALL])", [name])
}

deny contains msg if {
	some name, svc in services
	not "no-new-privileges:true" in object.get(svc, "security_opt", [])
	msg := sprintf("Service %q must set security_opt no-new-privileges:true", [name])
}

deny contains msg if {
	some name, svc in services
	object.get(svc, "privileged", false)
	msg := sprintf("Service %q must not run privileged", [name])
}

deny contains msg if {
	some name, svc in services
	object.get(svc, "network_mode", "") == "host"
	msg := sprintf("Service %q must not use the host network", [name])
}

deny contains msg if {
	some name, svc in services
	some port in object.get(svc, "ports", [])
	not startswith(sprintf("%v", [port]), "127.0.0.1:")
	msg := sprintf("Service %q publishes %v beyond localhost; bind to 127.0.0.1 and use a reverse proxy", [name, port])
}

deny contains msg if {
	some name, svc in services
	some vol in object.get(svc, "volumes", [])
	contains(sprintf("%v", [vol]), "docker.sock")
	msg := sprintf("Service %q must not mount the Docker socket (host takeover risk)", [name])
}

deny contains msg if {
	some name, svc in services
	not object.get(svc, "mem_limit", false)
	msg := sprintf("Service %q must set a memory limit (mem_limit)", [name])
}
