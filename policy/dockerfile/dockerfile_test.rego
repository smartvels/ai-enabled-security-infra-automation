package dockerfile

import rego.v1

good := [
	{"Cmd": "from", "Value": ["python:3.12-slim"]},
	{"Cmd": "copy", "Value": ["app.py", "."]},
	{"Cmd": "user", "Value": ["app"]},
	{"Cmd": "healthcheck", "Value": ["CMD", "true"]},
]

test_hardened_dockerfile_passes if {
	count(deny) == 0 with input as good
}

test_missing_user_is_denied if {
	"Image must switch to a non-root USER" in deny with input as [
		{"Cmd": "from", "Value": ["python:3.12-slim"]},
		{"Cmd": "healthcheck", "Value": ["CMD", "true"]},
	]
}

test_root_user_is_denied if {
	count(deny) > 0 with input as array.concat(good, [{"Cmd": "user", "Value": ["root"]}])
}

test_latest_tag_is_denied if {
	count(deny) > 0 with input as array.concat([{"Cmd": "from", "Value": ["python:latest"]}], array.slice(good, 1, 4))
}

test_untagged_image_is_denied if {
	count(deny) > 0 with input as array.concat([{"Cmd": "from", "Value": ["python"]}], array.slice(good, 1, 4))
}

test_add_is_denied if {
	count(deny) > 0 with input as array.concat(good, [{"Cmd": "add", "Value": ["https://x/y.tgz", "/"]}])
}

test_digest_pinned_image_has_no_warning if {
	count(warn) == 0 with input as array.concat([{"Cmd": "from", "Value": ["python:3.12-slim@sha256:abc"]}], array.slice(good, 1, 4))
}
