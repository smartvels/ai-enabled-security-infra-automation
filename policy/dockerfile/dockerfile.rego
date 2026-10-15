# Container build policy: every Dockerfile in the repo must pass these rules.
package dockerfile

import rego.v1

from_images := [img |
	some i
	input[i].Cmd == "from"
	img := input[i].Value[0]
]

users := [u |
	some i
	input[i].Cmd == "user"
	u := input[i].Value[0]
]

deny contains "Image must switch to a non-root USER" if {
	count(users) == 0
}

deny contains msg if {
	count(users) > 0
	last := users[count(users) - 1]
	lower(last) in {"root", "0", "0:0", "root:root"}
	msg := sprintf("Final USER must not be root (found %q)", [last])
}

deny contains msg if {
	some img in from_images
	endswith(lower(img), ":latest")
	msg := sprintf("Base image %q uses the mutable 'latest' tag", [img])
}

deny contains msg if {
	some img in from_images
	not contains(img, ":")
	not contains(img, "@sha256:")
	lower(img) != "scratch"
	msg := sprintf("Base image %q has no tag or digest", [img])
}

deny contains "Use COPY instead of ADD (ADD can fetch remote URLs and unpack archives)" if {
	some i
	input[i].Cmd == "add"
}

deny contains "Image must define a HEALTHCHECK" if {
	not any_healthcheck
}

any_healthcheck if {
	some i
	input[i].Cmd == "healthcheck"
}

warn contains msg if {
	some img in from_images
	not contains(img, "@sha256:")
	lower(img) != "scratch"
	msg := sprintf("Base image %q is pinned by tag, not digest", [img])
}
