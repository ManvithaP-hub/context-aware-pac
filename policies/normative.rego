# Normative policy set: context-free, deterministic. One rule per control,
# identical in every environment. Context and risk are NOT evaluated here.
package pac.normative

import rego.v1

allowed_registries := {"registry.internal.example"}

violations contains v if {
	input.kind in {"Database", "Bucket", "Volume"}
	not input.spec.encrypted
	v := {"policy": "P1_encryption_at_rest", "severity": "high"}
}

violations contains v if {
	input.spec.exposure == "public"
	v := {"policy": "P2_public_exposure", "severity": "high"}
}

violations contains v if {
	input.kind == "Deployment"
	some c in input.spec.containers
	registry := split(c.image, "/")[0]
	not registry in allowed_registries
	v := {"policy": "P3_image_registry", "severity": "medium"}
}

violations contains v if {
	input.kind == "Deployment"
	some c in input.spec.containers
	not c.limits
	v := {"policy": "P4_resource_limits", "severity": "low"}
}

violations contains v if {
	input.kind == "Deployment"
	some c in input.spec.containers
	c.privileged == true
	v := {"policy": "P5_privileged", "severity": "high"}
}

violations contains v if {
	required := {"owner", "cost-center"}
	missing := required - {k | some k, _ in input.metadata.tags}
	count(missing) > 0
	v := {"policy": "P6_required_tags", "severity": "low"}
}

violations contains v if {
	input.kind == "Deployment"
	some c in input.spec.containers
	endswith(c.image, ":latest")
	v := {"policy": "P7_latest_tag", "severity": "medium"}
}
