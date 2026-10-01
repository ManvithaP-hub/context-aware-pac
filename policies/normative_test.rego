package pac.normative_test

import rego.v1
import data.pac.normative

tags := {"owner": "a", "cost-center": "b"}

test_unencrypted_db if {
	vs := {v.policy | some v in normative.violations} with input as {"kind": "Database", "spec": {"encrypted": false}, "metadata": {"tags": tags}}
	vs == {"P1_encryption_at_rest"}
}

test_compliant_deployment if {
	count(normative.violations) == 0 with input as {"kind": "Deployment", "metadata": {"tags": tags}, "spec": {"exposure": "internal", "containers": [{"image": "registry.internal.example/app:1.2", "limits": {"cpu": "1"}, "privileged": false}]}}
}

test_privileged if {
	vs := {v.policy | some v in normative.violations} with input as {"kind": "Deployment", "metadata": {"tags": tags}, "spec": {"containers": [{"image": "registry.internal.example/app:1", "limits": {"cpu": "1"}, "privileged": true}]}}
	vs == {"P5_privileged"}
}

test_untrusted_registry_and_latest if {
	vs := {v.policy | some v in normative.violations} with input as {"kind": "Deployment", "metadata": {"tags": tags}, "spec": {"containers": [{"image": "docker.io/x/app:latest", "limits": {"cpu": "1"}}]}}
	vs == {"P3_image_registry", "P7_latest_tag"}
}

test_missing_tags_public_bucket if {
	vs := {v.policy | some v in normative.violations} with input as {"kind": "Bucket", "metadata": {"tags": {"owner": "a"}}, "spec": {"encrypted": true, "exposure": "public"}}
	vs == {"P2_public_exposure", "P6_required_tags"}
}
