package noise

import "testing"

func TestAssessBootstrapAsConservativeSuppressionCandidate(t *testing.T) {
	isDirectRuntimeTarget := false
	assessment := Assess(
		"identity_unresolved",
		"bootstrap",
		"/opt/apache-tomcat-8.5.82/bin/bootstrap.jar",
		"classpath",
		"filename",
		&isDirectRuntimeTarget,
		nil,
	)
	if !assessment.SuppressionCandidate {
		t.Fatal("expected bootstrap unresolved launcher to be marked as suppression candidate")
	}
	if assessment.SuppressionReason != "launcher_bin_archive_identity_unresolved" {
		t.Fatalf("unexpected suppression reason: %s", assessment.SuppressionReason)
	}
}

func TestAssessTomcatJuliDoesNotSuggestSuppression(t *testing.T) {
	isDirectRuntimeTarget := false
	assessment := Assess(
		"version_not_affected",
		"tomcat-juli",
		"/opt/apache-tomcat-8.5.82/bin/tomcat-juli.jar",
		"fd",
		"filename",
		&isDirectRuntimeTarget,
		nil,
	)
	if assessment.SuppressionCandidate {
		t.Fatal("did not expect tomcat-juli to be marked as suppression candidate")
	}
}
