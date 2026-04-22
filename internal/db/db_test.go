package db

import "testing"

func TestLoadBundleDirectory(t *testing.T) {
	index, err := Load("../../testdata/formal-db")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	metadata := index.Metadata()
	if metadata.Format != "runtime-java-bundle" {
		t.Fatalf("expected format runtime-java-bundle, got %s", metadata.Format)
	}
	if metadata.Source != "trivy-java-export" {
		t.Fatalf("expected source trivy-java-export, got %s", metadata.Source)
	}
	if index.Size() != 3 {
		t.Fatalf("expected 3 package records, got %d", index.Size())
	}
	if len(index.FindByGA("org.apache.logging.log4j", "log4j-core")) != 1 {
		t.Fatalf("expected one log4j-core record")
	}
}
