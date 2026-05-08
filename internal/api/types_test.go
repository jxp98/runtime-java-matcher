package api

import (
	"encoding/json"
	"testing"
)

func TestComponentInputUnmarshalRawInventoryDocument(t *testing.T) {
	payload := []byte(`{
	  "_inventory_id": "runtime-java:raw-1",
	  "_document_version": 7,
	  "_inventory_index": "wazuh-states-inventory-runtime-java-components",
	  "package": {
	    "name": "log4j-core",
	    "type": "jar",
	    "version": "2.14.1"
	  },
	  "file": {
	    "path": "/srv/app/lib/log4j-core-2.14.1.jar",
	    "hash": {
	      "sha1": "c5a52d75b03c4d197b35446d5cd0e7f85a8e986b"
	    }
	  },
	  "checksum": {
	    "hash": {
	      "sha1": "ignored-checksum-sha1"
	    }
	  },
	  "wazuh": {
	    "runtime_java": {
	      "group_id": "org.apache.logging.log4j",
	      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
	      "evidence_source": "pom.properties",
	      "confidence": "high",
	      "archive_path": "/srv/app/demo-app.jar",
	      "discovered_at": "2026-05-08T00:00:00Z"
	    }
	  }
	}`)

	var component ComponentInput
	if err := json.Unmarshal(payload, &component); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if component.InventoryID != "runtime-java:raw-1" {
		t.Fatalf("unexpected inventory id: %s", component.InventoryID)
	}
	if component.DocumentVersion != 7 {
		t.Fatalf("unexpected document version: %d", component.DocumentVersion)
	}
	if component.PackageType != "jar" {
		t.Fatalf("unexpected package type: %s", component.PackageType)
	}
	if component.GroupID != "org.apache.logging.log4j" {
		t.Fatalf("unexpected group id: %s", component.GroupID)
	}
	if component.ArtifactID != "log4j-core" {
		t.Fatalf("unexpected artifact id: %s", component.ArtifactID)
	}
	if component.Version != "2.14.1" {
		t.Fatalf("unexpected version: %s", component.Version)
	}
	if component.RuntimePath != "/srv/app/lib/log4j-core-2.14.1.jar" {
		t.Fatalf("unexpected runtime path: %s", component.RuntimePath)
	}
	if component.ArchivePath != "/srv/app/demo-app.jar" {
		t.Fatalf("unexpected archive path: %s", component.ArchivePath)
	}
	if component.SHA1 != "c5a52d75b03c4d197b35446d5cd0e7f85a8e986b" {
		t.Fatalf("unexpected sha1: %s", component.SHA1)
	}
}
