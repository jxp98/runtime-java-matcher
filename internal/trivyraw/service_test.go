package trivyraw

import (
	"errors"
	"strings"
	"testing"

	javaTypes "github.com/aquasecurity/trivy-java-db/pkg/types"

	"runtime-java-matcher/internal/api"
)

type fakeJavaDB struct {
	bySHA1     map[string]javaTypes.Index
	byArtifact map[string][]javaTypes.Index
}

func (f *fakeJavaDB) Close() error {
	return nil
}

func (f *fakeJavaDB) SelectIndexBySha1(sha1 string) (javaTypes.Index, error) {
	if f == nil {
		return javaTypes.Index{}, errors.New("nil db")
	}
	key := strings.ToLower(strings.TrimSpace(sha1))
	index, ok := f.bySHA1[key]
	if !ok {
		return javaTypes.Index{}, errors.New("not found")
	}
	return index, nil
}

func (f *fakeJavaDB) SelectIndexesByArtifactIDAndFileType(artifactID string, version string, fileType javaTypes.ArchiveType) ([]javaTypes.Index, error) {
	if f == nil {
		return nil, errors.New("nil db")
	}
	key := strings.TrimSpace(artifactID) + "@" + strings.TrimSpace(version) + "#" + string(fileType)
	indexes, ok := f.byArtifact[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return indexes, nil
}

func TestResolveComponentRejectsUnverifiedExplicitCoordinates(t *testing.T) {
	service := &Service{javaDB: &fakeJavaDB{}}
	component := normalizeComponent(api.ComponentInput{
		GroupID:        "org.example",
		ArtifactID:     "Fancy Display Name",
		Version:        "1.0.0",
		EvidenceSource: "manifest",
		Confidence:     "low",
	})

	resolved, confidence, source, ok := service.resolveComponent(component, buildArtifactCandidates(component))
	if ok {
		t.Fatalf("expected unresolved component, got ok=true with %#v", resolved)
	}
	if confidence != "low" {
		t.Fatalf("unexpected confidence: %q", confidence)
	}
	if source != "group_artifact_unverified" {
		t.Fatalf("unexpected source: %q", source)
	}
	if resolved.ArtifactID != "Fancy Display Name" {
		t.Fatalf("unexpected artifact id: %q", resolved.ArtifactID)
	}
}

func TestResolveComponentAcceptsVerifiedPURLCoordinates(t *testing.T) {
	service := &Service{javaDB: &fakeJavaDB{
		byArtifact: map[string][]javaTypes.Index{
			"tomcat-catalina@8.5.82#jar": {
				{GroupID: "org.apache.tomcat", ArtifactID: "tomcat-catalina", Version: "8.5.82"},
			},
		},
	}}
	component := normalizeComponent(api.ComponentInput{
		PURL: "pkg:maven/org.apache.tomcat/tomcat-catalina@8.5.82",
	})

	resolved, confidence, source, ok := service.resolveComponent(component, buildArtifactCandidates(component))
	if !ok {
		t.Fatal("expected purl coordinates to be verified")
	}
	if confidence != "high" {
		t.Fatalf("unexpected confidence: %q", confidence)
	}
	if source != "purl_verified" {
		t.Fatalf("unexpected source: %q", source)
	}
	if resolved.GroupID != "org.apache.tomcat" || resolved.ArtifactID != "tomcat-catalina" || resolved.Version != "8.5.82" {
		t.Fatalf("unexpected resolved component: %#v", resolved)
	}
}

func TestResolveComponentCanonicalizesManifestCandidateAgainstJavaDB(t *testing.T) {
	service := &Service{javaDB: &fakeJavaDB{
		byArtifact: map[string][]javaTypes.Index{
			"tomcat-catalina@8.5.82#jar": {
				{GroupID: "org.apache.tomcat", ArtifactID: "tomcat-catalina", Version: "8.5.82"},
			},
		},
	}}
	component := normalizeComponent(api.ComponentInput{
		GroupID:        "org.apache.tomcat",
		PackageName:    "Apache Tomcat",
		Version:        "8.5.82",
		RuntimePath:    "/opt/apache-tomcat-8.5.82/lib/catalina.jar",
		EvidenceSource: "manifest",
		Confidence:     "medium",
	})

	resolved, confidence, source, ok := service.resolveComponent(component, buildArtifactCandidates(component))
	if !ok {
		t.Fatal("expected manifest candidate to be canonicalized")
	}
	if confidence != "high" {
		t.Fatalf("unexpected confidence: %q", confidence)
	}
	if source != "group_artifact_candidate" {
		t.Fatalf("unexpected source: %q", source)
	}
	if resolved.ArtifactID != "tomcat-catalina" {
		t.Fatalf("unexpected artifact id: %q", resolved.ArtifactID)
	}
	if resolved.PURL != "pkg:maven/org.apache.tomcat/tomcat-catalina@8.5.82" {
		t.Fatalf("unexpected purl: %q", resolved.PURL)
	}
}

func TestResolveComponentCanonicalizesAfterGroupLookup(t *testing.T) {
	service := &Service{javaDB: &fakeJavaDB{
		byArtifact: map[string][]javaTypes.Index{
			"catalina@8.5.82#jar": {
				{GroupID: "org.apache.tomcat", ArtifactID: "catalina", Version: "8.5.82"},
			},
			"tomcat-catalina@8.5.82#jar": {
				{GroupID: "org.apache.tomcat", ArtifactID: "tomcat-catalina", Version: "8.5.82"},
			},
		},
	}}
	component := normalizeComponent(api.ComponentInput{
		PackageName:    "Apache Tomcat",
		Version:        "8.5.82",
		RuntimePath:    "/opt/apache-tomcat-8.5.82/lib/catalina.jar",
		EvidenceSource: "manifest",
		Confidence:     "medium",
	})

	resolved, confidence, source, ok := service.resolveComponent(component, buildArtifactCandidates(component))
	if !ok {
		t.Fatal("expected component to resolve after group lookup")
	}
	if confidence != "medium" {
		t.Fatalf("unexpected confidence: %q", confidence)
	}
	if source != "artifact_version_lookup_canonical" {
		t.Fatalf("unexpected source: %q", source)
	}
	if resolved.GroupID != "org.apache.tomcat" {
		t.Fatalf("unexpected group id: %q", resolved.GroupID)
	}
	if resolved.ArtifactID != "tomcat-catalina" {
		t.Fatalf("unexpected artifact id: %q", resolved.ArtifactID)
	}
	if resolved.PURL != "pkg:maven/org.apache.tomcat/tomcat-catalina@8.5.82" {
		t.Fatalf("unexpected purl: %q", resolved.PURL)
	}
}

func TestResolveComponentSHA1OverridesWeakFilenameArtifact(t *testing.T) {
	service := &Service{javaDB: &fakeJavaDB{
		bySHA1: map[string]javaTypes.Index{
			"fb5dbc35dcef6abd9e619b9a6bd56de10b2d7e86": {
				GroupID:    "org.apache.tomcat",
				ArtifactID: "tomcat-catalina",
				Version:    "8.5.82",
			},
		},
	}}
	component := normalizeComponent(api.ComponentInput{
		Version:        "8.5.82",
		RuntimePath:    "/opt/apache-tomcat-8.5.82/lib/catalina.jar",
		EvidenceSource: "manifest+filename",
		Confidence:     "medium",
		SHA1:           "fb5dbc35dcef6abd9e619b9a6bd56de10b2d7e86",
	})

	if component.ArtifactID != "catalina" {
		t.Fatalf("expected weak filename artifact before sha1 override, got %q", component.ArtifactID)
	}

	resolved, confidence, source, ok := service.resolveComponent(component, buildArtifactCandidates(component))
	if !ok {
		t.Fatal("expected component to resolve by sha1")
	}
	if confidence != "high" {
		t.Fatalf("unexpected confidence: %q", confidence)
	}
	if source != "sha1" {
		t.Fatalf("unexpected source: %q", source)
	}
	if resolved.GroupID != "org.apache.tomcat" {
		t.Fatalf("unexpected group id: %q", resolved.GroupID)
	}
	if resolved.ArtifactID != "tomcat-catalina" {
		t.Fatalf("unexpected artifact id: %q", resolved.ArtifactID)
	}
	if resolved.PURL != "pkg:maven/org.apache.tomcat/tomcat-catalina@8.5.82" {
		t.Fatalf("unexpected purl: %q", resolved.PURL)
	}
}
