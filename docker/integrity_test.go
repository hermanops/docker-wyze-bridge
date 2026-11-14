package docker_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDownloadChecksumVerification(t *testing.T) {
	requireTools(t, "sh", "sha256sum")
	dir := t.TempDir()
	path := filepath.Join(dir, "download")
	data := []byte("verified download")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	check := func(digest string) error {
		return exec.Command("sh", "verify-sha256.sh", path, digest).Run()
	}
	if err := check(hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("valid checksum rejected: %v", err)
	}
	if err := check(strings.Repeat("0", 64)); err == nil {
		t.Fatal("invalid checksum accepted")
	}
	if err := os.WriteFile(path, []byte("tampered download"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := check(hex.EncodeToString(sum[:])); err == nil {
		t.Fatal("modified download accepted")
	}
}

func requireTools(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s is required for workflow integrity tests", name)
		}
	}
}

func workflowStep(t *testing.T, path, job, name string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	for _, step := range workflow.Jobs[job].Steps {
		if step.Name == name && step.Run != "" {
			return step.Run
		}
	}
	t.Fatalf("step %q not found in %s", name, path)
	return ""
}

func runStep(script string, env ...string) error {
	cmd := exec.Command("bash", "-e", "-o", "pipefail", "-c", script)
	cmd.Env = append(os.Environ(), env...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, output)
	}
	return nil
}

func writeOCIArchive(t *testing.T, path, arch string, corrupt bool) string {
	t.Helper()
	manifest := []byte(`{"schemaVersion":2}`)
	sum := sha256.Sum256(manifest)
	digest := hex.EncodeToString(sum[:])
	index, err := json.Marshal(map[string]any{
		"schemaVersion": 2,
		"manifests": []any{map[string]any{
			"digest": "sha256:" + digest,
			"platform": map[string]string{
				"os": "linux", "architecture": arch,
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if corrupt {
		manifest = []byte("corrupted")
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	for name, data := range map[string][]byte{
		"index.json":             index,
		"blobs/sha256/" + digest: manifest,
	} {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return "sha256:" + digest
}

func writeTrivyStub(t *testing.T, dir string) {
	t.Helper()
	trivy := `#!/bin/sh
set -eu
args="$*"
inputs=0
output=
while [ "$#" -gt 0 ]; do
	case "$1" in
		--input)
			[ "$#" -ge 2 ] && [ "$2" = "oci" ] && [ -d "$2" ] && [ -f "$2/index.json" ] || exit 1
			inputs=$((inputs + 1))
			shift 2 ;;
		--output)
			[ "$#" -ge 2 ] || exit 1
			output=$2
			shift 2 ;;
		*) shift ;;
	esac
done
[ "$inputs" -eq 1 ] || exit 1
printf '%s\n' "$args" >> "$TRIVY_CALLS"
if [ -n "$output" ]; then
	case "$TEST_SBOM" in
		missing) ;;
		empty) : > "$output" ;;
		invalid) printf '%s\n' '{"bomFormat":"wrong"}' > "$output" ;;
		malformed) printf '%s\n' '{' > "$output" ;;
		invalid-schema) printf '%s\n' '{"bomFormat":"CycloneDX"}' > "$output" ;;
		generation-error) exit 1 ;;
		*) printf '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"container","name":"%s"}}}\n' "$ARCH" > "$output" ;;
	esac
elif [ "$TEST_SBOM" = changed-after-generation ]; then
	printf '%s\n' '{"bomFormat":"CycloneDX","changed":true}' > "sbom-$ARCH.cdx.json"
elif [ "$TEST_SBOM" = critical ]; then
	exit 1
fi
`
	if err := os.WriteFile(filepath.Join(dir, "trivy"), []byte(trivy), 0700); err != nil {
		t.Fatal(err)
	}
	validator := `#!/bin/sh
set -eu
[ "$*" = "validate --input-file sbom-$ARCH.cdx.json --input-format json --input-version v1_6 --fail-on-errors" ]
jq -e '.bomFormat == "CycloneDX" and .specVersion == "1.6" and .version == 1' "sbom-$ARCH.cdx.json" >/dev/null
`
	if err := os.WriteFile(filepath.Join(dir, "cyclonedx"), []byte(validator), 0700); err != nil {
		t.Fatal(err)
	}
}

func TestScannedArtifactConsistency(t *testing.T) {
	requireTools(t, "bash", "jq", "tar", "sha256sum")
	scan := workflowStep(t, "../.github/workflows/build-candidate.yml", "build", "Generate SBOM and scan candidate")
	verify := workflowStep(t, "../.github/workflows/publish.yml", "publish", "Verify scanned artifacts")

	for _, corrupt := range []bool{false, true} {
		t.Run(fmt.Sprintf("corrupt-manifest-%t", corrupt), func(t *testing.T) {
			dir := t.TempDir()
			manifest := writeOCIArchive(t, filepath.Join(dir, "image.tar"), "amd64", corrupt)
			writeTrivyStub(t, dir)
			output := filepath.Join(dir, "output")
			if err := os.WriteFile(output, nil, 0600); err != nil {
				t.Fatal(err)
			}
			calls := filepath.Join(dir, "trivy-calls")
			err := runStep(scan, "RUNNER_TEMP="+dir, "GITHUB_OUTPUT="+output, "ARCH=amd64", "TRIVY_CALLS="+calls, "TEST_SBOM=valid")
			if corrupt {
				if err == nil {
					t.Fatal("corrupt OCI manifest accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			invocations, err := os.ReadFile(calls)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Count(invocations, []byte("\n")) != 2 ||
				!bytes.Contains(invocations, []byte("--format cyclonedx")) ||
				!bytes.Contains(invocations, []byte("--scanners vuln --severity CRITICAL --exit-code 1 --ignorefile /dev/null")) {
				t.Fatalf("expected SBOM and vulnerability scans of the OCI layout, got: %s", invocations)
			}
			results, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(results, []byte("manifest_digest="+manifest+"\n")) {
				t.Fatalf("unexpected scan output: %s", results)
			}
			archive, err := os.ReadFile(filepath.Join(dir, "image.tar"))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(archive)
			hash := hex.EncodeToString(sum[:])
			if !bytes.Contains(results, []byte("archive_sha256="+hash+"\n")) {
				t.Fatalf("missing archive digest: %s", results)
			}
			sbom, err := os.ReadFile(filepath.Join(dir, "sbom-amd64.cdx.json"))
			if err != nil {
				t.Fatal(err)
			}
			sbomSum := sha256.Sum256(sbom)
			sbomHash := hex.EncodeToString(sbomSum[:])
			if !bytes.Contains(results, []byte("sbom_sha256="+sbomHash+"\n")) {
				t.Fatalf("missing SBOM digest: %s", results)
			}
			for _, arch := range []string{"amd64", "arm64"} {
				target := filepath.Join(dir, "candidates", "candidate-"+arch)
				if err := os.MkdirAll(target, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(target, "image.tar"), archive, 0600); err != nil {
					t.Fatal(err)
				}
				target = filepath.Join(dir, "sboms", arch)
				if err := os.MkdirAll(target, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(target, "sbom-"+arch+".cdx.json"), sbom, 0600); err != nil {
					t.Fatal(err)
				}
			}

			env := []string{"RUNNER_TEMP=" + dir, "AMD64_ARCHIVE=" + hash, "ARM64_ARCHIVE=" + hash,
				"AMD64_SBOM=" + sbomHash, "ARM64_SBOM=" + sbomHash}
			if err := runStep(verify, env...); err != nil {
				t.Fatalf("valid candidate rejected: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "candidates", "candidate-arm64", "image.tar"), []byte("tampered"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := runStep(verify, env...); err == nil {
				t.Fatal("modified candidate accepted")
			}
		})
	}
}

func TestSBOMGeneration(t *testing.T) {
	requireTools(t, "bash", "jq", "tar", "sha256sum")
	scan := workflowStep(t, "../.github/workflows/build-candidate.yml", "build", "Generate SBOM and scan candidate")
	for _, arch := range []string{"amd64", "arm64"} {
		for _, scenario := range []string{"valid", "missing", "empty", "invalid", "invalid-schema", "malformed", "generation-error", "changed-after-generation", "critical"} {
			t.Run(arch+"/"+scenario, func(t *testing.T) {
				dir := t.TempDir()
				writeOCIArchive(t, filepath.Join(dir, "image.tar"), arch, false)
				writeTrivyStub(t, dir)
				output := filepath.Join(dir, "output")
				err := runStep(scan, "RUNNER_TEMP="+dir, "GITHUB_OUTPUT="+output, "ARCH="+arch,
					"TRIVY_CALLS="+filepath.Join(dir, "calls"), "TEST_SBOM="+scenario)
				if (err == nil) != (scenario == "valid") {
					t.Fatalf("scan success = %t for %s: %v", err == nil, scenario, err)
				}
				if err != nil {
					if data, readErr := os.ReadFile(output); readErr == nil && bytes.Contains(data, []byte("sbom_sha256=")) {
						t.Fatalf("failed scan produced an SBOM output: %s", data)
					}
				}
			})
		}
	}
}

func TestSBOMPublicationVerification(t *testing.T) {
	requireTools(t, "bash", "sha256sum")
	for _, workflow := range []string{"publish.yml", "publish-candidate.yml"} {
		t.Run(workflow, func(t *testing.T) {
			verify := workflowStep(t, "../.github/workflows/"+workflow, "publish", "Verify scanned artifacts")
			for _, scenario := range []string{"valid", "missing-amd64", "missing-arm64", "empty-amd64", "empty-arm64",
				"tampered-amd64", "tampered-arm64", "swapped", "missing-digest-amd64", "missing-digest-arm64",
				"wrong-digest-amd64", "wrong-digest-arm64"} {
				t.Run(scenario, func(t *testing.T) {
					dir := t.TempDir()
					archive := []byte("scanned candidate")
					archiveSum := sha256.Sum256(archive)
					hash := hex.EncodeToString(archiveSum[:])
					sboms := map[string][]byte{
						"amd64": []byte(`{"bomFormat":"CycloneDX","arch":"amd64"}`),
						"arm64": []byte(`{"bomFormat":"CycloneDX","arch":"arm64"}`),
					}
					sbomHashes := make(map[string]string)
					for _, arch := range []string{"amd64", "arm64"} {
						target := filepath.Join(dir, "candidates", "candidate-"+arch)
						if err := os.MkdirAll(target, 0700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(filepath.Join(target, "image.tar"), archive, 0600); err != nil {
							t.Fatal(err)
						}
						target = filepath.Join(dir, "sboms", arch)
						if err := os.MkdirAll(target, 0700); err != nil {
							t.Fatal(err)
						}
						sum := sha256.Sum256(sboms[arch])
						sbomHashes[arch] = hex.EncodeToString(sum[:])
						data := sboms[arch]
						switch scenario {
						case "missing-" + arch:
							continue
						case "empty-" + arch:
							data = nil
						case "tampered-" + arch:
							data = []byte("tampered")
						case "swapped":
							if arch == "amd64" {
								data = sboms["arm64"]
							} else {
								data = sboms["amd64"]
							}
						}
						if err := os.WriteFile(filepath.Join(target, "sbom-"+arch+".cdx.json"), data, 0600); err != nil {
							t.Fatal(err)
						}
					}
					for _, arch := range []string{"amd64", "arm64"} {
						switch scenario {
						case "missing-digest-" + arch:
							sbomHashes[arch] = ""
						case "wrong-digest-" + arch:
							sbomHashes[arch] = strings.Repeat("0", 64)
						}
					}
					err := runStep(verify, "RUNNER_TEMP="+dir, "AMD64_ARCHIVE="+hash, "ARM64_ARCHIVE="+hash,
						"AMD64_SBOM="+sbomHashes["amd64"], "ARM64_SBOM="+sbomHashes["arm64"])
					if (err == nil) != (scenario == "valid") {
						t.Fatalf("verification success = %t for %s: %v", err == nil, scenario, err)
					}
				})
			}
		})
	}
}

func TestCandidateSourceSHA(t *testing.T) {
	requireTools(t, "bash")
	validate := workflowStep(t, "../.github/workflows/build-candidate.yml", "build", "Validate inputs")
	for _, tt := range []struct {
		name, sha string
		ok        bool
	}{
		{"default", "", true},
		{"valid", strings.Repeat("a", 40), true},
		{"short", strings.Repeat("a", 12), false},
		{"invalid", strings.Repeat("g", 40), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := runStep(validate, "ARCH=amd64", "VERSION=0.0.0", "SOURCE_SHA="+tt.sha)
			if (err == nil) != tt.ok {
				t.Fatalf("validation success = %t, want %t: %v", err == nil, tt.ok, err)
			}
		})
	}
}

func TestCandidateWorkflowWiring(t *testing.T) {
	type step struct {
		Name string            `yaml:"name"`
		Uses string            `yaml:"uses"`
		If   string            `yaml:"if"`
		With map[string]string `yaml:"with"`
		Env  map[string]string `yaml:"env"`
	}
	type job struct {
		Uses        string            `yaml:"uses"`
		Needs       yaml.Node         `yaml:"needs"`
		With        map[string]string `yaml:"with"`
		Permissions map[string]string `yaml:"permissions"`
		Steps       []step            `yaml:"steps"`
	}
	readJobs := func(path string) map[string]job {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var workflow struct {
			Jobs map[string]job `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(data, &workflow); err != nil {
			t.Fatal(err)
		}
		return workflow.Jobs
	}
	build := readJobs("../.github/workflows/build-candidate.yml")["build"]
	trustedSetup, sourceCheckout, sourceBuild := -1, -1, -1
	for i, s := range build.Steps {
		switch {
		case s.Uses == "./.github/actions/setup-buildx":
			trustedSetup = i
		case strings.HasPrefix(s.Uses, "actions/checkout@") && s.With["path"] == "candidate-source" &&
			s.With["ref"] == "${{ inputs.source_sha }}" && s.With["persist-credentials"] == "false" &&
			s.If == "inputs.source_sha != ''":
			sourceCheckout = i
		case s.Name == "Build candidate OCI archive" &&
			s.With["context"] == "${{ inputs.source_sha != '' && './candidate-source' || '.' }}" &&
			s.With["file"] == "${{ inputs.source_sha != '' && './candidate-source/docker/Dockerfile' || 'docker/Dockerfile' }}":
			sourceBuild = i
		}
	}
	if trustedSetup < 0 || sourceCheckout <= trustedSetup || sourceBuild <= sourceCheckout {
		t.Fatal("selected source must be isolated from the trusted setup action")
	}
	jobs := readJobs("../.github/workflows/publish-candidate.yml")
	for _, arch := range []string{"amd64", "arm64"} {
		build := jobs["build-"+arch]
		if build.Uses != "./.github/workflows/build-candidate.yml" ||
			build.With["arch"] != arch ||
			build.With["source_sha"] != "${{ needs.validate.outputs.source_sha }}" ||
			build.Permissions["contents"] != "read" || len(build.Permissions) != 1 {
			t.Fatalf("invalid %s build configuration: %+v", arch, build)
		}
	}
	publish := jobs["publish"]
	var needs []string
	if err := publish.Needs.Decode(&needs); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(needs, "build-amd64") || !slices.Contains(needs, "build-arm64") ||
		publish.Permissions["packages"] != "write" || publish.Permissions["actions"] != "read" ||
		publish.Permissions["contents"] != "read" || len(publish.Permissions) != 3 {
		t.Fatal("candidate publish dependencies or permissions are incorrect")
	}
	verification, login := -1, -1
	for i, s := range publish.Steps {
		if s.Name == "Verify scanned artifacts" {
			verification = i
		}
		if s.Name == "Login to GHCR" {
			login = i
		}
	}
	if verification < 0 || login <= verification {
		t.Fatal("candidate artifact verification must precede registry login")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		found := false
		for i, s := range publish.Steps {
			if i < verification && strings.HasPrefix(s.Uses, "actions/download-artifact@") &&
				s.With["name"] == "sbom-"+arch && s.With["path"] == "${{ runner.temp }}/sboms/"+arch {
				found = true
			}
		}
		if !found || publish.Steps[verification].Env[strings.ToUpper(arch)+"_SBOM"] !=
			"${{ needs.build-"+arch+".outputs.sbom_sha256 }}" {
			t.Fatalf("candidate %s SBOM download and digest are not bound to the build", arch)
		}
	}
}

func TestPublishCandidateManifests(t *testing.T) {
	requireTools(t, "bash", "jq", "sha256sum", "cut")
	publish := workflowStep(t, "../.github/workflows/publish-candidate.yml", "publish", "Publish scanned candidate manifests")
	amd, arm := []byte("amd64 manifest"), []byte("arm64 manifest")
	amdSum, armSum := sha256.Sum256(amd), sha256.Sum256(arm)
	amdDigest, armDigest := "sha256:"+hex.EncodeToString(amdSum[:]), "sha256:"+hex.EncodeToString(armSum[:])
	sha := strings.Repeat("a", 40)
	tag := "candidate-aaaaaaaaaaaa-123-1-" + strings.Repeat("b", 32)
	for _, scenario := range []string{"existing-package", "first-publication", "first-name-unknown", "first-collision", "first-write-denied",
		"first-post-write-forbidden", "existing-index", "existing-amd64", "existing-arm64",
		"ambiguous-package-404", "package-forbidden", "wrong-package", "package-network-error",
		"unauthorized", "bad-response", "auth-failure", "tampered-manifest", "invalid-nonce"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			dockerStub := `#!/bin/sh
printf '%s\n' "$*" >> "$TEST_CALLS"
case "$*" in
  *" copy --preserve-digests "*)
    [ "$TEST_CASE" != first-write-denied ] || exit 1
    : > "$TEST_PACKAGE_CREATED"
    exit 0 ;;
  *" inspect --raw "*)
    for last do :; done
    case "$last" in
      "docker://ghcr.io/hermanops/docker-wyze-bridge@$AMD64_MANIFEST") cat "$TEST_AMD64" ;;
      "docker://ghcr.io/hermanops/docker-wyze-bridge@$ARM64_MANIFEST") cat "$TEST_ARM64" ;;
      *) exit 1 ;;
    esac ;;
  "buildx imagetools create "*) exit 0 ;;
  *) exit 1 ;;
esac
`
			curlStub := `#!/bin/sh
output=
next_output=
for arg do
  if [ "$next_output" = yes ]; then output="$arg"; next_output=; continue; fi
  case "$arg" in
    --output) next_output=yes ;;
    https://*) url="$arg" ;;
  esac
done
config=$(cat)
expected='header = "Authorization: Bearer mock-registry-token"'
if [ "$TEST_CASE" = first-publication ] && [ -f "$TEST_PACKAGE_CREATED" ]; then
  expected='header = "Authorization: Bearer refreshed-registry-token"'
fi
case "$url" in
  https://ghcr.io/token)
    [ "$config" = 'user = "hermanops:mock-token"' ] || exit 1
    [ "$TEST_CASE" != auth-failure ] || exit 7
    if [ "$TEST_CASE" = first-publication ] && [ -f "$TEST_PACKAGE_CREATED" ]; then
      printf '%s' '{"token":"refreshed-registry-token"}'
    else
      printf '%s' '{"token":"mock-registry-token"}'
    fi ;;
  "https://ghcr.io/v2/hermanops/docker-wyze-bridge/tags/list?n=1")
    [ "$config" = "$expected" ] || exit 1
    case "$TEST_CASE" in
      first-publication|first-name-unknown|first-collision|first-write-denied|first-post-write-forbidden)
        if [ ! -f "$TEST_PACKAGE_CREATED" ]; then
          printf '%s' '{"errors":[{"code":"NAME_UNKNOWN"}]}' > "$output"; printf 404
        elif [ "$TEST_CASE" = first-post-write-forbidden ]; then
          printf '%s' '{}' > "$output"; printf 403
        else
          printf '%s' '{"name":"hermanops/docker-wyze-bridge","tags":[]}' > "$output"; printf 200
        fi ;;
      ambiguous-package-404) printf '%s' '{}' > "$output"; printf 404 ;;
      package-forbidden) printf '%s' '{}' > "$output"; printf 403 ;;
      wrong-package) printf '%s' '{"name":"other/package","tags":[]}' > "$output"; printf 200 ;;
      package-network-error) exit 7 ;;
      *) printf '%s' '{"name":"hermanops/docker-wyze-bridge","tags":[]}' > "$output"; printf 200 ;;
    esac ;;
  https://ghcr.io/v2/hermanops/docker-wyze-bridge/manifests/*)
    [ "$config" = "$expected" ] || exit 1
    tag=${url##*/}
    case "$TEST_CASE:$tag" in
      existing-index:"$TEST_TAG"|existing-amd64:"$TEST_TAG-amd64"|existing-arm64:"$TEST_TAG-arm64")
        printf '%s' '{}' > "$output"; printf 200 ;;
      first-collision:"$TEST_TAG-amd64") printf '%s' '{}' > "$output"; printf 200 ;;
      unauthorized:*) printf '%s' '{}' > "$output"; printf 401 ;;
      bad-response:*) printf '%s' '{"errors":[{"code":"NAME_UNKNOWN"}]}' > "$output"; printf 404 ;;
      first-name-unknown:*)
        if [ ! -f "$TEST_PACKAGE_CREATED" ]; then
          printf '%s' '{"errors":[{"code":"NAME_UNKNOWN"}]}' > "$output"; printf 404
        else
          printf '%s' '{"errors":[{"code":"MANIFEST_UNKNOWN"}]}' > "$output"; printf 404
        fi ;;
      *) printf '%s' '{"errors":[{"code":"MANIFEST_UNKNOWN"}]}' > "$output"; printf 404 ;;
    esac ;;
  *) exit 1 ;;
esac
`
			opensslStub := `#!/bin/sh
[ "$*" = "rand -hex 16" ] || exit 1
if [ "$TEST_CASE" = invalid-nonce ]; then printf '%s\n' invalid; else printf '%s\n' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; fi
`
			armContent := arm
			if scenario == "tampered-manifest" {
				armContent = []byte("tampered")
			}
			for name, content := range map[string][]byte{
				"docker": []byte(dockerStub), "curl": []byte(curlStub), "openssl": []byte(opensslStub),
				"amd64": amd, "arm64": armContent,
			} {
				if err := os.WriteFile(filepath.Join(dir, name), content, 0700); err != nil {
					t.Fatal(err)
				}
			}
			calls, output := filepath.Join(dir, "calls"), filepath.Join(dir, "output")
			err := runStep(publish, "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"RUNNER_TEMP="+dir, "GITHUB_OUTPUT="+output, "TEST_CALLS="+calls,
				"TEST_AMD64="+filepath.Join(dir, "amd64"), "TEST_ARM64="+filepath.Join(dir, "arm64"),
				"TEST_PACKAGE_CREATED="+filepath.Join(dir, "package-created"),
				"TEST_CASE="+scenario, "TEST_TAG="+tag, "SOURCE_SHA="+sha,
				"GITHUB_REPOSITORY=hermanops/docker-wyze-bridge", "GITHUB_REPOSITORY_OWNER=hermanops",
				"GITHUB_RUN_ID=123", "GITHUB_RUN_ATTEMPT=1", "GHCR_TOKEN=mock-token", "SKOPEO_IMAGE=skopeo",
				"AMD64_MANIFEST="+amdDigest, "ARM64_MANIFEST="+armDigest)
			success := scenario == "existing-package" || scenario == "first-publication" || scenario == "first-name-unknown"
			if (err == nil) != success {
				t.Fatalf("publication success = %t for %s: %v", err == nil, scenario, err)
			}
			log, readErr := os.ReadFile(calls)
			if readErr != nil && !os.IsNotExist(readErr) {
				t.Fatal(readErr)
			}
			if !success && scenario != "tampered-manifest" && scenario != "first-write-denied" &&
				scenario != "first-post-write-forbidden" && len(log) != 0 {
				t.Fatalf("registry writes before preflight success: %s", log)
			}
			indexCommand := "buildx imagetools create --tag ghcr.io/hermanops/docker-wyze-bridge:" + tag
			if strings.Contains(string(log), indexCommand) != success {
				t.Fatalf("unexpected index publication: %s", log)
			}
			if scenario == "first-write-denied" || scenario == "first-post-write-forbidden" {
				if strings.Count(string(log), " copy --preserve-digests ") != 1 {
					t.Fatalf("unexpected writes after first push: %s", log)
				}
			}
			if success {
				data, err := os.ReadFile(output)
				if err != nil || string(data) != "image=ghcr.io/hermanops/docker-wyze-bridge:"+tag+"\n" {
					t.Fatalf("unexpected output %q: %v", data, err)
				}
			}
		})
	}
}

func TestVerifyCandidateIndex(t *testing.T) {
	requireTools(t, "bash", "jq")
	verify := workflowStep(t, "../.github/workflows/publish-candidate.yml", "publish", "Verify candidate index")
	amd := "sha256:" + strings.Repeat("a", 64)
	arm := "sha256:" + strings.Repeat("b", 64)
	for _, tt := range []struct {
		name, armDigest string
		ok              bool
	}{
		{"valid", arm, true},
		{"wrong-arm", amd, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			index, err := json.Marshal(map[string]any{
				"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
				"manifests": []any{
					map[string]any{"platform": map[string]string{"os": "linux", "architecture": "amd64"}, "digest": amd},
					map[string]any{"platform": map[string]string{"os": "linux", "architecture": "arm64"}, "digest": tt.armDigest},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "index"), index, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\ncat \"$TEST_INDEX\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			image := "ghcr.io/hermanops/docker-wyze-bridge:candidate-test"
			summary := filepath.Join(dir, "summary")
			err = runStep(verify, "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"TEST_INDEX="+filepath.Join(dir, "index"), "GITHUB_STEP_SUMMARY="+summary,
				"SKOPEO_IMAGE=skopeo", "IMAGE="+image, "AMD64_MANIFEST="+amd, "ARM64_MANIFEST="+arm)
			if (err == nil) != tt.ok {
				t.Fatalf("index verification success = %t, want %t: %v", err == nil, tt.ok, err)
			}
			if tt.ok {
				data, err := os.ReadFile(summary)
				if err != nil || !bytes.Contains(data, []byte("docker pull "+image)) {
					t.Fatalf("missing candidate pull command in summary: %s (%v)", data, err)
				}
			}
		})
	}
}

func TestSBOMArtifactWiring(t *testing.T) {
	type step struct {
		Name            string            `yaml:"name"`
		Uses            string            `yaml:"uses"`
		If              string            `yaml:"if"`
		ContinueOnError bool              `yaml:"continue-on-error"`
		With            map[string]string `yaml:"with"`
		Env             map[string]string `yaml:"env"`
	}
	type job struct {
		Steps   []step            `yaml:"steps"`
		Outputs map[string]string `yaml:"outputs"`
		With    map[string]string `yaml:"with"`
		Uses    string            `yaml:"uses"`
		Needs   yaml.Node         `yaml:"needs"`
	}
	type workflow struct {
		On struct {
			WorkflowCall struct {
				Outputs map[string]struct {
					Value string `yaml:"value"`
				} `yaml:"outputs"`
			} `yaml:"workflow_call"`
		} `yaml:"on"`
		Jobs map[string]job `yaml:"jobs"`
	}
	read := func(path string) workflow {
		t.Helper()
		var parsed workflow
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := yaml.Unmarshal(data, &parsed); err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	candidate := read("../.github/workflows/build-candidate.yml")
	if candidate.On.WorkflowCall.Outputs["sbom_sha256"].Value != "${{ jobs.build.outputs.sbom_sha256 }}" ||
		candidate.Jobs["build"].Outputs["sbom_sha256"] != "${{ steps.scan.outputs.sbom_sha256 }}" {
		t.Fatal("candidate SBOM digest is not exposed as a workflow output")
	}
	var upload step
	for _, s := range candidate.Jobs["build"].Steps {
		if s.Name == "Upload SBOM" {
			upload = s
		}
	}
	if !strings.HasPrefix(upload.Uses, "actions/upload-artifact@") || upload.If != "" || upload.ContinueOnError ||
		upload.With["if-no-files-found"] != "error" ||
		upload.With["name"] != "sbom-${{ inputs.arch }}" ||
		upload.With["path"] != "${{ runner.temp }}/sbom-${{ inputs.arch }}.cdx.json" {
		t.Fatalf("SBOM upload is not mandatory and architecture-specific: %+v", upload)
	}
	publish := read("../.github/workflows/publish.yml")
	var publishNeeds []string
	publishJob := publish.Jobs["publish"]
	if err := publishJob.Needs.Decode(&publishNeeds); err != nil {
		t.Fatal(err)
	}
	verificationIndex, publicationIndex := -1, -1
	for i, s := range publish.Jobs["publish"].Steps {
		if s.Name == "Verify scanned artifacts" {
			verificationIndex = i
		}
		if s.Name == "Login to GHCR" {
			publicationIndex = i
		}
	}
	if verificationIndex < 0 || publicationIndex <= verificationIndex {
		t.Fatal("artifact verification must precede GHCR access")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		build := publish.Jobs["build-"+arch]
		if build.With["arch"] != arch || build.Uses != "./.github/workflows/build-candidate.yml" ||
			!slices.Contains(publishNeeds, "build-"+arch) {
			t.Fatalf("candidate job is not bound to %s", arch)
		}
		downloadFound, digestFound := false, false
		for i, s := range publish.Jobs["publish"].Steps {
			if strings.HasPrefix(s.Uses, "actions/download-artifact@") && s.If == "" && !s.ContinueOnError &&
				s.With["name"] == "sbom-"+arch && s.With["path"] == "${{ runner.temp }}/sboms/"+arch &&
				i < verificationIndex {
				downloadFound = true
			}
			if s.Name == "Verify scanned artifacts" && s.If == "" && !s.ContinueOnError &&
				s.Env[strings.ToUpper(arch)+"_SBOM"] == "${{ needs.build-"+arch+".outputs.sbom_sha256 }}" {
				digestFound = true
			}
		}
		if !downloadFound || !digestFound {
			t.Fatalf("SBOM download or digest is not bound to the %s candidate", arch)
		}
	}
}

func TestPublishedMultiArchTags(t *testing.T) {
	requireTools(t, "bash", "jq")
	verify := workflowStep(t, "../.github/workflows/publish.yml", "publish", "Verify published multi-architecture tags")
	amd64 := "sha256:" + strings.Repeat("a", 64)
	arm64 := "sha256:" + strings.Repeat("b", 64)
	index := func(mediaType string, manifests ...map[string]any) string {
		t.Helper()
		data, err := json.Marshal(map[string]any{
			"schemaVersion": 2, "mediaType": mediaType, "manifests": manifests,
		})
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	descriptor := func(os, arch, digest string) map[string]any {
		return map[string]any{
			"platform": map[string]string{"os": os, "architecture": arch},
			"digest":   digest,
		}
	}
	oci := "application/vnd.oci.image.index.v1+json"
	dockerList := "application/vnd.docker.distribution.manifest.list.v2+json"
	amd := descriptor("linux", "amd64", amd64)
	arm := descriptor("linux", "arm64", arm64)
	valid := index(oci, amd, arm)
	tests := []struct {
		name, ghcr string
		ok         bool
	}{
		{"valid-oci", valid, true},
		{"valid-reversed-docker-list", index(dockerList, arm, amd), true},
		{"missing-architecture", index(oci, amd), false},
		{"extra-architecture", index(oci, amd, arm, descriptor("linux", "arm", arm64)), false},
		{"duplicate-architecture", index(oci, amd, amd), false},
		{"wrong-os", index(oci, amd, descriptor("windows", "arm64", arm64)), false},
		{"swapped-digests", index(oci, descriptor("linux", "amd64", arm64), descriptor("linux", "arm64", amd64)), false},
		{"wrong-media-type", index("application/vnd.oci.image.manifest.v1+json", amd, arm), false},
		{"invalid-json", "{", false},
		{"inspection-fails", "FAIL", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			stub := `#!/bin/sh
for last do :; done
printf '%s\n' "$last" >> "$TEST_CALLS"
case "$last" in
  docker://ghcr.io/hermanops/docker-wyze-bridge:1.2.3) fixture="$TEST_GHCR" ;;
  *) exit 1 ;;
esac
if [ "$(cat "$fixture")" = FAIL ]; then exit 1; fi
cat "$fixture"
`
			for name, content := range map[string]string{"docker": stub, "ghcr.json": tt.ghcr} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0700); err != nil {
					t.Fatal(err)
				}
			}
			calls := filepath.Join(dir, "calls")
			err := runStep(verify,
				"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"TEST_CALLS="+calls, "TEST_GHCR="+filepath.Join(dir, "ghcr.json"),
				"GITHUB_REPOSITORY=hermanops/docker-wyze-bridge", "VERSION=1.2.3", "SKOPEO_IMAGE=skopeo",
				"AMD64_MANIFEST="+amd64, "ARM64_MANIFEST="+arm64)
			if (err == nil) != tt.ok {
				t.Fatalf("verification success = %t, want %t: %v", err == nil, tt.ok, err)
			}
			data, err := os.ReadFile(calls)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(data), "\n") != 1 {
				t.Fatalf("expected only the GHCR tag to be inspected: %s", data)
			}
		})
	}
}

func TestPublishScannedManifestsToGHCR(t *testing.T) {
	requireTools(t, "bash", "jq", "sha256sum", "cut")
	publish := workflowStep(t, "../.github/workflows/publish.yml", "publish", "Publish scanned manifests without rebuilding")
	amd := []byte("amd64 manifest")
	arm := []byte("arm64 manifest")
	amdSum, armSum := sha256.Sum256(amd), sha256.Sum256(arm)
	amdDigest, armDigest := "sha256:"+hex.EncodeToString(amdSum[:]), "sha256:"+hex.EncodeToString(armSum[:])

	for _, tt := range []struct {
		name, armContent, knownStatus, versionStatus, versionBody string
		ok                                                        bool
	}{
		{"missing-manifest", string(arm), "200", "404", `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, true},
		{"existing-manifest", string(arm), "200", "200", `{}`, false},
		{"unauthorized", string(arm), "200", "401", `{}`, false},
		{"forbidden", string(arm), "200", "403", `{}`, false},
		{"rate-limited", string(arm), "200", "429", `{}`, false},
		{"server-error", string(arm), "200", "500", `{}`, false},
		{"redirect", string(arm), "200", "302", `{}`, false},
		{"network-failure", string(arm), "200", "network-failure", "", false},
		{"malformed-response", string(arm), "200", "404", `{`, false},
		{"multiple-responses", string(arm), "200", "404", `{} {"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, false},
		{"unexpected-error", string(arm), "200", "404", `{"errors":[{"code":"NAME_UNKNOWN"}]}`, false},
		{"mixed-errors", string(arm), "200", "404", `{"errors":[{"code":"MANIFEST_UNKNOWN"},{"code":"DENIED"}]}`, false},
		{"repository-inaccessible", string(arm), "403", "404", `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, false},
		{"known-manifest-tampered", string(arm), "200", "404", `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, false},
		{"auth-malformed", string(arm), "200", "404", `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, false},
		{"auth-multiple", string(arm), "200", "404", `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, false},
		{"auth-network-failure", string(arm), "200", "404", `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, false},
		{"modified-arm-manifest", "tampered", "200", "404", `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			stub := `#!/bin/sh
printf '%s\n' "$*" >> "$TEST_CALLS"
case "$*" in
  *" copy --preserve-digests "*) exit 0 ;;
  *" inspect --raw "*)
    for last do :; done
    case "$last" in
      "docker://ghcr.io/hermanops/docker-wyze-bridge@$AMD64_MANIFEST") cat "$TEST_AMD64" ;;
      "docker://ghcr.io/hermanops/docker-wyze-bridge@$ARM64_MANIFEST") cat "$TEST_ARM64" ;;
      *) exit 1 ;;
    esac ;;
  "buildx imagetools create "*) exit 0 ;;
  *) exit 1 ;;
esac
`
			curlStub := `#!/bin/sh
output=
next_output=
for arg do
  if [ "$next_output" = yes ]; then output="$arg"; next_output=; continue; fi
  case "$arg" in
    --output) next_output=yes ;;
    https://*) url="$arg" ;;
  esac
done
config=$(cat)
printf '%s\n' "$url" >> "$TEST_CURL_CALLS"
case "$url" in
  https://ghcr.io/token)
    [ "$config" = 'user = "hermanops:mock-token"' ] || exit 1
    case " $* " in *" --data-urlencode service=ghcr.io "*) ;; *) exit 1 ;; esac
    case " $* " in *" --data-urlencode scope=repository:hermanops/docker-wyze-bridge:pull "*) ;; *) exit 1 ;; esac
    case "$TEST_CASE" in
      auth-malformed) printf '%s' '{' ;;
      auth-multiple) printf '%s' '{"token":"first"} {"token":"second"}' ;;
      auth-network-failure) exit 7 ;;
      *) printf '%s' '{"token":"mock-registry-token"}' ;;
    esac ;;
  "https://ghcr.io/v2/hermanops/docker-wyze-bridge/manifests/$AMD64_MANIFEST")
    [ "$config" = 'header = "Authorization: Bearer mock-registry-token"' ] || exit 1
    if [ "$TEST_CASE" = known-manifest-tampered ]; then
      printf '%s' 'tampered' > "$output"
    else
      cat "$TEST_AMD64" > "$output"
    fi
    printf '%s' "$TEST_KNOWN_STATUS" ;;
  https://ghcr.io/v2/hermanops/docker-wyze-bridge/manifests/1.2.3)
    [ "$config" = 'header = "Authorization: Bearer mock-registry-token"' ] || exit 1
    if [ "$TEST_VERSION_STATUS" = network-failure ]; then exit 7; fi
    printf '%s' "$TEST_VERSION_BODY" > "$output"
    printf '%s' "$TEST_VERSION_STATUS" ;;
  *) exit 1 ;;
esac
`
			for name, content := range map[string]string{"docker": stub, "curl": curlStub, "amd64": string(amd), "arm64": tt.armContent} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0700); err != nil {
					t.Fatal(err)
				}
			}
			calls := filepath.Join(dir, "calls")
			curlCalls := filepath.Join(dir, "curl-calls")
			err := runStep(publish,
				"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "RUNNER_TEMP="+dir,
				"TEST_CALLS="+calls, "TEST_AMD64="+filepath.Join(dir, "amd64"), "TEST_ARM64="+filepath.Join(dir, "arm64"),
				"TEST_CURL_CALLS="+curlCalls, "TEST_CASE="+tt.name, "TEST_KNOWN_STATUS="+tt.knownStatus,
				"TEST_VERSION_STATUS="+tt.versionStatus, "TEST_VERSION_BODY="+tt.versionBody,
				"GITHUB_REPOSITORY=hermanops/docker-wyze-bridge", "GITHUB_RUN_ID=123", "GITHUB_RUN_ATTEMPT=1",
				"GITHUB_REPOSITORY_OWNER=hermanops", "GHCR_TOKEN=mock-token", "VERSION=1.2.3", "SKOPEO_IMAGE=skopeo",
				"AMD64_MANIFEST="+amdDigest, "ARM64_MANIFEST="+armDigest)
			if (err == nil) != tt.ok {
				t.Fatalf("publication success = %t, want %t: %v", err == nil, tt.ok, err)
			}
			data, err := os.ReadFile(calls)
			if err != nil {
				t.Fatal(err)
			}
			log := string(data)
			if strings.Contains(log, "docker.io/") || strings.Contains(log, "buildx build") {
				t.Fatalf("unexpected publication command: %s", log)
			}
			expected := "buildx imagetools create --tag ghcr.io/hermanops/docker-wyze-bridge:1.2.3 ghcr.io/hermanops/docker-wyze-bridge@" + amdDigest + " ghcr.io/hermanops/docker-wyze-bridge@" + armDigest
			if strings.Contains(log, expected) != tt.ok {
				t.Fatalf("unexpected index creation: %s", log)
			}
			if tt.knownStatus == "200" && tt.armContent == string(arm) &&
				tt.name != "known-manifest-tampered" && !strings.HasPrefix(tt.name, "auth-") {
				data, err := os.ReadFile(curlCalls)
				if err != nil {
					t.Fatal(err)
				}
				target := "https://ghcr.io/v2/hermanops/docker-wyze-bridge/manifests/1.2.3\n"
				if !strings.Contains(string(data), target) {
					t.Fatalf("version manifest was not queried: %s", data)
				}
			}
		})
	}
}
