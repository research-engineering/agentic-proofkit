package witnessschedulerplan

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/kernel/cliexec"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/witnesscommand"
)

const digestedCommandID = "proofkit.test-command"

// nodeDigestPlan is a two-command plan whose vocabulary admits an alternative
// for every execution-relevant member of the first command, so each edit below
// changes exactly the member it names and stays admissible.
func nodeDigestPlan() map[string]any {
	input := validSchedulerPlanInput()
	input["vocabulary"] = map[string]any{
		"artifactKinds":      []any{"log", "report"},
		"credentialClasses":  []any{"none", "token"},
		"environmentClasses": []any{"local-go", "local-python"},
		"environmentClassPolicies": []any{
			map[string]any{"environmentClass": "local-go", "networkPolicies": []any{"loopback", "none"}, "credentialClasses": []any{"none", "token"}, "cachePolicies": []any{"disabled", "read-only"}},
			map[string]any{"environmentClass": "local-python", "networkPolicies": []any{"none"}, "credentialClasses": []any{"none"}, "cachePolicies": []any{"disabled"}},
		},
		"parallelGroups":                []any{"local", "other"},
		"nonCacheableCredentialClasses": []any{},
		"maxTimeoutMs":                  json.Number("10000"),
	}
	second, secondPolicy := cloneMap(command(input)), cloneMap(schedulerPolicy(input))
	second["id"], secondPolicy["commandId"] = "proofkit.test-command.second", "proofkit.test-command.second"
	second["expectedArtifacts"], secondPolicy["outputSelectors"], secondPolicy["resourceWrites"] = []any{}, []any{}, []any{}
	second["environment"].(map[string]any)["classes"] = []any{"local-python"}
	secondPolicy["sideEffectClass"] = "none"
	input["commands"] = append(input["commands"].([]any), second)
	input["policies"] = append(input["policies"].([]any), secondPolicy)
	return input
}

func nodeDigests(t *testing.T, edit func(map[string]any)) map[string]string {
	t.Helper()
	input := nodeDigestPlan()
	edit(input)
	projection, record, _, err := Evaluate(input)
	if err != nil {
		t.Fatalf("edit made the plan inadmissible: %v", err)
	}
	digests := map[string]string{}
	for _, command := range projection.Commands {
		digests[command.ID] = command.ProofNodeDigest
	}
	reported := record.Diagnostics[len(record.Diagnostics)-1]
	rows, _ := reported.Value.([]any)
	if record.SchemaVersion != 2 || reported.Key != "proofNodeDigests" || len(rows) != len(projection.Commands) {
		t.Fatalf("report schemaVersion=%d diagnostic=%s rows=%d", record.SchemaVersion, reported.Key, len(rows))
	}
	for index, raw := range rows {
		row := raw.(map[string]any)
		if row["commandId"] != projection.Commands[index].ID || row["proofNodeDigest"] != projection.Commands[index].ProofNodeDigest || !strings.HasPrefix(row["proofNodeDigest"].(string), "sha256:") {
			t.Fatalf("reported node row %v differs from the linkage projection", row)
		}
	}
	return digests
}

func digestedCommand(input map[string]any) map[string]any {
	return input["commands"].([]any)[0].(map[string]any)
}

func digestedPolicy(input map[string]any) map[string]any {
	return input["policies"].([]any)[0].(map[string]any)
}

func environmentClassPolicy(input map[string]any, class string) map[string]any {
	for _, raw := range input["vocabulary"].(map[string]any)["environmentClassPolicies"].([]any) {
		if row := raw.(map[string]any); row["environmentClass"] == class {
			return row
		}
	}
	panic("missing environment class policy " + class)
}

// leafFields lists the admitted leaf members of a native record type, so the
// coverage tables below must name every member a future change adds.
func leafFields(prefix string, value reflect.Type) []string {
	for value.Kind() == reflect.Slice || value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return []string{prefix}
	}
	result := []string{}
	for index := range value.NumField() {
		result = append(result, leafFields(prefix+"."+value.Field(index).Name, value.Field(index).Type)...)
	}
	return result
}

func requireCoveredFields(t *testing.T, label string, want []string, covered map[string]bool) {
	t.Helper()
	slices.Sort(want)
	got := make([]string, 0, len(covered))
	for field := range covered {
		got = append(got, field)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("%s coverage = %v, want every admitted member %v", label, got, want)
	}
}

// Every member that decides how a command runs is part of its node digest:
// an edit to one member of the first command changes that command's digest
// and leaves the other command's digest unchanged.
func TestProofNodeDigestCoversEveryExecutionMember(t *testing.T) {
	base := nodeDigests(t, func(map[string]any) {})
	changes := map[string]func(map[string]any){
		"Command.Argv":        func(input map[string]any) { digestedCommand(input)["argv"] = []any{"go", "test", "-count=1", "./..."} },
		"Command.CachePolicy": func(input map[string]any) { digestedCommand(input)["cachePolicy"] = "read-only" },
		"Command.CredentialClass": func(input map[string]any) {
			digestedCommand(input)["credentialClass"] = "token"
		},
		"Command.Cwd": func(input map[string]any) { digestedCommand(input)["cwd"] = "cmd" },
		"Command.Environment.Allowlist": func(input map[string]any) {
			digestedCommand(input)["environment"] = map[string]any{"inherit": "allowlist", "allowlist": []any{"HOME"}, "classes": []any{"local-go"}}
		},
		// inherit is determined by allowlist emptiness, so it cannot change alone.
		"Command.Environment.Inherit": func(input map[string]any) {
			digestedCommand(input)["environment"] = map[string]any{"inherit": "allowlist", "allowlist": []any{"PATH"}, "classes": []any{"local-go"}}
		},
		"Command.Environment.Classes": func(input map[string]any) {
			digestedCommand(input)["environment"].(map[string]any)["classes"] = []any{"local-go", "local-python"}
		},
		"Command.ExitCodePolicy.Kind": func(input map[string]any) {
			digestedCommand(input)["exitCodePolicy"] = map[string]any{"kind": "listed", "successCodes": []any{json.Number("0")}}
		},
		"Command.ExitCodePolicy.SuccessCodes": func(input map[string]any) {
			digestedCommand(input)["exitCodePolicy"] = map[string]any{"kind": "listed", "successCodes": []any{json.Number("0"), json.Number("1")}}
		},
		"Command.ExpectedArtifacts.Kind": func(input map[string]any) {
			digestedCommand(input)["expectedArtifacts"].([]any)[0].(map[string]any)["kind"] = "log"
		},
		"Command.ExpectedArtifacts.Path": func(input map[string]any) {
			digestedCommand(input)["expectedArtifacts"].([]any)[0].(map[string]any)["path"] = "artifacts/proofkit/other.json"
		},
		"Command.ExpectedArtifacts.Required": func(input map[string]any) {
			digestedCommand(input)["expectedArtifacts"].([]any)[0].(map[string]any)["required"] = false
		},
		"Command.NetworkPolicy": func(input map[string]any) { digestedCommand(input)["networkPolicy"] = "loopback" },
		"Command.ParallelGroup": func(input map[string]any) { digestedCommand(input)["parallelGroup"] = "other" },
		"Command.TimeoutMs":     func(input map[string]any) { digestedCommand(input)["timeoutMs"] = json.Number("2000") },
		"policy.CacheAdmissionRefs": func(input map[string]any) {
			digestedPolicy(input)["cacheAdmissionRefs"] = []any{"docs/cache.md"}
		},
		"policy.CancellationPolicy.GraceMs": func(input map[string]any) {
			digestedPolicy(input)["cancellationPolicy"] = map[string]any{"kind": "cooperative", "graceMs": json.Number("6000")}
		},
		"policy.CancellationPolicy.Kind": func(input map[string]any) {
			digestedPolicy(input)["cancellationPolicy"] = map[string]any{"kind": "not_supported"}
		},
		"policy.DeterministicOutput": func(input map[string]any) { digestedPolicy(input)["deterministicOutput"] = false },
		"policy.ExclusiveLocks":      func(input map[string]any) { digestedPolicy(input)["exclusiveLocks"] = []any{"lock.proofkit.test"} },
		"policy.InputSelectors":      func(input map[string]any) { digestedPolicy(input)["inputSelectors"] = []any{"internal"} },
		"policy.OutputSelectors":     func(input map[string]any) { digestedPolicy(input)["outputSelectors"] = []any{} },
		"policy.ResourceReads":       func(input map[string]any) { digestedPolicy(input)["resourceReads"] = []any{} },
		"policy.ResourceWrites": func(input map[string]any) {
			digestedPolicy(input)["resourceWrites"] = []any{"resource.proofkit.other-artifacts"}
		},
		"policy.RetryPolicy.Kind": func(input map[string]any) {
			digestedPolicy(input)["retryPolicy"] = map[string]any{"kind": "bounded", "maxAttempts": json.Number("2")}
		},
		"policy.SideEffectClass": func(input map[string]any) { digestedPolicy(input)["sideEffectClass"] = "shared_resource" },
		"policy.TimeoutPolicy.TimeoutMs": func(input map[string]any) {
			digestedPolicy(input)["timeoutPolicy"].(map[string]any)["timeoutMs"] = json.Number("2000")
		},
	}
	// Pairs whose baseline differs from the plan baseline in a second member.
	pairs := map[string][2]func(map[string]any){
		"policy.RetryPolicy.MaxAttempts": {
			func(input map[string]any) {
				digestedPolicy(input)["retryPolicy"] = map[string]any{"kind": "bounded", "maxAttempts": json.Number("2")}
			},
			func(input map[string]any) {
				digestedPolicy(input)["retryPolicy"] = map[string]any{"kind": "bounded", "maxAttempts": json.Number("3")}
			},
		},
	}
	// The command ID is the node identity itself: renaming the command and its
	// policy yields another node, never the old node's digest.
	renamed := nodeDigests(t, func(input map[string]any) {
		digestedCommand(input)["id"], digestedPolicy(input)["commandId"] = "proofkit.test-command.renamed", "proofkit.test-command.renamed"
	})
	if renamed["proofkit.test-command.renamed"] == base[digestedCommandID] {
		t.Fatal("renamed command kept the node digest")
	}
	covered := map[string]bool{"Command.ID": true, "policy.CommandID": true}
	// One timeout kind exists, so no admitted edit can change it.
	covered["policy.TimeoutPolicy.Kind"] = true
	for field, edit := range changes {
		got := nodeDigests(t, edit)
		if got[digestedCommandID] == base[digestedCommandID] {
			t.Fatalf("%s edit kept the node digest", field)
		}
		if got["proofkit.test-command.second"] != base["proofkit.test-command.second"] {
			t.Fatalf("%s edit of the first command changed the second command's node digest", field)
		}
		covered[field] = true
	}
	for field, pair := range pairs {
		if nodeDigests(t, pair[0])[digestedCommandID] == nodeDigests(t, pair[1])[digestedCommandID] {
			t.Fatalf("%s edit kept the node digest", field)
		}
		covered[field] = true
	}
	// Prose is the one policy member that cannot change how the command runs.
	covered["policy.NonClaims"] = true
	if got := nodeDigests(t, func(input map[string]any) {
		digestedPolicy(input)["nonClaims"] = []any{"Reworded synthetic policy prose."}
	}); got[digestedCommandID] != base[digestedCommandID] {
		t.Fatal("policy nonClaims prose changed the node digest")
	}
	requireCoveredFields(t, "command and policy", append(leafFields("Command", reflect.TypeFor[witnesscommand.Command]()), leafFields("policy", reflect.TypeFor[policy]())...), covered)
}

// The vocabulary enters a node digest only through the names the command
// references: changing a referenced row changes the digest, changing an
// unreferenced row or a pure admission bound does not.
func TestProofNodeDigestProjectsVocabularyOntoReferencedNames(t *testing.T) {
	base := nodeDigests(t, func(map[string]any) {})
	vocabulary := func(input map[string]any) map[string]any { return input["vocabulary"].(map[string]any) }
	referenced := map[string]func(map[string]any){
		"Vocabulary.EnvironmentClassPolicies.CachePolicies": func(input map[string]any) {
			environmentClassPolicy(input, "local-go")["cachePolicies"] = []any{"disabled", "read-only", "write-local"}
		},
		"Vocabulary.EnvironmentClassPolicies.CredentialClasses": func(input map[string]any) {
			environmentClassPolicy(input, "local-go")["credentialClasses"] = []any{"none"}
		},
		"Vocabulary.EnvironmentClassPolicies.NetworkPolicies": func(input map[string]any) {
			environmentClassPolicy(input, "local-go")["networkPolicies"] = []any{"none"}
		},
		"Vocabulary.NonCacheableCredentialClasses": func(input map[string]any) {
			vocabulary(input)["nonCacheableCredentialClasses"] = []any{"none"}
		},
	}
	unreferenced := map[string]func(map[string]any){
		"Vocabulary.ArtifactKinds":     func(input map[string]any) { vocabulary(input)["artifactKinds"] = []any{"log", "report", "trace"} },
		"Vocabulary.CredentialClasses": func(input map[string]any) { vocabulary(input)["credentialClasses"] = []any{"deploy", "none", "token"} },
		"Vocabulary.EnvironmentClasses": func(input map[string]any) {
			vocabulary(input)["environmentClasses"] = []any{"local-go", "local-python", "local-rust"}
		},
		"Vocabulary.EnvironmentClassPolicies.EnvironmentClass": func(input map[string]any) {
			vocabulary(input)["environmentClasses"] = []any{"local-go", "local-python", "local-rust"}
			vocabulary(input)["environmentClassPolicies"] = append(vocabulary(input)["environmentClassPolicies"].([]any),
				map[string]any{"environmentClass": "local-rust", "networkPolicies": []any{"none"}, "credentialClasses": []any{"none"}, "cachePolicies": []any{"disabled"}})
		},
		"Vocabulary.EnvironmentClassPolicies.CachePolicies.unreferenced-row": func(input map[string]any) {
			environmentClassPolicy(input, "local-python")["cachePolicies"] = []any{"disabled", "read-only"}
		},
		"Vocabulary.MaxTimeoutMs": func(input map[string]any) { vocabulary(input)["maxTimeoutMs"] = json.Number("20000") },
		"Vocabulary.NonCacheableCredentialClasses.unreferenced": func(input map[string]any) {
			vocabulary(input)["nonCacheableCredentialClasses"] = []any{"token"}
		},
		"Vocabulary.ParallelGroups": func(input map[string]any) { vocabulary(input)["parallelGroups"] = []any{"local", "other", "zeta"} },
	}
	covered := map[string]bool{}
	for name, edit := range referenced {
		if nodeDigests(t, edit)[digestedCommandID] == base[digestedCommandID] {
			t.Fatalf("referenced vocabulary edit %s kept the node digest", name)
		}
		covered[name] = true
	}
	for name, edit := range unreferenced {
		if nodeDigests(t, edit)[digestedCommandID] != base[digestedCommandID] {
			t.Fatalf("unreferenced vocabulary edit %s changed the node digest", name)
		}
		covered[strings.TrimSuffix(strings.TrimSuffix(name, ".unreferenced-row"), ".unreferenced")] = true
	}
	// A referenced name's own membership cannot be removed while the command
	// stays admitted and the name is already in the command record, so bare
	// membership lists are not hashed; the unreferenced edits above cover them.
	requireCoveredFields(t, "vocabulary", leafFields("Vocabulary", reflect.TypeFor[witnesscommand.Vocabulary]()), covered)
}

// Linkage identity excludes prose and everything outside the node: plan and
// policy nonClaims, the plan ID (linkage compares it separately), another
// command and its policy, and input spelling and order.
func TestProofNodeDigestIgnoresProseOtherNodesAndSpelling(t *testing.T) {
	base := nodeDigests(t, func(map[string]any) {})
	for name, edit := range map[string]func(map[string]any){
		"plan nonClaims": func(input map[string]any) { input["nonClaims"] = []any{"Reworded synthetic plan prose."} },
		"policy nonClaims": func(input map[string]any) {
			digestedPolicy(input)["nonClaims"] = []any{"Reworded synthetic policy prose."}
		},
		"schedulerPlanId": func(input map[string]any) { input["schedulerPlanId"] = "proofkit.test.scheduler.renamed" },
		"other command": func(input map[string]any) {
			input["commands"].([]any)[1].(map[string]any)["argv"] = []any{"go", "vet", "./..."}
		},
		"other policy": func(input map[string]any) {
			input["policies"].([]any)[1].(map[string]any)["inputSelectors"] = []any{"internal"}
		},
		"other group member": func(input map[string]any) {
			third, policy := cloneMap(input["commands"].([]any)[1].(map[string]any)), cloneMap(input["policies"].([]any)[1].(map[string]any))
			third["id"], policy["commandId"] = "proofkit.test-command.third", "proofkit.test-command.third"
			input["commands"] = append(input["commands"].([]any), third)
			input["policies"] = append(input["policies"].([]any), policy)
		},
		"commands and policies reversed": func(input map[string]any) {
			slices.Reverse(input["commands"].([]any))
			slices.Reverse(input["policies"].([]any))
		},
		"omitted optional vocabulary list": func(input map[string]any) {
			delete(input["vocabulary"].(map[string]any), "nonCacheableCredentialClasses")
		},
	} {
		if got := nodeDigests(t, edit); got[digestedCommandID] != base[digestedCommandID] {
			t.Fatalf("%s changed the node digest of %s", name, digestedCommandID)
		}
	}
	if got := nodeDigests(t, func(input map[string]any) {
		input["commands"].([]any)[1].(map[string]any)["argv"] = []any{"go", "vet", "./..."}
	}); got["proofkit.test-command.second"] == base["proofkit.test-command.second"] {
		t.Fatal("edited command kept its own node digest")
	}
}

// The guide states exactly the empty-list constraints native admission
// enforces for sideEffectClass none.
func TestSchedulerGuideStatesEnforcedSideEffectFreeConstraints(t *testing.T) {
	refused := []string{}
	for _, field := range []string{"exclusiveLocks", "outputSelectors", "resourceReads", "resourceWrites"} {
		input := validSchedulerPlanInput()
		digestedCommand(input)["expectedArtifacts"] = []any{}
		policy := digestedPolicy(input)
		policy["sideEffectClass"], policy["outputSelectors"], policy["resourceReads"], policy["resourceWrites"] = "none", []any{}, []any{}, []any{}
		policy[field] = []any{"value.x"}
		_, _, exitCode, err := Evaluate(input)
		if err != nil {
			t.Fatal(err)
		}
		if exitCode != 0 {
			refused = append(refused, field)
		}
	}
	guide := strings.Join(strings.Fields(InputGuide(cliexec.PathRenderer())), " ")
	slices.Sort(refused)
	if want := "none requires empty " + strings.Join(refused, " and ") + " and means"; !strings.Contains(guide, want) {
		t.Fatalf("guide does not state the enforced constraint %q", want)
	}
}
