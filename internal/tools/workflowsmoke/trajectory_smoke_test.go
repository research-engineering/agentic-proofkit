package workflowsmoke_test

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/research-engineering/agentic-proofkit/internal/command/witnessschedulerplan"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/admission"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/digest"
	"github.com/research-engineering/agentic-proofkit/internal/kernel/stablejson"
	"github.com/research-engineering/agentic-proofkit/internal/tools/workflowsmoke"
)

func TestVerifyTrajectoryAcceptsApplicationCLI(t *testing.T) {
	if err := workflowsmoke.VerifyTrajectory(t.Context(), applicationRunner); err != nil {
		t.Fatal(err)
	}
}

// The installed carriers call VerifyProcess; this runs the same entry point
// against a binary built from the current source tree.
func TestVerifyProcessAcceptsSourceBuiltBinary(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "agentic-proofkit")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/agentic-proofkit")
	build.Dir = filepath.Join("..", "..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build source binary: %v\n%s", err, output)
	}
	if err := workflowsmoke.VerifyProcess(t.Context(), workflowsmoke.ProcessCarrier{Directory: t.TempDir(), Executable: binary}); err != nil {
		t.Fatal(err)
	}
}

// Installed carriers inherit the trajectory only through VerifyProcess, so
// that entry point must run the workflow smoke and then the trajectory once.
func TestVerifyProcessComposesWorkflowAndTrajectory(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "process.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "VerifyProcess" || function.Body == nil {
			continue
		}
		calls := []string{}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				if callee, ok := call.Fun.(*ast.Ident); ok && (callee.Name == "Verify" || callee.Name == "VerifyTrajectory") {
					calls = append(calls, callee.Name)
				}
			}
			return true
		})
		if !slices.Equal(calls, []string{"Verify", "VerifyTrajectory"}) {
			t.Fatalf("VerifyProcess calls %v, want Verify then VerifyTrajectory exactly once", calls)
		}
		return
	}
	t.Fatal("VerifyProcess is missing from process.go")
}

// Each mutant CLI wrongly accepts one negative control, or wrongly propagates
// one invalidation; the trajectory must reject it at that exact control.
func TestVerifyTrajectoryRejectsAcceptedNegativeControls(t *testing.T) {
	passedReport := workflowsmoke.Result{ExitCode: 0, Stdout: []byte("{\"state\":\"passed\"}\n")}
	for _, test := range []struct {
		name   string
		want   string
		mutate func(*testing.T, workflowsmoke.Invocation) (workflowsmoke.Result, bool)
	}{
		{"scenario membership accepted", "scenario membership must be refused", func(t *testing.T, invocation workflowsmoke.Invocation) (workflowsmoke.Result, bool) {
			return passedReport, routeIs(invocation, "adopt materialize plan") && inputValue(t, invocation, "/requirementProofBinding/record/bindings/1/scenarioId") == "greeter.empty_name"
		}},
		{"skipped review accepted", "apply without reviewed identities must be refused", func(t *testing.T, invocation workflowsmoke.Invocation) (workflowsmoke.Result, bool) {
			return passedReport, routeIs(invocation, "adopt materialize apply") && !slices.Contains(invocation.Args, "--expect-transaction")
		}},
		{"forged identity accepted", "forged identity apply exit=0", func(t *testing.T, invocation workflowsmoke.Invocation) (workflowsmoke.Result, bool) {
			return passedReport, routeIs(invocation, "adopt materialize apply") && expectedTransaction(invocation) == digest.SHA256TextRef("forged transaction identity")
		}},
		{"binding without execution accepted", "binding without execution bundle exit=0", func(t *testing.T, invocation workflowsmoke.Invocation) (workflowsmoke.Result, bool) {
			return passedReport, routeIs(invocation, "spec-proof-bundle-admission") && inputValue(t, invocation, "/mergeRequiredReceiptIds/0") == "greeter.receipt.empty-name.1" && inputValue(t, invocation, "/receiptAdmission/receipts/1") == nil
		}},
		{"relabelled failed run accepted", "relabelled failed run must be refused", func(t *testing.T, invocation workflowsmoke.Invocation) (workflowsmoke.Result, bool) {
			return passedReport, routeIs(invocation, "spec-proof-bundle-admission") && inputValue(t, invocation, "/receiptAdmission/receipts/0/receiptId") == "greeter.receipt.empty-name.failed"
		}},
		{"python evidence linked after migration", "python evidence after migration bundle exit=0", func(t *testing.T, invocation workflowsmoke.Invocation) (workflowsmoke.Result, bool) {
			return passedReport, routeIs(invocation, "spec-proof-bundle-admission") && inputValue(t, invocation, "/receiptAdmission/receipts/0/receiptKind") == "greeter.python-test" && !bindsCommand(t, invocation, "greeter.python-test")
		}},
		{"edited node linked", "edited farewell command bundle exit=0", func(t *testing.T, invocation workflowsmoke.Invocation) (workflowsmoke.Result, bool) {
			return passedReport, routeIs(invocation, "spec-proof-bundle-admission") && plansArgument(t, invocation, "-count=1")
		}},
		{"stale review accepted", "stale review assessment must be refused", func(t *testing.T, invocation workflowsmoke.Invocation) (workflowsmoke.Result, bool) {
			return passedReport, routeIs(invocation, "change plan") && inputValue(t, invocation, "/checkpoint/state") == "review_passed"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertTrajectoryMutant(t, test.want, func(ctx context.Context, invocation workflowsmoke.Invocation) (workflowsmoke.Result, bool, error) {
				result, matched := test.mutate(t, invocation)
				return result, matched, nil
			})
		})
	}
	t.Run("stale identity accepted", func(t *testing.T) {
		t.Parallel()
		// The first apply of a changed packet reuses the identities reviewed
		// for the previous packet; the reviewed apply of that packet follows.
		seen := map[string]bool{}
		assertTrajectoryMutant(t, "stale identity apply exit=0", func(ctx context.Context, invocation workflowsmoke.Invocation) (workflowsmoke.Result, bool, error) {
			if !routeIs(invocation, "adopt materialize apply") || expectedTransaction(invocation) == "" || seen[string(invocation.Input)] {
				return workflowsmoke.Result{}, false, nil
			}
			seen[string(invocation.Input)] = true
			if len(seen) == 1 {
				return workflowsmoke.Result{}, false, nil
			}
			return passedReport, true, nil
		})
	})
}

// Invalidation mutants keep every output well formed but change the verdict.
func TestVerifyTrajectoryRejectsWrongInvalidation(t *testing.T) {
	for _, test := range []struct {
		name   string
		want   string
		mutate func(*testing.T, workflowsmoke.Invocation) (workflowsmoke.Invocation, bool)
	}{
		{"currentness ignores changed subjects", "forged subject failed obligations", func(t *testing.T, invocation workflowsmoke.Invocation) (workflowsmoke.Invocation, bool) {
			return rewriteChecks(t, invocation, func(check map[string]any) { check["currentDigest"] = check["recordedDigest"] })
		}},
		{"currentness ignores native test bytes", "whitespace witness extension stale findings", func(t *testing.T, invocation workflowsmoke.Invocation) (workflowsmoke.Invocation, bool) {
			return rewriteChecks(t, invocation, func(check map[string]any) {
				if check["checkId"] == "greeter.check.dependency" {
					check["currentDigest"] = check["recordedDigest"]
				}
			})
		}},
		{"currentness invalidates unrelated edges", "forged subject failed obligations", func(t *testing.T, invocation workflowsmoke.Invocation) (workflowsmoke.Invocation, bool) {
			record := decodeInput(t, invocation)
			if !routeIs(invocation, "receipt-currentness-scope") || !anyStaleCheck(record) {
				return invocation, false
			}
			return rewriteChecks(t, invocation, func(check map[string]any) {
				if check["checkId"] == "greeter.check.selectors" {
					check["currentDigest"] = "sha256:" + strings.Repeat("0", 64)
				}
			})
		}},
		// Linking by plan and command ID alone would let the farewell receipt
		// link to an edited farewell command under the same plan ID.
		{"bundle links receipts by plan and command ID only", "edited farewell command bundle exit=0", func(t *testing.T, invocation workflowsmoke.Invocation) (workflowsmoke.Invocation, bool) {
			if !routeIs(invocation, "spec-proof-bundle-admission") || invocation.StdinClass != workflowsmoke.StdinBytes {
				return invocation, false
			}
			return rewriteInput(t, invocation, func(record map[string]any) {
				projection, _, _, err := witnessschedulerplan.Evaluate(record["witnessPlan"])
				if err != nil {
					t.Fatal(err)
				}
				nodeDigests := map[string]string{}
				for _, command := range projection.Commands {
					nodeDigests[command.ID] = command.ProofNodeDigest
				}
				receipts, _ := record["receiptAdmission"].(map[string]any)["receipts"].([]any)
				for _, receipt := range receipts {
					row := receipt.(map[string]any)
					if nodeDigest, ok := nodeDigests[row["receiptKind"].(string)]; ok {
						row["proofNodeDigest"] = nodeDigest
					}
				}
			})
		}},
		// Binding receipts to the whole plan would unlink the unaffected
		// farewell receipt as soon as the migration changes another node.
		{"bundle binds receipts to the whole plan", "python evidence after migration", wholePlanLinkage()},
		{"semantic diff misses requirement changes", "requirement change diff", func(t *testing.T, invocation workflowsmoke.Invocation) (workflowsmoke.Invocation, bool) {
			if !routeIs(invocation, "requirement-semantic-diff") || invocation.StdinClass != workflowsmoke.StdinBytes {
				return invocation, false
			}
			return rewriteInput(t, invocation, func(record map[string]any) { record["baseContext"] = record["currentContext"] })
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertTrajectoryMutant(t, test.want, func(ctx context.Context, invocation workflowsmoke.Invocation) (workflowsmoke.Result, bool, error) {
				mutated, matched := test.mutate(t, invocation)
				if !matched {
					return workflowsmoke.Result{}, false, nil
				}
				result, err := applicationRunner(ctx, mutated)
				return result, true, err
			})
		})
	}
}

// Prompt mutants remove one CLI-named continuation; the route ledger must
// then refuse to execute the unnamed route.
func TestVerifyTrajectoryRequiresCLINamedRoutes(t *testing.T) {
	for _, test := range []struct{ name, help, drop, want string }{
		{"scheduler guide loses witness projection", "witness-scheduler-plan --help", " witness-plan --input ", `does not name the next route "witness-plan"`},
		{"next help loses verification continuation", "next --help", " native-evidence-guidance --help", "next help does not continue run_repository_verification"},
		{"cookbook loses semantic diff", "native-evidence-guidance --help", " requirement-semantic-diff --help", `does not name the next route "requirement-semantic-diff"`},
		{"context guide loses slice", "requirement-context-compose --help", " requirement-context-slice --help", `does not name the next route "requirement-context-slice"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertTrajectoryMutant(t, test.want, func(ctx context.Context, invocation workflowsmoke.Invocation) (workflowsmoke.Result, bool, error) {
				if strings.Join(invocation.Args, " ") != test.help {
					return workflowsmoke.Result{}, false, nil
				}
				result, err := applicationRunner(ctx, invocation)
				lines := []string{}
				for _, line := range strings.Split(string(result.Stdout), "\n") {
					if !strings.Contains(line, test.drop) {
						lines = append(lines, line)
					}
				}
				result.Stdout = []byte(strings.Join(lines, "\n"))
				return result, true, err
			})
		})
	}
}

func assertTrajectoryMutant(t *testing.T, want string, mutate func(context.Context, workflowsmoke.Invocation) (workflowsmoke.Result, bool, error)) {
	t.Helper()
	var mu sync.Mutex
	applied := 0
	err := workflowsmoke.VerifyTrajectory(t.Context(), func(ctx context.Context, invocation workflowsmoke.Invocation) (workflowsmoke.Result, error) {
		result, matched, err := mutate(ctx, invocation)
		if matched {
			mu.Lock()
			applied++
			mu.Unlock()
			return result, err
		}
		return applicationRunner(ctx, invocation)
	})
	if applied == 0 {
		t.Fatal("mutant route was not exercised")
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("mutant error = %v, want %q", err, want)
	}
}

func routeIs(invocation workflowsmoke.Invocation, route string) bool {
	return strings.HasPrefix(strings.Join(invocation.Args, " ")+" ", route+" ") && !slices.Contains(invocation.Args, "--help")
}

func decodeInput(t *testing.T, invocation workflowsmoke.Invocation) map[string]any {
	t.Helper()
	if invocation.StdinClass != workflowsmoke.StdinBytes || len(invocation.Input) == 0 {
		return nil
	}
	value, err := admission.DecodeJSON(bytes.NewReader(invocation.Input), int64(len(invocation.Input)))
	if err != nil {
		t.Fatalf("trajectory input must be strict JSON: %v", err)
	}
	record, _ := value.(map[string]any)
	return record
}

func inputValue(t *testing.T, invocation workflowsmoke.Invocation, pointer string) any {
	t.Helper()
	var value any = decodeInput(t, invocation)
	for _, segment := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		switch typed := value.(type) {
		case map[string]any:
			value = typed[segment]
		case []any:
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(typed) {
				return nil
			}
			value = typed[index]
		default:
			return nil
		}
	}
	return value
}

func expectedTransaction(invocation workflowsmoke.Invocation) string {
	index := slices.Index(invocation.Args, "--expect-transaction")
	if index < 0 || index+1 >= len(invocation.Args) {
		return ""
	}
	return invocation.Args[index+1]
}

func anyStaleCheck(record map[string]any) bool {
	obligations, _ := record["obligationReceipts"].([]any)
	for _, obligation := range obligations {
		for _, check := range obligation.(map[string]any)["currentnessChecks"].([]any) {
			if values := check.(map[string]any); values["currentDigest"] != values["recordedDigest"] {
				return true
			}
		}
	}
	return false
}

func bindsCommand(t *testing.T, invocation workflowsmoke.Invocation, commandID string) bool {
	commands, _ := inputValue(t, invocation, "/requirementBindings/witnessCommands").([]any)
	for _, command := range commands {
		if record, ok := command.(map[string]any); ok && record["commandId"] == commandID {
			return true
		}
	}
	return false
}

func rewriteChecks(t *testing.T, invocation workflowsmoke.Invocation, edit func(map[string]any)) (workflowsmoke.Invocation, bool) {
	if !routeIs(invocation, "receipt-currentness-scope") || invocation.StdinClass != workflowsmoke.StdinBytes {
		return invocation, false
	}
	return rewriteInput(t, invocation, func(record map[string]any) {
		for _, obligation := range record["obligationReceipts"].([]any) {
			for _, check := range obligation.(map[string]any)["currentnessChecks"].([]any) {
				edit(check.(map[string]any))
			}
		}
	})
}

// plansArgument reports whether a bundle's witness plan gives some command
// the argv token argument.
func plansArgument(t *testing.T, invocation workflowsmoke.Invocation, argument string) bool {
	commands, _ := inputValue(t, invocation, "/witnessPlan/commands").([]any)
	for _, command := range commands {
		if argv, _ := command.(map[string]any)["argv"].([]any); slices.Contains(argv, any(argument)) {
			return true
		}
	}
	return false
}

// wholePlanLinkage rewrites bundle inputs as if linkage bound each receipt to
// the whole plan it was first bundled with: bundled again with different plan
// content, the receipt no longer carries a matching node digest.
func wholePlanLinkage() func(*testing.T, workflowsmoke.Invocation) (workflowsmoke.Invocation, bool) {
	var mu sync.Mutex
	firstPlans := map[string]string{}
	return func(t *testing.T, invocation workflowsmoke.Invocation) (workflowsmoke.Invocation, bool) {
		if !routeIs(invocation, "spec-proof-bundle-admission") || invocation.StdinClass != workflowsmoke.StdinBytes {
			return invocation, false
		}
		return rewriteInput(t, invocation, func(record map[string]any) {
			plan, err := stablejson.Marshal(record["witnessPlan"])
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			receipts, _ := record["receiptAdmission"].(map[string]any)["receipts"].([]any)
			for _, receipt := range receipts {
				row := receipt.(map[string]any)
				receiptID := row["receiptId"].(string)
				if first, seen := firstPlans[receiptID]; !seen {
					firstPlans[receiptID] = string(plan)
				} else if first != string(plan) {
					row["proofNodeDigest"] = "sha256:" + strings.Repeat("0", 64)
				}
			}
		})
	}
}

func rewriteInput(t *testing.T, invocation workflowsmoke.Invocation, edit func(map[string]any)) (workflowsmoke.Invocation, bool) {
	record := decodeInput(t, invocation)
	if record == nil {
		return invocation, false
	}
	edit(record)
	encoded, err := stablejson.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	invocation.Input = encoded
	return invocation, true
}
