package app

func usage() string {
	return "" +
		"Usage:\n" +
		"  agentic-proofkit adoption-checklist --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit adoption-contract-envelope --input <path|-> --mode adoption|bootstrap|guidance|pilot|workflow [--agent-envelope] [--materialization-manifest] [--pilot first|stack-diverse|all] [--guidance-mode <mode>] [--checked-scope <scope>] [--touched-rule-id <id>]\n" +
		"  agentic-proofkit adoption-doctor --input <path|-> [--input-pointer <pointer>] [--agent-envelope]\n" +
		"  agentic-proofkit adoption-workflow-plan --input <path|-> [--input-pointer <pointer>] [--contract-envelope] [--agent-envelope]\n" +
		"  agentic-proofkit agent-route --input <path|-> [--input-pointer <pointer>] [--agent-envelope]\n" +
		"  agentic-proofkit binding-partition --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit branch-authority --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit changed-path-set --input <path|-> [--input-pointer <pointer>] [--agent-envelope]\n" +
		"  agentic-proofkit completion-criteria --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit conformance-profile --input <path|-> [--input-pointer <pointer>] (--verify|--list|--profile <id>) [--format json|markdown]\n" +
		"  agentic-proofkit custom-rule-boundary --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit deployment-evidence-admission --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit document-lifecycle-boundary --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit evidence-graph --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit external-consumer --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit gradual-adoption --input <path|-> [--input-pointer <pointer>] [--contract-envelope]\n" +
		"  agentic-proofkit gradual-adoption-bootstrap --input <path|-> [--input-pointer <pointer>] [--contract-envelope] [--agent-envelope] [--materialization-manifest]\n" +
		"  agentic-proofkit gradual-adoption-guidance --input <path|-> [--input-pointer <pointer>] [--contract-envelope] [--agent-envelope] [--guidance-mode <mode>] [--checked-scope <scope>] [--touched-rule-id <id>]\n" +
		"  agentic-proofkit help [-h|--help]\n" +
		"  agentic-proofkit impact --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit json-report-cli-adapter-source --language typescript [--format json]\n" +
		"  agentic-proofkit migration-parity-admission --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit migration-plan --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit obligation-decision --input <path|-> [--input-pointer <pointer>] [--agent-envelope]\n" +
		"  agentic-proofkit package-runtime-dependency-admission --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit pilot-admission --input <path|-> [--input-pointer <pointer>] [--stack-diverse|--pilot <first|stack-diverse|all>] [--contract-envelope]\n" +
		"  agentic-proofkit proof-obligation-algebra --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit producer-policy-self-proof --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit proof-receipt-admission --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit proof-slice --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit typescript-public-api-surfaces --input <path|-> [--input-pointer <pointer>] --repo-root <path>\n" +
		"  agentic-proofkit readiness-closeout --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit receipt-currentness-scope --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit receipt-producer-admission --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit receipt-trust-class --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit registry-consumer --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit registry-consumer-proof-input-compose --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit rendered-artifact-freshness --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit release-authority --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit repo-profile-admission --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit requirement-authoring-plan --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit requirement-bindings --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit requirement-browser-server --input <path|-> [--input-pointer <pointer>] --view source|proof|coverage|spec-tree [--serve] [--host 127.0.0.1|::1] [--port <port>] [--open] [--scope graph|slice] [--local-environment-class <id>|--empty-local-environment-policy]\n" +
		"  agentic-proofkit requirement-coverage-input-compose --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit requirement-coverage-view --input <path|-> [--input-pointer <pointer>] [--format json|markdown|html] [--agent-envelope]\n" +
		"  agentic-proofkit requirement-impact-input-compose --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit requirement-proof-resolver --input <path|-> [--input-pointer <pointer>] [--local-environment-class <id>|--empty-local-environment-policy]\n" +
		"  agentic-proofkit requirement-proof-source-set --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit requirement-proof-view --input <path|-> [--input-pointer <pointer>] [--scope graph|slice] [--format json|markdown|html] [--local-environment-class <id>|--empty-local-environment-policy]\n" +
		"  agentic-proofkit requirement-source-admission --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit requirement-spec-tree --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit requirement-spec-tree-view --input <path|-> [--input-pointer <pointer>] [--format json|markdown|html] [--output <path>]\n" +
		"  agentic-proofkit requirement-source-transition --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit requirement-source-view --input <path|-> [--input-pointer <pointer>] [--format json|markdown|html]\n" +
		"  agentic-proofkit scaffold-project-structure --input <path|-> [--input-pointer <pointer>] [--agent-envelope]\n" +
		"  agentic-proofkit scaffold-profile-plan --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit selective-gate-evidence --input <path|-> [--input-pointer <pointer>] [--agent-envelope]\n" +
		"  agentic-proofkit selective-gate-obligation-decision-input --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit selective-gate-plan --input <path|-> [--input-pointer <pointer>] [--agent-envelope]\n" +
		"  agentic-proofkit spec-overview-claims --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit spec-proof-bundle-admission --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit stack-preset --preset <id>\n" +
		"  agentic-proofkit test-evidence-inventory --input <path|-> [--input-pointer <pointer>] [--projection proof-binding-derived] [--normalized-inventory]\n" +
		"  agentic-proofkit text-policy --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit witness-plan --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit witness-scheduler-plan --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit workspace-changed-package-plan --input <path|-> [--input-pointer <pointer>] [--agent-envelope]\n" +
		"  agentic-proofkit workspace-manifest-facts --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit workspace-shard-partition --input <path|-> [--input-pointer <pointer>] [--agent-envelope]\n" +
		"  agentic-proofkit workspace-registry --input <path|-> [--input-pointer <pointer>]\n" +
		"  agentic-proofkit self-check --input <path|->\n" +
		"\n" +
		"The Go runtime is the primary CLI implementation. CLI/JSON is the public cross-language contract.\n"
}
