import {redactDiagnosticValue} from "./stable-json.mjs";

export async function runDiagnosticEntrypoint(operation, stderr = process.stderr) {
  try {
    await operation();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    stderr.write(`${redactDiagnosticValue(message)}\n`);
    process.exitCode = 1;
  }
}
