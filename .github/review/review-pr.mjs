import { execFileSync } from "node:child_process";
import { Agent, CursorAgentError } from "@cursor/sdk";

const pr = process.env.PR_NUMBER;
const apiKey = process.env.CURSOR_API_KEY;
const testResult = process.env.TEST_RESULT ?? "unknown";
const buildResult = process.env.BUILD_RESULT ?? "unknown";
const xcframeworkResult = process.env.XCFRAMEWORK_RESULT ?? "unknown";

if (!pr) {
  console.error("PR_NUMBER is required");
  process.exit(1);
}

function gh(args, input) {
  return execFileSync("gh", args, {
    encoding: "utf8",
    input,
    maxBuffer: 32 * 1024 * 1024,
  });
}

function post(body) {
  gh(["pr", "review", pr, "--comment", "--body-file", "-"], body);
}

const status = [
  `| Check | Result |`,
  `| --- | --- |`,
  `| Test (macOS) | ${testResult} |`,
  `| Build (iOS) | ${buildResult} |`,
  `| XCFramework | ${xcframeworkResult} |`,
].join("\n");

if (!apiKey) {
  post(
    [
      "## Code review",
      "",
      "The review agent did not run. Add a repository secret named `CURSOR_API_KEY` (a Cursor user or team service-account key) and re-run this job.",
      "",
      "### Checks",
      "",
      status,
    ].join("\n")
  );
  process.exit(0);
}

// The vendored C is thousands of lines and is not what a reviewer should read.
const diff = gh(["pr", "diff", pr, "--exclude", "Sources/CryptoPQC/**"]);
const clipped = diff.length > 120_000 ? `${diff.slice(0, 120_000)}\n\n[diff truncated]` : diff;

const prompt = `Review this pull request for SwiftyCryptoPQ, a Swift package implementing ML-KEM, ML-DSA, and X-Wing.

Rules:
- Read the diff. You may inspect the checked-out repository. Do not modify, create, or commit files.
- Report real defects: incorrect cryptography, secret handling, API breakage, and missing tests. Skip style nits.
- Lead with "Verdict: approve" or "Verdict: request changes".
- Then a short summary, then findings as bullets with file paths. If there are no findings, say so.

Checks already recorded for this pull request:
${status}

Diff:
${clipped}`;

try {
  const result = await Agent.prompt(prompt, {
    apiKey,
    model: { id: "composer-2.5" },
    local: { cwd: process.cwd() },
  });

  if (result.status === "error") {
    console.error("review run failed", result.id, result.error);
    post(`## Code review\n\nThe review agent failed while running (\`${result.id ?? "unknown"}\`).\n\n### Checks\n\n${status}`);
    process.exit(2);
  }

  const review = (result.result ?? "").trim() || "The review agent returned no text.";
  const body = ["## Code review", "", review.slice(0, 60_000), "", "### Checks", "", status].join("\n");
  post(body);
  console.log("posted review", result.id);
} catch (error) {
  if (error instanceof CursorAgentError) {
    console.error("review did not start:", error.message, "retryable=", error.isRetryable);
    post(`## Code review\n\nThe review agent did not start: ${error.message}\n\n### Checks\n\n${status}`);
    process.exit(1);
  }
  throw error;
}
