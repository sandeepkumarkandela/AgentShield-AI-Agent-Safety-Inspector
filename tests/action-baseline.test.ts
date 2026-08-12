import { describe, expect, it } from "vitest";
import {
  renderBaselineJobSummary,
  renderMissingBaselineJobSummary,
  statusForBaselineGate,
} from "../src/action-baseline.js";
import type { BaselineComparison, GateResult } from "../src/baseline/index.js";
import type { Finding } from "../src/types.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "permissions-wildcard",
    severity: "high",
    category: "permissions",
    title: "Wildcard permission",
    description: "Wildcard permission is unsafe",
    file: ".claude/settings.json",
    evidence: "Bash(*)",
    ...overrides,
  };
}

function makeComparison(
  overrides: Partial<BaselineComparison> = {}
): BaselineComparison {
  return {
    timestamp: "2026-05-12T12:00:00.000Z",
    baselineTimestamp: "2026-05-11T12:00:00.000Z",
    newFindings: [makeFinding()],
    resolvedFindings: [
      {
        id: "old-rule",
        severity: "medium",
        category: "hooks",
        title: "Old hook issue",
        file: ".claude/settings.json",
        evidence: "2>/dev/null",
        fingerprint: "old-rule::.claude/settings.json::2>/dev/null",
      },
    ],
    unchangedCount: 3,
    scoreDelta: -6,
    baselineScore: 90,
    currentScore: 84,
    isRegression: true,
    newCriticalCount: 0,
    newHighCount: 1,
    ...overrides,
  };
}

function makeGateResult(overrides: Partial<GateResult> = {}): GateResult {
  const comparison = makeComparison();
  return {
    passed: false,
    reasons: ["1 new high finding(s) introduced"],
    comparison,
    ...overrides,
  };
}

describe("action baseline helpers", () => {
  it("reports passed or failed baseline status from the gate result", () => {
    expect(statusForBaselineGate(makeGateResult({ passed: true }))).toBe(
      "passed"
    );
    expect(statusForBaselineGate(makeGateResult({ passed: false }))).toBe(
      "failed"
    );
  });

  it("renders baseline drift details for the GitHub Actions job summary", () => {
    const comparison = makeComparison();
    const output = renderBaselineJobSummary(comparison, makeGateResult());

    expect(output).toContain("## AgentShield Baseline Drift");
    expect(output).toContain("- Status: failed");
    expect(output).toContain("- Score: 90 -> 84 (-6)");
    expect(output).toContain("- New findings: 1");
    expect(output).toContain("- Resolved findings: 1");
    expect(output).toContain("- Unchanged findings: 3");
    expect(output).toContain("### Gate Reasons");
    expect(output).toContain("1 new high finding(s) introduced");
    expect(output).toContain("Wildcard permission");
    expect(output).toContain("Old hook issue");
  });

  it("renders a missing-baseline summary", () => {
    const output = renderMissingBaselineJobSummary("security/baseline.json");

    expect(output).toContain("## AgentShield Baseline Drift");
    expect(output).toContain("- Status: missing");
    expect(output).toContain("- Baseline path: security/baseline.json");
    expect(output).toContain("Comparison skipped");
  });
});
