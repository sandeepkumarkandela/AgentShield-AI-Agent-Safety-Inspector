import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * The action module runs immediately on import (top-level `run().catch(...)`),
 * so we can't import it directly without mocking process.env and process.exitCode.
 *
 * Instead, we test the helper functions by extracting them via a dynamic import
 * pattern, or test the module's observable behavior.
 *
 * For now, we test the escapeAnnotation pattern and the severity helpers
 * by recreating them (since they're not exported).
 */

// Recreate the helpers to test their logic (mirrors action.ts implementation)
function escapeAnnotation(message: string): string {
  return message
    .replace(/%/g, "%25")
    .replace(/\r/g, "%0D")
    .replace(/\n/g, "%0A");
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const ACTION_PATH = resolve(process.cwd(), "dist/action.js");

function severityIndex(severity: string): number {
  const idx = SEVERITY_ORDER.indexOf(severity as typeof SEVERITY_ORDER[number]);
  return idx === -1 ? SEVERITY_ORDER.length : idx;
}

function isAtOrAboveSeverity(severity: string, minSeverity: string): boolean {
  return severityIndex(severity) <= severityIndex(minSeverity);
}

describe("action helpers (logic verification)", () => {
  it("uses the current GitHub JavaScript action runtime", () => {
    const actionYaml = readFileSync(resolve(process.cwd(), "action.yml"), "utf-8");

    expect(actionYaml).toContain('using: "node24"');
    expect(actionYaml).not.toContain('using: "node20"');
  });

  it("documents organization policy inputs and outputs in action.yml", () => {
    const actionYaml = readFileSync(resolve(process.cwd(), "action.yml"), "utf-8");

    expect(actionYaml).toContain("policy:");
    expect(actionYaml).toContain("fail-on-policy:");
    expect(actionYaml).toContain("policy-status:");
    expect(actionYaml).toContain("policy-violations:");
  });

  it("documents baseline drift inputs and outputs in action.yml", () => {
    const actionYaml = readFileSync(resolve(process.cwd(), "action.yml"), "utf-8");

    expect(actionYaml).toContain("baseline:");
    expect(actionYaml).toContain("save-baseline:");
    expect(actionYaml).toContain("baseline-path:");
    expect(actionYaml).toContain("baseline-status:");
    expect(actionYaml).toContain("new-findings:");
    expect(actionYaml).toContain("resolved-findings:");
    expect(actionYaml).toContain("unchanged-findings:");
    expect(actionYaml).toContain("score-delta:");
  });

  it("documents evidence-pack inputs and outputs in action.yml", () => {
    const actionYaml = readFileSync(resolve(process.cwd(), "action.yml"), "utf-8");

    expect(actionYaml).toContain("evidence-pack:");
    expect(actionYaml).toContain("verify-evidence-pack:");
    expect(actionYaml).toContain("evidence-pack-path:");
    expect(actionYaml).toContain("evidence-pack-status:");
    expect(actionYaml).toContain("evidence-pack-digest:");
    expect(actionYaml).toContain('default: "true"');
  });

  it("documents supply-chain gate inputs and outputs in action.yml", () => {
    const actionYaml = readFileSync(resolve(process.cwd(), "action.yml"), "utf-8");

    expect(actionYaml).toContain("supply-chain:");
    expect(actionYaml).toContain("supply-chain-online:");
    expect(actionYaml).toContain("fail-on-supply-chain:");
    expect(actionYaml).toContain("supply-chain-status:");
    expect(actionYaml).toContain("supply-chain-risky-packages:");
    expect(actionYaml).toContain("supply-chain-critical-count:");
    expect(actionYaml).toContain("supply-chain-high-count:");
  });

  it("documents package-manager hardening outputs in action.yml", () => {
    const actionYaml = readFileSync(resolve(process.cwd(), "action.yml"), "utf-8");

    expect(actionYaml).toContain("package-manager-hardening-status:");
    expect(actionYaml).toContain("package-manager-hardening-findings:");
    expect(actionYaml).toContain("package-manager-hardening-critical-count:");
    expect(actionYaml).toContain("package-manager-hardening-high-count:");
    expect(actionYaml).toContain("package-manager-hardening-registry-credentials:");
    expect(actionYaml).toContain("package-manager-hardening-lifecycle-scripts:");
    expect(actionYaml).toContain("package-manager-hardening-release-age-gates:");
  });

  it("documents policy promotion inputs and outputs in action.yml", () => {
    const actionYaml = readFileSync(resolve(process.cwd(), "action.yml"), "utf-8");

    expect(actionYaml).toContain("policy-promotion-manifest:");
    expect(actionYaml).toContain("policy-promotion-pack:");
    expect(actionYaml).toContain("policy-promotion-output:");
    expect(actionYaml).toContain("policy-promotion-dry-run:");
    expect(actionYaml).toContain("fail-on-policy-promotion:");
    expect(actionYaml).toContain("policy-promotion-status:");
    expect(actionYaml).toContain("policy-promotion-review-items:");
    expect(actionYaml).toContain("policy-promotion-action-required-count:");
    expect(actionYaml).toContain("policy-promotion-digest:");
  });

  it("writes and verifies an evidence pack when requested", () => {
    const workspace = mkdtempSync(join(tmpdir(), "agentshield-action-workspace-"));
    const outputFile = join(workspace, "github-output.txt");
    const summaryFile = join(workspace, "github-summary.md");
    const evidencePackPath = "agentshield-evidence";

    writeFileSync(join(workspace, "README.md"), "# Fixture\n");

    const result = spawnSync(process.execPath, [ACTION_PATH], {
      cwd: workspace,
      env: {
        ...process.env,
        GITHUB_WORKSPACE: workspace,
        GITHUB_OUTPUT: outputFile,
        GITHUB_STEP_SUMMARY: summaryFile,
        INPUT_PATH: ".",
        "INPUT_FAIL-ON-FINDINGS": "false",
        "INPUT_EVIDENCE-PACK": evidencePackPath,
      },
      encoding: "utf-8",
    });

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain("Evidence pack verification: PASSED");

    const evidenceDir = join(workspace, evidencePackPath);
    expect(existsSync(join(evidenceDir, "manifest.json"))).toBe(true);
    expect(existsSync(join(evidenceDir, "agentshield-report.json"))).toBe(true);

    const outputs = readFileSync(outputFile, "utf-8");
    expect(outputs).toContain(`evidence-pack-path=${evidenceDir}`);
    expect(outputs).toContain("evidence-pack-status=passed");
    expect(outputs).toMatch(/evidence-pack-digest=sha256:[a-f0-9]{64}/);
    expect(outputs).toContain("supply-chain-status=clean");
    expect(outputs).toContain("package-manager-hardening-status=hardened");
  });

  it("emits package-manager hardening outputs and job summary evidence", () => {
    const workspace = mkdtempSync(join(tmpdir(), "agentshield-action-hardening-"));
    const outputFile = join(workspace, "github-output.txt");
    const summaryFile = join(workspace, "github-summary.md");

    writeFileSync(join(workspace, ".npmrc"), [
      "ignore-scripts=false",
      "minimum-release-age=60",
      "",
    ].join("\n"));

    const result = spawnSync(process.execPath, [ACTION_PATH], {
      cwd: workspace,
      env: {
        ...process.env,
        GITHUB_WORKSPACE: workspace,
        GITHUB_OUTPUT: outputFile,
        GITHUB_STEP_SUMMARY: summaryFile,
        INPUT_PATH: ".",
        "INPUT_FAIL-ON-FINDINGS": "false",
      },
      encoding: "utf-8",
    });

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");

    const outputs = readFileSync(outputFile, "utf-8");
    expect(outputs).toContain("package-manager-hardening-status=needs-review");
    expect(outputs).toContain("package-manager-hardening-findings=2");
    expect(outputs).toContain("package-manager-hardening-high-count=1");
    expect(outputs).toContain("package-manager-hardening-lifecycle-scripts=1");
    expect(outputs).toContain("package-manager-hardening-release-age-gates=1");

    const summary = readFileSync(summaryFile, "utf-8");
    expect(summary).toContain("## AgentShield Package Manager Hardening");
    expect(summary).toContain("- Status: needs-review");
    expect(summary).toContain("package-manager-lifecycle-scripts-enabled");
    expect(summary).toContain("package-manager-npm-release-age-gate-unsupported");
  });

  it("emits policy promotion review-item outputs and runtime smoke summary", () => {
    const workspace = mkdtempSync(join(tmpdir(), "agentshield-action-promotion-"));
    const outputFile = join(workspace, "github-output.txt");
    const summaryFile = join(workspace, "github-summary.md");
    const policiesDir = join(workspace, ".github", "agentshield-policies");

    mkdirSync(join(workspace, ".claude"), { recursive: true });
    writeFileSync(join(workspace, ".claude", "settings.json"), JSON.stringify({
      permissions: {
        deny: ["Bash(rm -rf *)"],
      },
    }, null, 2));

    const exportResult = spawnSync(process.execPath, [
      resolve(process.cwd(), "dist/index.js"),
      "policy",
      "export",
      "--output-dir",
      policiesDir,
      "--pack",
      "ci-enforcement",
      "--owner",
      "security@example.com",
    ], {
      cwd: workspace,
      env: {
        ...process.env,
        NODE_NO_WARNINGS: "1",
      },
      encoding: "utf-8",
    });
    expect(exportResult.status).toBe(0);
    expect(exportResult.stderr).toBe("");

    const activePolicy = join(workspace, ".agentshield", "policy.json");
    const result = spawnSync(process.execPath, [ACTION_PATH], {
      cwd: workspace,
      env: {
        ...process.env,
        GITHUB_WORKSPACE: workspace,
        GITHUB_OUTPUT: outputFile,
        GITHUB_STEP_SUMMARY: summaryFile,
        INPUT_PATH: ".",
        "INPUT_FAIL-ON-FINDINGS": "false",
        "INPUT_POLICY-PROMOTION-MANIFEST": join(policiesDir, "manifest.json"),
        "INPUT_POLICY-PROMOTION-PACK": "ci-enforcement",
        "INPUT_POLICY-PROMOTION-OUTPUT": activePolicy,
        "INPUT_POLICY-PROMOTION-DRY-RUN": "false",
        INPUT_POLICY: activePolicy,
        "INPUT_FAIL-ON-POLICY": "false",
      },
      encoding: "utf-8",
    });

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");

    const outputs = readFileSync(outputFile, "utf-8");
    expect(outputs).toContain("policy-promotion-status=verified");
    expect(outputs).toContain("policy-promotion-review-items=4");
    expect(outputs).toContain("policy-promotion-action-required-count=0");
    expect(outputs).toMatch(/policy-promotion-digest=sha256:[a-f0-9]{64}/);
    expect(outputs).toContain("policy-status=");

    const summary = readFileSync(summaryFile, "utf-8");
    expect(summary).toContain("## AgentShield Policy Promotion");
    expect(summary).toContain("- Status: verified");
    expect(summary).toContain("runtime-smoke-test");
    expect(summary).toContain("Runtime smoke scan completed against");
    expect(summary).toContain(activePolicy);
  });

  it("fails by default when MCP supply-chain verification finds a compromised package", () => {
    const workspace = mkdtempSync(join(tmpdir(), "agentshield-action-supply-chain-"));
    const outputFile = join(workspace, "github-output.txt");
    const summaryFile = join(workspace, "github-summary.md");
    const claudeDir = join(workspace, ".claude");
    const settingsPath = join(claudeDir, "settings.json");

    mkdirSync(claudeDir, { recursive: true });
    writeFileSync(settingsPath, JSON.stringify({
      mcpServers: {
        router: {
          command: "npx",
          args: ["@tanstack/react-router@1.169.8"],
        },
      },
    }, null, 2));

    const result = spawnSync(process.execPath, [ACTION_PATH], {
      cwd: workspace,
      env: {
        ...process.env,
        GITHUB_WORKSPACE: workspace,
        GITHUB_OUTPUT: outputFile,
        GITHUB_STEP_SUMMARY: summaryFile,
        INPUT_PATH: ".",
      },
      encoding: "utf-8",
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain("Supply Chain Verification Report");
    expect(result.stdout).toContain("@tanstack/react-router@1.169.8");
    expect(result.stdout).toContain("AgentShield supply-chain gate FAILED");

    const outputs = readFileSync(outputFile, "utf-8");
    expect(outputs).toContain("supply-chain-status=risky");
    expect(outputs).toContain("supply-chain-risky-packages=1");
    expect(outputs).toContain("supply-chain-critical-count=1");

    const summary = readFileSync(summaryFile, "utf-8");
    expect(summary).toContain("## AgentShield Supply Chain");
    expect(summary).toContain("@tanstack/react-router@1.169.8");
  });

  it("collects supply-chain evidence without failing when findings gate is disabled", () => {
    const workspace = mkdtempSync(join(tmpdir(), "agentshield-action-supply-chain-collect-"));
    const outputFile = join(workspace, "github-output.txt");
    const summaryFile = join(workspace, "github-summary.md");
    const claudeDir = join(workspace, ".claude");
    const settingsPath = join(claudeDir, "settings.json");

    mkdirSync(claudeDir, { recursive: true });
    writeFileSync(settingsPath, JSON.stringify({
      mcpServers: {
        router: {
          command: "npx",
          args: ["@tanstack/react-router@1.169.8"],
        },
      },
    }, null, 2));

    const result = spawnSync(process.execPath, [ACTION_PATH], {
      cwd: workspace,
      env: {
        ...process.env,
        GITHUB_WORKSPACE: workspace,
        GITHUB_OUTPUT: outputFile,
        GITHUB_STEP_SUMMARY: summaryFile,
        INPUT_PATH: ".",
        "INPUT_FAIL-ON-FINDINGS": "false",
      },
      encoding: "utf-8",
    });

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain("Supply Chain Verification Report");
    expect(result.stdout).not.toContain("AgentShield supply-chain gate FAILED");

    const outputs = readFileSync(outputFile, "utf-8");
    expect(outputs).toContain("supply-chain-status=risky");
    expect(outputs).toContain("supply-chain-critical-count=1");
  });

  describe("escapeAnnotation", () => {
    it("escapes percent signs", () => {
      expect(escapeAnnotation("100%")).toBe("100%25");
    });

    it("escapes newlines", () => {
      expect(escapeAnnotation("line1\nline2")).toBe("line1%0Aline2");
    });

    it("escapes carriage returns", () => {
      expect(escapeAnnotation("line1\rline2")).toBe("line1%0Dline2");
    });

    it("escapes combined special chars", () => {
      expect(escapeAnnotation("100%\r\n")).toBe("100%25%0D%0A");
    });

    it("passes through plain text", () => {
      expect(escapeAnnotation("hello world")).toBe("hello world");
    });
  });

  describe("severityIndex", () => {
    it("returns 0 for critical", () => {
      expect(severityIndex("critical")).toBe(0);
    });

    it("returns 4 for info", () => {
      expect(severityIndex("info")).toBe(4);
    });

    it("returns length for unknown severity", () => {
      expect(severityIndex("unknown")).toBe(SEVERITY_ORDER.length);
    });
  });

  describe("isAtOrAboveSeverity", () => {
    it("critical is at or above medium", () => {
      expect(isAtOrAboveSeverity("critical", "medium")).toBe(true);
    });

    it("high is at or above medium", () => {
      expect(isAtOrAboveSeverity("high", "medium")).toBe(true);
    });

    it("medium is at or above medium", () => {
      expect(isAtOrAboveSeverity("medium", "medium")).toBe(true);
    });

    it("low is NOT at or above medium", () => {
      expect(isAtOrAboveSeverity("low", "medium")).toBe(false);
    });

    it("info is NOT at or above medium", () => {
      expect(isAtOrAboveSeverity("info", "medium")).toBe(false);
    });

    it("critical is at or above critical", () => {
      expect(isAtOrAboveSeverity("critical", "critical")).toBe(true);
    });
  });
});
