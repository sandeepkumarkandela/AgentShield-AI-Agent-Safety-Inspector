import { describe, expect, it } from "vitest";
import {
  renderPackageManagerHardeningJobSummary,
  summarizePackageManagerHardening,
} from "../src/action-hardening.js";
import type { Finding } from "../src/types.js";

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "package-manager-lifecycle-scripts-enabled",
    severity: "high",
    category: "misconfiguration",
    title: "Package lifecycle scripts are explicitly enabled",
    description: "Lifecycle scripts are enabled.",
    file: ".npmrc",
    ...overrides,
  };
}

describe("action package-manager hardening helpers", () => {
  it("reports hardened status when no package-manager findings are present", () => {
    const summary = summarizePackageManagerHardening([
      finding({
        id: "hooks-command-injection",
        category: "hooks",
      }),
    ]);

    expect(summary.status).toBe("hardened");
    expect(summary.totalFindings).toBe(0);
  });

  it("summarizes package-manager finding classes for CI routing", () => {
    const summary = summarizePackageManagerHardening([
      finding({
        id: "package-manager-registry-credential-2",
        severity: "critical",
        category: "secrets",
      }),
      finding({
        id: "package-manager-lifecycle-scripts-enabled",
        severity: "high",
      }),
      finding({
        id: "package-manager-pnpm-strict-dep-builds-disabled",
        severity: "medium",
      }),
      finding({
        id: "package-manager-npm-release-age-gate-unsupported",
        severity: "medium",
      }),
    ]);

    expect(summary.status).toBe("needs-review");
    expect(summary.totalFindings).toBe(4);
    expect(summary.criticalCount).toBe(1);
    expect(summary.highCount).toBe(1);
    expect(summary.registryCredentialCount).toBe(1);
    expect(summary.lifecycleScriptCount).toBe(2);
    expect(summary.releaseAgeGateCount).toBe(1);
  });

  it("renders job-summary evidence without including finding evidence values", () => {
    const summary = summarizePackageManagerHardening([
      finding({
        id: "package-manager-registry-credential-2",
        severity: "critical",
        category: "secrets",
        title: "Plaintext package registry credential",
        evidence: "_authToken=secret-token",
      }),
    ]);

    const rendered = renderPackageManagerHardeningJobSummary(summary);

    expect(rendered).toContain("## AgentShield Package Manager Hardening");
    expect(rendered).toContain("- Status: needs-review");
    expect(rendered).toContain("- Registry credential findings: 1");
    expect(rendered).toContain("package-manager-registry-credential-2");
    expect(rendered).not.toContain("secret-token");
  });
});
