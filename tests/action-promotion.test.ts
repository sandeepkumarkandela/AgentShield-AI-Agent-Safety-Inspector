import { describe, expect, it } from "vitest";
import {
  renderPolicyPromotionJobSummary,
  summarizePolicyPromotion,
} from "../src/action-promotion.js";
import type { PolicyPackPromotionResult } from "../src/policy/index.js";

function promotion(overrides: Partial<PolicyPackPromotionResult> = {}): PolicyPackPromotionResult {
  return {
    manifestPath: ".github/agentshield-policies/manifest.json",
    sourceFile: ".github/agentshield-policies/enterprise-policy.json",
    outputPath: ".agentshield/policy.json",
    pack: "enterprise",
    policyName: "Acme Enterprise Policy",
    owners: ["security@example.com"],
    sha256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    verified: true,
    promoted: true,
    dryRun: false,
    reviewItems: [
      {
        id: "manifest-digest-verified",
        status: "verified",
        severity: "info",
        title: "Manifest digest verified",
        detail: "enterprise matched sha256.",
        evidencePaths: [
          ".github/agentshield-policies/manifest.json",
          ".github/agentshield-policies/enterprise-policy.json",
        ],
        recommendation: "Attach the manifest and exported policy to the policy promotion review.",
      },
      {
        id: "policy-owner-review",
        status: "verified",
        severity: "info",
        title: "Policy owner review",
        detail: "Owners: security@example.com.",
        evidencePaths: [".github/agentshield-policies/enterprise-policy.json"],
        recommendation: "Require one listed owner to approve the protected rollout PR.",
      },
      {
        id: "protected-rollout-pr",
        status: "verified",
        severity: "info",
        title: "Protected rollout path",
        detail: "Active policy written to .agentshield/policy.json.",
        evidencePaths: [
          ".github/agentshield-policies/manifest.json",
          ".github/agentshield-policies/enterprise-policy.json",
        ],
        recommendation: "Keep subsequent policy changes behind branch protection, CI, and owner approval.",
      },
      {
        id: "runtime-smoke-test",
        status: "action_required",
        severity: "medium",
        title: "Runtime smoke test",
        detail: "Promotion did not run a repository scan with .agentshield/policy.json.",
        evidencePaths: [".agentshield/policy.json"],
        recommendation: "Run agentshield scan --policy .agentshield/policy.json before enabling this policy as an enforcing CI gate.",
      },
    ],
    ...overrides,
  };
}

describe("action policy promotion helpers", () => {
  it("keeps promotion review items actionable when runtime smoke evidence is missing", () => {
    const summary = summarizePolicyPromotion(promotion());

    expect(summary.status).toBe("needs-review");
    expect(summary.totalReviewItems).toBe(4);
    expect(summary.actionRequiredCount).toBe(1);
    expect(summary.reviewItems).toEqual(expect.arrayContaining([
      expect.objectContaining({
        id: "runtime-smoke-test",
        status: "action_required",
      }),
    ]));
  });

  it("marks runtime smoke verified when the action scanned with the promoted policy", () => {
    const summary = summarizePolicyPromotion(promotion(), {
      runtimeSmoke: {
        policyPath: ".agentshield/policy.json",
        targetPath: ".",
        policyStatus: "compliant",
      },
    });

    expect(summary.status).toBe("verified");
    expect(summary.actionRequiredCount).toBe(0);
    expect(summary.reviewItems).toEqual(expect.arrayContaining([
      expect.objectContaining({
        id: "runtime-smoke-test",
        status: "verified",
        severity: "info",
        detail: "Runtime smoke scan completed against . with .agentshield/policy.json; policy status compliant.",
      }),
    ]));
  });

  it("renders owner-ready job-summary evidence without raw policy contents", () => {
    const summary = summarizePolicyPromotion(promotion(), {
      runtimeSmoke: {
        policyPath: ".agentshield/policy.json",
        targetPath: ".",
        policyStatus: "compliant",
      },
    });

    const rendered = renderPolicyPromotionJobSummary(summary);

    expect(rendered).toContain("## AgentShield Policy Promotion");
    expect(rendered).toContain("- Status: verified");
    expect(rendered).toContain("- Pack: enterprise");
    expect(rendered).toContain("- Digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    expect(rendered).toContain("runtime-smoke-test");
    expect(rendered).toContain(".agentshield/policy.json");
    expect(rendered).not.toContain("\"required_deny_list\"");
  });
});
