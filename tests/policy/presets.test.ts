import { describe, expect, it } from "vitest";
import {
  generatePolicyPack,
  listPolicyPacks,
} from "../../src/policy/presets.js";
import {
  evaluatePolicy,
  generateExamplePolicy,
} from "../../src/policy/evaluate.js";
import { OrgPolicySchema } from "../../src/policy/types.js";
import type { ConfigFile, SecurityScore } from "../../src/types.js";

function makeScore(numericScore: number): SecurityScore {
  return {
    grade: numericScore >= 90 ? "A" : numericScore >= 75 ? "B" : "C",
    numericScore,
    breakdown: { secrets: 100, permissions: 100, hooks: 100, mcp: 100, agents: 100 },
  };
}

function makeSettings(config: Record<string, unknown>): ConfigFile {
  return {
    path: "settings.json",
    type: "settings-json",
    content: JSON.stringify(config),
  };
}

function makeMcpConfig(servers: Record<string, unknown>): ConfigFile {
  return {
    path: "mcp.json",
    type: "mcp-json",
    content: JSON.stringify({ mcpServers: servers }),
  };
}

describe("policy pack presets", () => {
  it("defines every public policy pack with labels and descriptions", () => {
    expect(listPolicyPacks()).toEqual([
      expect.objectContaining({ id: "oss", label: "OSS" }),
      expect.objectContaining({ id: "team", label: "Team" }),
      expect.objectContaining({ id: "enterprise", label: "Enterprise" }),
      expect.objectContaining({ id: "regulated", label: "Regulated" }),
      expect.objectContaining({ id: "high-risk-hooks-mcp", label: "High-risk hooks/MCP" }),
      expect.objectContaining({ id: "ci-enforcement", label: "CI enforcement" }),
    ]);

    for (const pack of listPolicyPacks()) {
      expect(pack.description.length).toBeGreaterThan(20);
    }
  });

  it("generates schema-valid policies for every pack", () => {
    for (const pack of listPolicyPacks()) {
      const policy = generatePolicyPack(pack.id, {
        owners: ["security@example.com"],
      });
      const parsed = OrgPolicySchema.parse(policy);

      expect(parsed.version).toBe(1);
      expect(parsed.policy_pack).toBe(pack.id);
      expect(parsed.owners).toEqual(["security@example.com"]);
      expect(parsed.required_deny_list.length).toBeGreaterThan(0);
    }
  });

  it("makes regulated stricter than enterprise and team", () => {
    const team = generatePolicyPack("team");
    const enterprise = generatePolicyPack("enterprise");
    const regulated = generatePolicyPack("regulated");

    expect(regulated.min_score).toBeGreaterThan(enterprise.min_score);
    expect(enterprise.min_score).toBeGreaterThan(team.min_score);
    expect(regulated.max_severity).toBe("medium");
    expect(regulated.banned_mcp_servers).toContain("shell*");
    expect(regulated.banned_mcp_servers).toContain("terminal*");
  });

  it("high-risk hooks/MCP pack enforces runtime hooks and risky MCP bans", () => {
    const policy = generatePolicyPack("high-risk-hooks-mcp");
    const files = [
      makeSettings({
        hooks: {},
        permissions: { deny: ["Bash(rm", "Bash(curl"] },
      }),
      makeMcpConfig({ "shell-server": { command: "sh" } }),
    ];
    const result = evaluatePolicy(policy, [], makeScore(90), files);

    expect(result.passed).toBe(false);
    expect(result.violations.some((v) => v.rule === "required_hooks")).toBe(true);
    expect(result.violations.some((v) => v.rule === "banned_mcp_servers")).toBe(true);
  });

  it("generates example policy from a named pack", () => {
    const parsed = JSON.parse(generateExamplePolicy("ci-enforcement", {
      owners: ["platform@example.com"],
      name: "Platform CI Policy",
    }));

    expect(parsed.name).toBe("Platform CI Policy");
    expect(parsed.policy_pack).toBe("ci-enforcement");
    expect(parsed.owners).toEqual(["platform@example.com"]);
    expect(parsed.required_hooks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ event: "PreToolUse" }),
      ])
    );
  });
});
