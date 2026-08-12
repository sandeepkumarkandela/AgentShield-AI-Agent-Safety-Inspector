import { describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import type { SerializedBaseline } from "../../src/baseline/index.js";

const CLI_PATH = resolve(import.meta.dirname, "../../dist/index.js");

function makeConfigDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "agentshield-baseline-cli-"));
  mkdirSync(join(dir, ".claude"), { recursive: true });
  writeFileSync(
    join(dir, ".claude", "settings.json"),
    JSON.stringify({
      permissions: {
        allow: ["Bash(*)", "Read(*)"],
        deny: [],
      },
    }, null, 2)
  );
  return dir;
}

function runCli(args: string[]) {
  return spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: "utf-8",
    env: {
      ...process.env,
      NODE_NO_WARNINGS: "1",
    },
  });
}

describe("baseline CLI", () => {
  it("writes a baseline snapshot through a first-class command", () => {
    const configDir = makeConfigDir();
    const outputPath = join(configDir, "security", "agentshield-baseline.json");

    const result = runCli([
      "baseline",
      "write",
      "--path",
      join(configDir, ".claude"),
      "--output",
      outputPath,
      "--min-severity",
      "medium",
    ]);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain("Baseline written");
    expect(result.stdout).toContain(outputPath);
    expect(existsSync(outputPath)).toBe(true);

    const baseline = JSON.parse(readFileSync(outputPath, "utf-8")) as SerializedBaseline;
    expect(baseline.version).toBe(1);
    expect(baseline.score.numericScore).toBeGreaterThanOrEqual(0);
    expect(baseline.findings.length).toBeGreaterThan(0);
    expect(baseline.findings.every((finding) => finding.fingerprint)).toBe(true);
  });

  it("emits machine-readable baseline metadata when --json is set", () => {
    const configDir = makeConfigDir();
    const outputPath = join(configDir, "baseline.json");

    const result = runCli([
      "baseline",
      "write",
      "--path",
      join(configDir, ".claude"),
      "--output",
      outputPath,
      "--json",
    ]);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");

    const payload = JSON.parse(result.stdout) as {
      baselinePath: string;
      targetPath: string;
      score: number;
      grade: string;
      findings: number;
    };

    expect(payload.baselinePath).toBe(outputPath);
    expect(payload.targetPath).toBe(join(configDir, ".claude"));
    expect(payload.score).toBeGreaterThanOrEqual(0);
    expect(payload.grade).toMatch(/^[A-F]$/);
    expect(payload.findings).toBeGreaterThan(0);
  });

  it("rejects unsupported severity filters before writing", () => {
    const configDir = makeConfigDir();
    const outputPath = join(configDir, "baseline.json");

    const result = runCli([
      "baseline",
      "write",
      "--path",
      join(configDir, ".claude"),
      "--output",
      outputPath,
      "--min-severity",
      "urgent",
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("--min-severity must be one of");
    expect(existsSync(outputPath)).toBe(false);
  });
});
