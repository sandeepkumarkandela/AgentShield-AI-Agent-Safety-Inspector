# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- Updated the GitHub Action metadata to run on the Node.js 24 JavaScript action
  runtime before GitHub removes Node.js 20 support from hosted runners.
- Added end-to-end scan coverage and README guidance for AI developer-tool
  persistence IOCs in Claude Code, VS Code, GitHub workflow, LaunchAgent, and
  systemd automation surfaces, including `gh-token-monitor` token-store
  persistence.
- Added evidence-pack fleet `operatorReadback` output with promotion status,
  deterministic review digest, owner counts, approval routes, and next-action
  guidance for GitHub App, Linear, and ECC Tools routing.
- Added `agentshield policy promote` to verify exported policy-pack manifests,
  reject tampered policy JSON by SHA-256 digest, and promote a selected pack
  into the active policy path with dry-run and JSON review modes.
- Added GitHub Action package-manager hardening outputs and job-summary
  evidence for registry credentials, lifecycle-script drift, and release-age
  gate drift.
- Added GitHub Action policy-promotion review outputs and job-summary evidence
  so CI can route owner approval, protected rollout, and runtime-smoke
  `reviewItems` from checksum-verified policy exports.

## [1.4.0] - 2026-03-20

This release focuses on scan accuracy, source-aware scoring, and safer interpretation of example and manifest-heavy repositories.

### Highlights

- Added first-class source confidence for `docs-example`, `plugin-manifest`, and `hook-code` findings alongside existing `template-example` and `project-local-optional` output.
- Downgraded structural findings from docs/example config and rewrote report wording so risky shipped examples no longer read like confirmed active runtime exposure.
- Extended example classification beyond `docs/` and `commands/` to `examples/`, `example/`, `samples/`, and `sample/`.
- Re-added standalone docs/example `CLAUDE.md` files to scanning so real secrets in example guidance are not silently missed.
- Improved hook analysis for manifest-resolved non-shell implementations, including explicit context injection, transcript access, and remote shell payloads executed via child-process wrappers.
- Tightened hook-manifest handling so declarative config is distinguished from executable hook implementations.
- Expanded structured agent coverage for `.claude/subagents/*.json` and `.claude/slash-commands/*.json`.
- Refined report scoring so template, project-local, docs/example, and plugin-manifest findings no longer inflate grades like active runtime exposure.

### Validation

- `npm run typecheck`
- `npm test`
- `npm run build`
- Live rescans of `everything-claude-code`, `PMX-backend`, and `basket-trader`

### Upgrade Notes

- The GitHub Action bundle under `dist/` must be committed before tagging a release.
- The release workflow verifies that the pushed tag matches `package.json`, reruns the full gate, rebuilds `dist/`, and refuses to publish if generated action artifacts are out of sync.
