# FA-2 demo package — APL vetting of OpenC3 COSMOS v7.2.0

All data here is public open-source (OpenC3/cosmos, public advisories, public registries). No ITAR/CUI content. Baseline: tag `v7.2.0`, commit `77acb91cc2c3b21af3eb981c829285dea96c984e`, branch `demo-baseline`.

| Item | Link |
|---|---|
| Fork (pinned baseline) | https://github.com/achilli444/cosmos-fa2-demo/tree/demo-baseline |
| Devin Security Swarm scan | https://app.devin.ai/code-scan/d58e80b2ee2c4c829eda0934f8031e18 |
| Follow-up Security Swarm scan (C ext + JSON-RPC dispatch + settings) | https://app.devin.ai/code-scan/6040f399eef8480289e490c3fc7c4bb3 |
| Artifacts PR (`demo-artifacts` → `demo-baseline`) | https://github.com/achilli444/cosmos-fa2-demo/pull/2 |
| Fix PR (`pypi_url` command injection → `demo-baseline`) | https://github.com/achilli444/cosmos-fa2-demo/pull/1 |
| Fix session (recorded) | https://app.devin.ai/sessions/f113758123084fb296c28d56f7aa4a37 |

## Artifacts

| File | Content |
|---|---|
| [`RUNBOOK.md`](RUNBOOK.md) | 15-minute demo sequence + do-not-say list |
| [`RISK_MEMO.md`](RISK_MEMO.md) | One-page APL-style risk memo: verdict, top-5 risks, remediations, engineer-hours |
| [`findings/FINDINGS.md`](findings/FINDINGS.md) | Swarm findings mapped to OWASP Top 10 / CWE / severity / mission impact; published-advisory matches vs new/unverified |
| [`findings/swarm_findings_export.json`](findings/swarm_findings_export.json) | Raw Security Swarm findings export |
| [`findings/swarm_followup_findings_export.json`](findings/swarm_followup_findings_export.json) | Raw export of the targeted follow-up scan (`openc3/ext`, `io`, `api`, `packets`, `accessors`) |
| [`sbom/`](sbom/) | CycloneDX + SPDX SBOMs, Grype results, summary table |
| [`provenance/PROVENANCE.md`](provenance/PROVENANCE.md) | Origin / development-lineage report from git history and registry metadata |
| [`heuristics/BACKDOOR_SCAN.md`](heuristics/BACKDOOR_SCAN.md) | Malware/backdoor heuristics (dynamic exec, obfuscated blobs, install-hook network, secrets, binaries) |
| [`FIX_COMPARISON.md`](FIX_COMPARISON.md) | Demo fix vs upstream fix commit `be70d1d836c83c3b084e768e31a399312d4cbe0b` |
| [`COMPOSE_EVIDENCE.txt`](COMPOSE_EVIDENCE.txt) | `docker compose` (openc3.sh) startup evidence for the pinned tag |

## Verification

| Check | Result | Evidence |
|---|---|---|
| Baseline pinned | `demo-baseline` = `v7.2.0` = `77acb91cc2c3b21af3eb981c829285dea96c984e`; `plugin_model.rb:269-289` still builds the `pipinstall` shell string from `pypi_url` | `git log -1 demo-baseline`; `FIX_COMPARISON.md` (before/after) |
| Security Swarm scan | `scan-d58e80b2ee2c4c829eda0934f8031e18`, deep, pinned to the commit above, **completed** 2026-09-28: 44 emitted → 29 open (1 critical / 6 high / 9 medium / 13 low), 15 duplicates auto-dismissed. 5 of 8 published advisories reproduced; A6/A7/A8 not emitted by this scan (see `findings/FINDINGS.md §D`) | [`findings/swarm_findings_export.json`](findings/swarm_findings_export.json), scan link above |
| Follow-up Security Swarm scan | `scan-6040f399eef8480289e490c3fc7c4bb3`, deep, same commit, scoped to `openc3/ext` + `openc3/lib/openc3/{io,api,packets,accessors}`, **completed** 2026-09-29: 23 emitted → 12 open (3 high / 7 medium / 2 low), 11 duplicates auto-dismissed. A6/A7/A8 reproduced (F1–F3); 9 new/unverified items. Combined: 41 open; 7 of 8 advisories reproduced at their published sink, A4 only via a related sink (see `findings/FINDINGS.md §D, §F`) | [`findings/swarm_followup_findings_export.json`](findings/swarm_followup_findings_export.json), scan link above |
| Artifacts | 69 files under `demo/fa2/` on `demo-artifacts`: 61 SBOM/Grype, provenance, heuristics, script and advisory-data files (incl. 4 force-added Bundler lockfiles) + risk memo, this README, runbook, findings (+2 swarm exports), fix comparison, compose evidence — `git ls-files demo/fa2 \| wc -l` | PR #2 (link above) |
| Fix PR | `fix/pypi-url-command-injection` → `demo-baseline`, title "Fix authenticated OS command injection via pypi_url setting"; RSpec fails before / passes after, RuboCop clean; **not merged** | PR #1 and fix session (links above); `FIX_COMPARISON.md` |
| Running UI | `OPENC3_TAG=7.2.0 ./openc3.sh run` brought up all 9 containers at the pinned tag; `http://localhost:2900/` and `/tools/cmdtlmserver` returned 200 | [`COMPOSE_EVIDENCE.txt`](COMPOSE_EVIDENCE.txt) |

Known limitation: `demo-baseline` could not be set as the repository default branch (GitHub App returned 403), so `main` still tracks upstream — always check out `demo-baseline` / `demo-artifacts` explicitly.

## Reproduce

```bash
git clone https://github.com/achilli444/cosmos-fa2-demo && cd cosmos-fa2-demo
git checkout demo-artifacts            # artifacts + this README
OPENC3_TAG=7.2.0 ./openc3.sh run       # optional: running UI at http://localhost:2900 (~90 s)
```
Tool versions and exact commands for each artifact are recorded at the top of that artifact.
