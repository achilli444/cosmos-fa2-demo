# FA-2 Demo Runbook — OpenC3 COSMOS v7.2.0 APL vetting (15 min)

Baseline: `demo-baseline` = upstream tag v7.2.0, commit `77acb91cc2c3b21af3eb981c829285dea96c984e`. All inputs are public OSS; ITAR-clean.

| Link | URL |
|---|---|
| Fork | https://github.com/achilli444/cosmos-fa2-demo |
| Security Swarm scan | https://app.devin.ai/code-scan/d58e80b2ee2c4c829eda0934f8031e18 |
| Follow-up Security Swarm scan | https://app.devin.ai/code-scan/6040f399eef8480289e490c3fc7c4bb3 |
| Artifacts PR | https://github.com/achilli444/cosmos-fa2-demo/pull/2 |
| Fix PR | https://github.com/achilli444/cosmos-fa2-demo/pull/1 |
| Fix session | https://app.devin.ai/sessions/f113758123084fb296c28d56f7aa4a37 |

Pre-flight (T-10 min): open the six links above in tabs; `git checkout demo-artifacts`; optional running UI: `OPENC3_TAG=7.2.0 ./openc3.sh run` then http://localhost:2900 (Core edition: the login page asks you to set a password on first visit; ~90 s to healthy).

## 0:00–1:00 Framing
Say: "This is APL vetting of a commercial/FOSS release candidate — COSMOS 7.2.0, the TT&C ground software on the FORGE C2 team — before it enters a DCW enclave. One automated pass: SBOM, risk, OWASP findings, backdoor heuristics, origin lineage."

## 1:00–3:00 (a) SBOM summary
1. Open `demo/fa2/sbom/SBOM_SUMMARY.md` (component counts by ecosystem, known-CVE components, license flags).
2. Show the raw files exist: `ls demo/fa2/sbom/` → `cosmos-v7.2.0.cdx.json`, `cosmos-v7.2.0.spdx.json`, `grype-cosmos-v7.2.0.json`.
3. Say: "CycloneDX + SPDX, regenerable with the exact commands at the top of the summary."

## 3:00–8:00 (b) Three findings (open `demo/fa2/findings/FINDINGS.md`, then the scan UI)
1. **Authenticated OS command injection via `pypi_url`** — `openc3/lib/openc3/models/plugin_model.rb:272-288`. Operator impact: "any user who can edit one admin setting owns the C2 host — pip runs whatever the setting contains." Matches GHSA-vp3w-52v9-q57f / CVE-2026-77601.
2. **Unauthenticated global logout** — `openc3-cosmos-cmd-tlm-api/config/routes.rb:243`, `users_controller.rb:23-24`, `auth_model.rb:139-140`. Impact: "one unauthenticated request deletes every operator session — denial of command-and-control during a pass." Matches GHSA-25rh-53rx-456q / CVE-2026-92165.
3. **JsonDRb `public_send` denylist bypass** — `openc3/lib/openc3/io/json_rpc.rb:230`, `json_drb.rb:257-258`. Impact: "the API blocks `send` but not `public_send`; an authenticated caller reaches methods the API never meant to expose." Matches GHSA-q2gf-g584-w94p / CVE-2026-92166. **Note:** the first scan did not emit this one; the targeted follow-up scan did (`sfind-57994279…`, `FINDINGS.md §F` row F2). Open it in the follow-up scan UI and say so: "the first pass missed it, a scoped second pass caught it — and it is a published advisory we reproduced, not a discovery." Also say the shipped API sets a method whitelist, so the default deployment is not exploitable.
4. Switch to the scan UI (first scan: 29 open findings — 1 critical, 6 high, 9 medium, 13 low; 15 duplicates auto-dismissed. Follow-up scan: 12 open — 3 high, 7 medium, 2 low; 11 duplicates. Combined 41; 7 of 8 published advisories reproduced at their published sink, A4 only via a related sink). Open the `pypi_url` finding (`sfind-c4f38280…`) to show file:line, attack path, preconditions and the scan note cross-referencing GHSA-vp3w-52v9-q57f. Then open one **new** item — e.g. the unauthenticated login-lockout DoS (`sfind-eca2fa94…`) or the pre-auth `create_additions: true` deserialization (`sfind-912d80ca…`) — and say explicitly: "this one is not in any published advisory; we label it new/unverified." If time allows, open the follow-up scan's heap-OOB finding (`sfind-d384fe99…`) to show a C-extension memory-safety trace from a 24-byte crafted telemetry packet — "one packet on the target link crashes the decom process."

## 8:00–10:00 (c) Provenance
1. Open `demo/fa2/provenance/PROVENANCE.md`: commit/author counts, email-domain table, timezone table, first-time-contributor touches on auth/plugin-install/script-exec paths, dependency maintainer signals.
2. Say: "Data, not accusations — this is the lineage evidence an APL reviewer asks for and normally assembles by hand."

## 10:00–13:00 (d) The fix
1. Open the fix session (https://app.devin.ai/sessions/f113758123084fb296c28d56f7aa4a37) — scroll to the failing RSpec (before) and passing RSpec (after).
2. Open the fix PR (https://github.com/achilli444/cosmos-fa2-demo/pull/1): show URL validation + argv-array `pipinstall` invocation and the new specs.
3. Open `demo/fa2/FIX_COMPARISON.md`: "Independent fix lands on the same design as upstream's be70d1d83 — validate scheme/host, no shell string."
4. Live option: re-run the spec in the container: `./openc3.sh cli rspec openc3/spec/models/plugin_model_spec.rb` (or `cd openc3 && bundle exec rspec spec/models/plugin_model_spec.rb`).

## 13:00–15:00 (e) Close
1. Open `demo/fa2/RISK_MEMO.md`: verdict, top-5 risks, required remediations, engineer-hours replaced (assumptions stated).
2. Closing line: "FA-2 asks for proactive assurance of third-party software before it touches a DCW system. This pass produced the SBOM, the OWASP/CWE-mapped findings, the backdoor heuristics, the lineage report, and a tested fix — from a public release candidate, with every claim linked to a file, commit, or advisory."

## Do not say
- Do not claim Devin discovered any public CVE/GHSA; all eight advisories at this tag are published by OpenC3. Say "reproduced / matches the published advisory."
- Do not drift into on-orbit / flight-software (FA-3) unless asked.
- Do not compare to named competitors or scanners.
- Do not say "zero-day."

## Fallbacks
- Scan UI unavailable → `demo/fa2/findings/swarm_findings_export.json` + FINDINGS.md.
- Fix session unavailable → PR diff + `FIX_COMPARISON.md` + local rspec run.
- Docker not available → skip UI; everything else is static.
