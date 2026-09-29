# FA-2 Risk Memo — OpenC3 COSMOS v7.2.0 (release-candidate vetting)

| | |
|---|---|
| System | OpenC3 COSMOS (satellite C2 / TT&C ground software), source tree `achilli444/cosmos-fa2-demo` (mirror of `OpenC3/cosmos`) |
| Version / tag / SHA | `v7.2.0` = branch `demo-baseline`, commit `77acb91cc2c3b21af3eb981c829285dea96c984e` |
| Date | 2026-09-28 |
| Scope | Source tree at the tag (Ruby core + C ext, Rails APIs, Python lib, Vue frontend, Dockerfiles, committed vendored binaries) and its declared dependencies. No container images, no running system, no dynamic analysis. Artifacts: `demo/fa2/sbom/SBOM_SUMMARY.md`, `demo/fa2/provenance/PROVENANCE.md`, `demo/fa2/heuristics/BACKDOOR_SCAN.md`. |
| Data classification | all inputs public/open-source; ITAR-clean |

## Verdict: **approve-with-conditions**

Rationale: no evidence of hidden functionality, tampered vendored binaries or covert credentials was found, and provenance is consistent with a single vendor's controlled history — but the tag carries eight published advisories (one critical RCE) and 44 vulnerable dependency components that are fixed in 7.3.0/7.4.0, plus shipped default credentials, so it must not be deployed as-is.

## Top 5 risks

| # | Risk | Evidence | Severity | Mission impact (C2 operator) |
|---|---|---|---|---|
| 1 | Authenticated RCE via user-writable config overlay (`targets_modified/`) and shell injection via admin `pypi_url` setting | GHSA-jjq7-m736-w977 / CVE-2026-77602 (CVSS 9.9); GHSA-vp3w-52v9-q57f / CVE-2026-77601 (8.8); `BACKDOOR_SCAN.md §1` rows `generic_conversion.rb:54`, `plugin_model.rb:288` | Critical | any logged-in user (or a stolen session) can run code on the cmd/tlm API host and thus send arbitrary commands to the vehicle |
| 2 | Script-approval bypass and RPC denylist bypass — operator-script controls can be side-stepped | GHSA-hf9c-xwpr-cjvr / CVE-2026-92169 (8.8, fixed 7.4.0); GHSA-q2gf-g584-w94p / CVE-2026-92166 (5.6); `BACKDOOR_SCAN.md §1` rows `running_script.rb`, `json_drb.rb:261` | High | two-person / approved-procedure controls on command scripts are not enforceable at this tag |
| 3 | Shipped default credentials (`OPENC3_SERVICE_PASSWORD` and five store passwords in `.env`) accepted as bearer tokens; service password verified before user auth | `BACKDOOR_SCAN.md §4-5`; `openc3/lib/openc3/models/auth_model.rb` `verify`; `.env:48-59`; docs `getting-started/security.md:100-229`; CVE-2025-28388 lineage | High (deployment-dependent) | an unchanged `.env` gives anyone on the network segment full API access with a publicly known string |
| 4 | Unauthenticated denial of operator C2 sessions and cross-user stored XSS in telemetry screens | GHSA-25rh-53rx-456q / CVE-2026-92165 (unauth global logout, fixed 7.3.0); GHSA-gvf2-2rh5-mpgf / CVE-2026-77394 (7.6); `ButtonWidget.vue:109` | High | an attacker can log every operator out during a pass, or plant JS in a shared screen that runs in another operator's browser |
| 5 | Vulnerable third-party components and unpinned supply chain: 44 components with known CVEs (19 critical matches), 0 of 25 base images digest-pinned, `OPENC3_TAG=latest`, no build-time checksums on vendored release blobs | `SBOM_SUMMARY.md` (top-25 table: `golang.org/x/crypto` in AnyCable binaries, `websocket-driver`, `form-data`, `axios`, `immutable`, `image-size`); `PROVENANCE.md §5-6` | High | patch state of the ground segment depends on whatever the registry served on build day; SSH/TLS-adjacent Go crypto CVEs sit in the WebSocket path that carries live telemetry to operator screens |

Not ranked but recorded: GHSA-jmg5-qfmh-4jh3 / CVE-2026-92168 (unauthenticated `update_news` write, medium 5.3, fixed 7.4.0; output is DOMPurify-sanitised) and GHSA-g7jg-9chv-jq9j / CVE-2026-92167 (heap OOB read in `openc3/ext/.../structure.c:427`, high 7.4, fixed 7.4.0; malformed packet definition → crash/info leak of the decom process).

## Published advisories applying to this tag (referenced as published; none discovered by this pass)

Source: repository advisory feed `https://api.github.com/repos/OpenC3/cosmos/security-advisories?state=published` (17 published, saved to `demo/fa2/data/openc3_cosmos_published_advisories.json`) and `https://github.com/OpenC3/cosmos/security/advisories/<GHSA>` (HTTP 200 for all eight). Reachability note: the global pages `https://github.com/advisories/<GHSA>` returned 200 only for the three 2026-09-03 advisories and 404 for the five 2026-09-21 (CVE-2026-9216x) advisories, and the global advisory API rate-limited (403) during this run — the repo-level feed is the authoritative source for those five.

| GHSA | CVE | Severity / CVSS | Affected | Fixed | Summary |
|---|---|---|---|---|---|
| GHSA-jjq7-m736-w977 | CVE-2026-77602 | critical / 9.9 | ≥ 5.1.0, ≤ 7.2.1 | 7.3.0 | authenticated RCE via user-writable config overlay (table/cmd/tlm definitions, script suites) |
| GHSA-gvf2-2rh5-mpgf | CVE-2026-77394 | high / 7.6 | ≥ 5.0.6, ≤ 7.2.1 | 7.3.0 | stored cross-user XSS via Telemetry screen BUTTON widget |
| GHSA-vp3w-52v9-q57f | CVE-2026-77601 | high / 8.8 | ≥ 5.12.0, ≤ 7.2.1 | 7.3.0 | authenticated OS command injection via `pypi_url` setting (`plugin_model.rb`) |
| GHSA-hf9c-xwpr-cjvr | CVE-2026-92169 | high / 8.8 | ≥ 6.5.0, ≤ 7.3.0 | 7.4.0 | Ruby injection via unsanitised `suiteRunner` params bypasses Script Runner approval |
| GHSA-q2gf-g584-w94p | CVE-2026-92166 | medium / 5.6 | ≥ 5.0.6, ≤ 7.2.1 | 7.3.0 | JsonDRb denylist bypass through inherited `public_send` |
| GHSA-25rh-53rx-456q | CVE-2026-92165 | high / (no CVSS vector published) | ≥ 5.0.6, ≤ 7.2.1 | 7.3.0 | unauthenticated global session termination (`PATCH/PUT /users/logout/:user`) |
| GHSA-jmg5-qfmh-4jh3 | CVE-2026-92168 | medium / 5.3 | ≥ 6.2.0, ≤ 7.3.0 | 7.4.0 | missing authorization in `update_news` (`rescue Exception` swallows AuthError) |
| GHSA-g7jg-9chv-jq9j | CVE-2026-92167 | high / 7.4 | (range given as file location `structure.c:427`) | 7.4.0 | heap out-of-bounds read via integer overflow |

## Required remediations (conditions of approval)

1. **Do not field 7.2.0.** Rebase the candidate on ≥ 7.4.0, which closes all eight advisories above (7.3.0 closes six; GHSA-hf9c-xwpr-cjvr and GHSA-jmg5-qfmh-4jh3 need 7.4.0). Re-run this pipeline on the new tag.
2. **Dependency CVEs** (`SBOM_SUMMARY.md` top-25): rebuild `openc3-ruby` with AnyCable-Go ≥ a release built against `golang.org/x/crypto` ≥ 0.52.0 (CVE-2026-46595, CVE-2026-39832 — 8 Go components); bump `websocket-driver` → 0.7.5, `form-data` → 4.0.6, `axios` → 1.18.0, `immutable` → 5.1.8, `image-size` → 2.0.3; the `openc3` gem entries clear with item 1. Re-run grype; accept remaining transitive dev-only items by written waiver.
3. **Credentials** (`BACKDOOR_SCAN.md §4-5`): replace every default in `.env` (`OPENC3_SERVICE_PASSWORD`, `OPENC3_{TSDB,REDIS,BUCKET,SR_REDIS,SR_BUCKET}_PASSWORD`, `SECRET_KEY_BASE`) with generated secrets injected at deploy time; treat `OPENC3_SERVICE_PASSWORD` as a privileged credential (it is verified *before* user tokens in `AuthModel.verify`); confirm the file is not committed to any deployment repo.
4. **Privilege model for config-as-code paths**: until item 1, restrict the `admin` role (Redis console `redis_controller.rb`, plugin install, `pypi_url`/settings) and the ability to edit screens/targets to a named, small operator set; log and review `targets_modified/` and screen changes; disable BUTTON-widget JS execution in shared screens if the release cannot move.
5. **Supply-chain pinning** (`PROVENANCE.md §5-6`): set `OPENC3_TAG` to the release version and pin all 25 `FROM` references by digest; add SHA-256 verification of the 12 committed release blobs (all currently match upstream — record those hashes) in the Dockerfiles; mirror `RUBYGEMS_URL`/`PYPI_URL`/`NPM_URL` to an internal proxy for the build.
6. **Heuristic follow-ups** (no malicious finding; hygiene): remove or rotate the committed MQTT example private key (`examples/openc3-cosmos-mqtt-test/client.key`); change `Kernel.open` to `File.open` in `posix_serial_driver.rb:53`; make `redis_controller.rb` `DISALLOWED_COMMANDS` an allow-list; use HTTPS for `dl-cdn.alpinelinux.org` in `scripts/release/package_audit_lib.rb`.
7. **Licensing**: no blocking flag. Record the AGPL-3.0 + commercial terms (`LICENSE.md`) and the six GPL/LGPL-optioned transitive packages (`SBOM_SUMMARY.md` license table) in the program's OSS register; obtain a declared license for `websocket-native` / `require-like` or document non-redistribution.
8. **Provenance**: no action required; retain `PROVENANCE.md §3` low-volume-contributor SHAs as the spot-check list for the code-review team.

## Engineer-hours this automated pass replaced (bottom-up estimate)

| Activity | Basis | Hours |
|---|---|---|
| SBOM generation + CVE triage | 2,663 components; 208 grype matches → 44 unique vulnerable components at ~30 min each (fix-version lookup, direct/transitive, reachability note) + 4 h tooling/lockfile setup + 29 license flags × 10 min | 31 |
| Provenance analysis | git statistics/scripts 6 h; 167 direct dependencies × 5 min registry review 14 h; 25 sensitive-path commits × 10 min 4 h; 25 `FROM` + 13 vendored blobs hash verification 3 h | 27 |
| Security-focused code review of the four scoped directories by LoC | 59,706 (`openc3/lib/openc3`) + 9,097 (`cmd-tlm-api/app`) + 826 (`script-runner-api/app`) + 60,609 (`plugins/packages` src, excl. node_modules/public/dist) = 130,238 LoC at 200 LoC/h (security review pace for dynamic-language code, one reviewer, no tool assist) | 651 |
| Credential / backdoor sweep | 867 binaries classified + 13 upstream hash checks 6 h; 22 gitleaks + 37 grep credential hits 3 h; 142 dynamic-exec hits triaged 12 h; 8 advisory cross-references 3 h; CVE-2025-28388 history diff 2 h | 26 |
| **Total** | | **≈ 735 h** (≈ 18 engineer-weeks at 40 h) |

Assumptions: single reviewer, no prior COSMOS familiarity, manual tool operation; the LoC line dominates and would scale down (to ~130 h) if review were limited to the auth/scripting/plugin surfaces identified in `BACKDOOR_SCAN.md §1` rather than the full four directories. Wall-clock for this automated pass: one session.

## Security Swarm results (scan `scan-d58e80b2ee2c4c829eda0934f8031e18`, deep, completed 2026-09-28)

29 open findings after the scan's own de-duplication (1 critical, 6 high, 9 medium, 13 low; 15 duplicates dismissed). Five of the eight published advisories were reproduced by the swarm (A1 config-overlay RCE — critical; A2 `pypi_url` injection, A3 unauthenticated global logout, A5 BUTTON stored XSS — high; A4 approval bypass through a different sink); A6/A7/A8 were confirmed by reading only in this scan and reproduced by the follow-up scan (next section). New items not covered by any advisory, in priority order: pre-authentication `JSON.parse(create_additions: true)` on the primary API endpoint (high, gadget-dependent); cross-scope replay of running-script output over WebSocket (high, Enterprise); unauthenticated login-lockout DoS via a single global failure counter (medium); unauthenticated `/openc3-api/internal/metrics` and `/openc3-api/traefik` topology disclosure (medium); Table Manager and `delete_modified` writes gated only by the view-level `system` permission (medium/low). Full mapping, file:line and operator impact: `findings/FINDINGS.md`; raw export: `findings/swarm_findings_export.json`. Added condition for approval: disable `create_additions` on all `JSON.parse` calls and make the auth rate-limit per-caller — neither is covered by the eight advisories referenced above.

## Follow-up Security Swarm results (scan `scan-6040f399eef8480289e490c3fc7c4bb3`, deep, completed 2026-09-29)

Targeted at the three advisory code paths the first scan did not emit (`openc3/ext`, `openc3/lib/openc3/{io,api,packets,accessors}`). 12 open findings after de-duplication (3 high, 7 medium, 2 low; 11 duplicates dismissed). All three remaining advisories were reproduced by the swarm: A6 heap OOB read via signed-int overflow in `structure.c:421-439`, reachable from one crafted `VARIABLE_BIT_SIZE` telemetry packet against the shipped `INST VARIABLE_ARRAYS` definition (high — decom-process crash or heap read from the target link); A7 `public_send` denylist bypass (high by rule, latent — only a `JsonDRb` without `method_whitelist`); A8 `update_news` swallowed `AuthError` (high by rule, content impact low). New items not covered by any advisory, in priority order: command-identity spoofing by overwriting ID_PARAMETER fields under `cmd_no_range_check` (medium — defeats per-command RBAC, two-person approval and `disable_cmd` in Enterprise, falsifies the command log in Core); `get_packets` reading any caller-named Redis stream after a scope-wide `tlm` check (medium); `connect_interface`/`connect_router` persisting caller-supplied constructor parameters with only `system_set` (medium — link redirection to an attacker host); `send_raw` skipping `cmd_raw` on interfaces without mapped command targets (medium); `critical_commanding = ALL` approval keyed to a client-asserted `manual` flag (medium); ReDoS in `get_overall_limits_state` (medium); `DISABLE_DISCONNECT` enforced only in the UI and an unauthenticated name-existence oracle (low). Combined across both scans: **41 open findings** (1 critical, 9 high, 16 medium, 15 low); all eight published advisories reproduced. Full mapping: `findings/FINDINGS.md §F`; raw export: `findings/swarm_followup_findings_export.json`. Added conditions for approval: 64-bit bounds arithmetic with negative-value rejection in `structure.c` (upstream fix lands in 7.4.0) and rejection of ID-item overwrites in `Commands#set_parameters` — the latter is not covered by any published advisory. Verdict unchanged: approve-with-conditions.
