# SBOM summary — OpenC3 COSMOS v7.2.0

Target: `achilli444/cosmos-fa2-demo` @ `demo-baseline` = upstream tag `v7.2.0`, commit `77acb91cc2c3b21af3eb981c829285dea96c984e`.
Scan date: 2026-09-28 (Grype DB built 2026-09-27T06:30:30Z).
All figures below are computed by `demo/fa2/scripts/sbom_summary.py` from the committed JSON and re-rendered by `demo/fa2/scripts/render_sbom_summary.py`; the script asserts the headline counts against the raw files.

## Files

| File | Content |
|---|---|
| `sbom/cosmos-v7.2.0.cdx.json` | CycloneDX 1.7 JSON, 2663 components |
| `sbom/cosmos-v7.2.0.spdx.json` | SPDX-2.3 JSON, 2609 packages (same syft run; syft emits file/binary records differently in SPDX) |
| `sbom/grype-cosmos-v7.2.0.json` | Grype output, 208 matches |
| `sbom/data/grype-table.txt`, `sbom/data/syft-table.txt` | human-readable tables from the same runs |
| `sbom/data/cosmos-v7.2.0.syft.json` | native syft JSON (source id `c704c4a433ae`) |
| `sbom/data/*.Gemfile.lock` | Bundler lockfiles generated for the scan (repo `.gitignore` excludes `*Gemfile.lock`, so none are committed upstream) |
| `sbom/data/direct_deps.csv` | direct-dependency declarations parsed from Gemfile/gemspec/package.json/pyproject/requirements by `scripts/extract_direct_deps.py` |
| `sbom/data/registry_licenses.json` | public registry license metadata (rubygems.org / registry.npmjs.org / pypi.org) fetched by `scripts/registry_metadata.py` |
| `sbom/data/*.csv`, `sbom/data/summary_numbers.json` | derived tables used below |

## Tools and commands

| Tool | Version |
|---|---|
| syft | 1.52.0 |
| grype | 0.119.0 (DB built 2026-09-27T06:30:30Z) |
| Ruby / Bundler (lockfile generation only) | 3.4.5 / 2.6.9 |
| python3 (derivation scripts, stdlib only) | 3.x |

```
# lockfiles (repo ignores *Gemfile.lock); run in each dir, then copied to sbom/data/<dir>.Gemfile.lock
bundle lock --lockfile=Gemfile.lock            # ./, openc3/, openc3-cosmos-cmd-tlm-api/, openc3-cosmos-script-runner-api/
# SBOMs (single syft run, repo root, default directory+file catalogers)
syft scan dir:. --source-name cosmos --source-version v7.2.0 \
  -o cyclonedx-json=demo/fa2/sbom/cosmos-v7.2.0.cdx.json \
  -o spdx-json=demo/fa2/sbom/cosmos-v7.2.0.spdx.json \
  -o syft-json=demo/fa2/sbom/data/cosmos-v7.2.0.syft.json \
  -o table=demo/fa2/sbom/data/syft-table.txt
# vulnerabilities
grype sbom:demo/fa2/sbom/cosmos-v7.2.0.cdx.json -o json=demo/fa2/sbom/grype-cosmos-v7.2.0.json -o table=demo/fa2/sbom/data/grype-table.txt
# derived numbers
python3 demo/fa2/scripts/extract_direct_deps.py
python3 demo/fa2/scripts/registry_metadata.py     # network: public registry JSON APIs, no credentials
python3 demo/fa2/scripts/sbom_summary.py
python3 demo/fa2/scripts/render_sbom_summary.py
```

Coverage check (syft location properties in the CycloneDX file): Ruby — `openc3/Gemfile.lock` (191), `openc3-cosmos-cmd-tlm-api/Gemfile.lock` (190), `openc3-cosmos-script-runner-api/Gemfile.lock` (188), root `Gemfile.lock` (32) plus one gem record per `*.gemspec`; npm — `openc3-cosmos-init/plugins/pnpm-lock.yaml`, `playwright/pnpm-lock.yaml`, `docs.openc3.com/pnpm-lock.yaml`; Python — `openc3/python/uv.lock` (49 components, parsed natively by syft 1.52.0; no `cyclonedx-py` supplement was needed) and `openc3-cosmos-init/plugins/packages/openc3-cosmos-demo/requirements.txt` (1). Full per-lockfile gem counts: `sbom/data/gem_counts_by_lockfile.csv`.

## Component count by ecosystem (CycloneDX, 2663 total)

| Ecosystem (PURL type) | Components |
|---|---|
| npm | 1751 |
| gem | 623 |
| github-action | 90 |
| go-module (from vendored anycable-go binaries) | 88 |
| file | 55 |
| pypi | 50 |
| library | 6 |

Notes: `go-module` entries are syft's binary cataloger reading the Go build info embedded in the two committed AnyCable binaries (`openc3-ruby/anycable-go-linux-{amd64,arm64}`), not a Go source tree. `github-action` = `uses:` references in `.github/workflows/**`. `file`/`library` = syft binary-classifier and file records (fonts, vendored JS). Gem counts include one record per first-party `.gemspec` (version string `0.0.0' + ".#{time}` is the literal gemspec expression; syft does not evaluate Ruby).

## Vulnerabilities (Grype)

Matches: **208** (one row per vulnerability × component location). Unique vulnerable components (name+version+ecosystem): **44** — direct 4, transitive 31, not applicable 9 (vendored Go binaries / GitHub Actions have no manifest declaring them).

| Severity | Matches |
|---|---|
| Critical | 19 |
| High | 95 |
| Medium | 68 |
| Low | 16 |
| Unknown | 10 |

| Ecosystem | Vulnerable components |
|---|---|
| go-module (from vendored anycable-go binaries) | 8 |
| npm | 34 |
| gem | 1 |
| github-action | 1 |

Direct/transitive is decided by presence of the (ecosystem, name) pair in `sbom/data/direct_deps.csv` (declarations in Gemfile/gemspec, package.json, pyproject.toml, requirements*.txt outside node_modules/templates/examples). The `openc3` gem 7.2.0 is the first-party gem itself; Grype matches it because the published OpenC3 advisories (see `RISK_MEMO.md`) are in the GitHub Advisory Database.

### Top 25 by severity / CVSS (`sbom/data/top25_cves.csv`)

| # | ID | Sev | CVSS | Component | Version | Ecosystem | Direct/transitive | Fixed in |
|---|---|---|---|---|---|---|---|---|
| 1 | CVE-2026-46595 | Critical | 10.0 | golang.org/x/crypto | v0.50.0 | go-module (anycable bin) | n/a | 0.52.0 |
| 2 | CVE-2026-77602 | Critical | 9.9 | openc3 | 7.2.0 | gem | direct | 7.3.0 |
| 3 | CVE-2026-54466 | Critical | 9.2 | websocket-driver | 0.7.4 | npm | transitive | 0.7.5 |
| 4 | CVE-2026-39832 | Critical | 9.1 | golang.org/x/crypto | v0.50.0 | go-module (anycable bin) | n/a | 0.52.0 |
| 5 | CVE-2026-42508 | Critical | 9.1 | golang.org/x/crypto | v0.50.0 | go-module (anycable bin) | n/a | 0.52.0 |
| 6 | CVE-2026-39834 | Critical | 9.1 | golang.org/x/crypto | v0.50.0 | go-module (anycable bin) | n/a | 0.52.0 |
| 7 | CVE-2026-39830 | Critical | 9.1 | golang.org/x/crypto | v0.50.0 | go-module (anycable bin) | n/a | 0.52.0 |
| 8 | CVE-2026-39831 | Critical | 9.1 | golang.org/x/crypto | v0.50.0 | go-module (anycable bin) | n/a | 0.52.0 |
| 9 | CVE-2026-39833 | Critical | 9.1 | golang.org/x/crypto | v0.50.0 | go-module (anycable bin) | n/a | 0.52.0 |
| 10 | GHSA-hrxh-6v49-42gf | High | 8.8 | google.golang.org/grpc | v1.80.0 | go-module (anycable bin) | n/a | 1.82.1 |
| 11 | CVE-2026-77601 | High | 8.8 | openc3 | 7.2.0 | gem | direct | 7.3.0 |
| 12 | CVE-2026-12143 | High | 8.7 | form-data | 4.0.5 | npm | transitive | 4.0.6 |
| 13 | CVE-2026-84445 | High | 8.7 | google.golang.org/grpc | v1.80.0 | go-module (anycable bin) | n/a | 1.82.2 |
| 14 | CVE-2026-84304 | High | 8.7 | google.golang.org/grpc | v1.80.0 | go-module (anycable bin) | n/a | 1.83.1 |
| 15 | CVE-2025-71329 | High | 8.7 | image-size | 2.0.2 | npm | transitive | 2.0.3 |
| 16 | CVE-2025-71330 | High | 8.7 | image-size | 2.0.2 | npm | transitive | 2.0.3 |
| 17 | CVE-2026-59880 | High | 8.7 | immutable | 5.1.5 | npm | transitive | 5.1.8 |
| 18 | CVE-2026-59879 | High | 8.7 | immutable | 5.1.5 | npm | transitive | 5.1.8 |
| 19 | CVE-2026-13311 | High | 8.7 | shell-quote | 1.8.4 | npm | transitive | 1.9.0 |
| 20 | CVE-2026-67320 | High | 8.3 | axios | 1.16.1 | npm | direct | 1.18.0 |
| 21 | CVE-2026-39821 | High | 8.2 | golang.org/x/net | v0.53.0 | go-module (anycable bin) | n/a | 0.55.0 |
| 22 | CVE-2026-67213 | High | 8.2 | nanoid | 3.3.12 | npm | transitive | 3.3.18 |
| 23 | CVE-2026-67214 | High | 8.2 | nanoid | 3.3.12 | npm | transitive | 3.3.16 |
| 24 | CVE-2026-39821 | High | 8.2 | stdlib | go1.26.3 | go-module (anycable bin) | n/a | 1.25.13,1.26.6,1.27.0-r… |
| 25 | CVE-2026-84370 | High | 8.2 | svgo | 3.3.3 | npm | transitive | 3.3.5 |

### All 44 vulnerable components (`sbom/data/vulnerable_components.csv`)

| Component | Version | Ecosystem | D/T | Worst sev | #vulns | Fix versions |
|---|---|---|---|---|---|---|
| openc3 | 7.2.0 | gem | direct | Critical | 8 | 7.3.0 |
| golang.org/x/crypto | v0.50.0 | go-module (anycable bin) | n/an/a | Critical | 34 | 0.52.0;0.55.0;0.56.0 |
| websocket-driver | 0.7.4 | npm | transitive | Critical | 2 | 0.7.5 |
| golang.org/x/net | v0.53.0 | go-module (anycable bin) | n/an/a | High | 14 | 0.55.0;0.56.0 |
| golang.org/x/text | v0.36.0 | go-module (anycable bin) | n/an/a | High | 2 | 0.39.0 |
| google.golang.org/grpc | v1.80.0 | go-module (anycable bin) | n/an/a | High | 8 | 1.82.1;1.82.2;1.83.1 |
| stdlib | go1.26.3 | go-module (anycable bin) | n/an/a | High | 26 | 1.25.11;1.25.12;1.25.13;1.26.4;1.26.5;1… |
| axios | 1.16.1 | npm | direct | High | 10 | 1.18.0 |
| brace-expansion | 1.1.15 | npm | transitive | High | 3 | 1.1.16;1.1.17;1.1.18 |
| brace-expansion | 5.0.6 | npm | transitive | High | 6 | 5.0.7;5.0.8;5.0.9 |
| browserslist | 4.28.2 | npm | transitive | High | 6 | 4.28.7 |
| fast-uri | 3.1.2 | npm | transitive | High | 6 | 3.1.3;3.1.4;3.1.5;3.1.6 |
| form-data | 4.0.5 | npm | transitive | High | 1 | 4.0.6 |
| image-size | 2.0.2 | npm | transitive | High | 2 | 2.0.3 |
| immutable | 5.1.5 | npm | transitive | High | 2 | 5.1.8 |
| js-yaml | 3.14.2 | npm | transitive | High | 8 | 3.15.0;3.15.1;3.15.2 |
| js-yaml | 4.1.1 | npm | transitive | High | 4 | 4.2.0;4.3.0;4.3.1;4.3.2 |
| nanoid | 3.3.12 | npm | transitive | High | 4 | 3.3.16;3.3.18 |
| postcss | 8.5.15 | npm | transitive | High | 4 | 8.5.18;8.5.23 |
| serialize-javascript | 6.0.2 | npm | transitive | High | 2 | 7.0.3;7.0.5 |
| shell-quote | 1.8.4 | npm | transitive | High | 1 | 1.9.0 |
| svgo | 3.3.3 | npm | transitive | High | 3 | 3.3.4;3.3.5 |
| undici | 7.24.7 | npm | transitive | High | 12 | 7.28.0;7.29.0 |
| vite | 7.3.3 | npm | direct | High | 2 | 7.3.5 |
| @swc/html | 1.15.40 | npm | transitive | Medium | 1 | 1.15.47-nightly-20260729.1 |
| baseline-browser-mapping | 2.10.24 | npm | transitive | Medium | 1 | 2.11.0 |
| baseline-browser-mapping | 2.10.32 | npm | transitive | Medium | 2 | 2.11.0 |
| colord | 2.9.3 | npm | transitive | Medium | 1 | 2.9.4 |
| dompurify | 3.4.7 | npm | direct | Medium | 5 | 3.4.11;3.4.12;3.4.13;3.4.8;3.4.9 |
| http-proxy-middleware | 2.0.9 | npm | transitive | Medium | 1 | 2.0.10 |
| joi | 17.13.3 | npm | transitive | Medium | 3 | 17.13.4;17.13.5;17.13.6 |
| launch-editor | 2.13.2 | npm | transitive | Medium | 1 | 2.14.1 |
| qs | 6.15.2 | npm | transitive | Medium | 2 | 6.16.0 |
| uuid | 8.3.2 | npm | transitive | Medium | 1 | 11.1.1 |
| webpack-dev-server | 5.2.4 | npm | transitive | Medium | 3 | 5.2.5;5.2.6 |
| pypa/gh-action-pypi-publish | cef221092ed1bacb1cc03d23a2d87d1d172e277b | github-action | n/an/a | Low | 1 | 1.13.0 |
| golang.org/x/sys | v0.43.0 | go-module (anycable bin) | n/an/a | Low | 2 | 0.44.0 |
| @babel/core | 7.28.4 | npm | transitive | Low | 1 | 7.29.6 |
| body-parser | 1.20.5 | npm | transitive | Low | 1 | 1.20.6 |
| esbuild | 0.27.7 | npm | transitive | Low | 1 | 0.28.1 |
| postcss-selector-parser | 6.1.2 | npm | transitive | Low | 1 | 6.1.3 |
| postcss-selector-parser | 7.1.1 | npm | transitive | Low | 2 | 7.1.3 |
| github.com/go-chi/chi/v5 | v5.2.5 | go-module (anycable bin) | n/an/a | Unknown | 6 | 5.3.0 |
| github.com/klauspost/compress | v1.18.5 | go-module (anycable bin) | n/an/a | Unknown | 2 | 1.18.7 |

## License flags

Repository license: `LICENSE.md` — AGPL-3.0 with a separate commercial license offered by OpenC3, Inc. First-party gems and the in-tree `openc3` Python package are not published to a registry (HTTP 404), so they are assigned `AGPL-3.0-only OR commercial (first-party; LICENSE.md)` from the repository license; because the flag set includes AGPL they appear in the table below as `AGPL` rows (first-party, same terms as the product itself — not a third-party copyleft dependency).

License source for the 2663 components: SBOM-declared 3, public registry lookup 2398, repository `LICENSE.md` (first-party, registry 404) 21, registry lookup failed 0, not applicable (binary/file/action records) 241. Syft attaches license text to only 3 components for this tree (lockfiles carry no license field), so registry metadata is the primary source and is itself a limitation (registry metadata is declared by the publisher, not verified against the shipped files).

Flag rows (deduplicated across repeated lockfile locations): **29** — AGPL: 21, GPL: 2, LGPL: 4, none-declared: 2.

| Flag | Ecosystem | Component | Version | Declared license | Source | D/T | Location(s) |
|---|---|---|---|---|---|---|---|
| AGPL | gem | openc3-cosmos-demo | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /openc3-cosmos-init/plugins/packages/openc3-cosmos-demo/openc3-cosmos… |
| AGPL | gem | openc3-cosmos-erb-test | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /examples/openc3-cosmos-erb-test/openc3-cosmos-erb-test.gemspec |
| AGPL | gem | openc3-cosmos-http-example | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /examples/openc3-cosmos-http-example/openc3-cosmos-http-example.gemsp… |
| AGPL | gem | openc3-cosmos-mqtt-test | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /examples/openc3-cosmos-mqtt-test/openc3-cosmos-mqtt-test.gemspec |
| AGPL | gem | openc3-cosmos-tool-admin | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /openc3-cosmos-init/plugins/packages/openc3-cosmos-tool-admin/openc3-… |
| AGPL | gem | openc3-cosmos-tool-bucketexplorer | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /openc3-cosmos-init/plugins/packages/openc3-cosmos-tool-bucketexplore… |
| AGPL | gem | openc3-cosmos-tool-cmdsender | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /openc3-cosmos-init/plugins/packages/openc3-cosmos-tool-cmdsender/ope… |
| AGPL | gem | openc3-cosmos-tool-cmdtlmserver | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /openc3-cosmos-init/plugins/packages/openc3-cosmos-tool-cmdtlmserver/… |
| AGPL | gem | openc3-cosmos-tool-dataextractor | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /openc3-cosmos-init/plugins/packages/openc3-cosmos-tool-dataextractor… |
| AGPL | gem | openc3-cosmos-tool-dataviewer | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /openc3-cosmos-init/plugins/packages/openc3-cosmos-tool-dataviewer/op… |
| AGPL | gem | openc3-cosmos-tool-docs | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /docs.openc3.com/openc3-cosmos-tool-docs.gemspec |
| AGPL | gem | openc3-cosmos-tool-handbooks | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /openc3-cosmos-init/plugins/packages/openc3-cosmos-tool-handbooks/ope… |
| AGPL | gem | openc3-cosmos-tool-iframe | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /openc3-cosmos-init/plugins/packages/openc3-cosmos-tool-iframe/openc3… |
| AGPL | gem | openc3-cosmos-tool-limitsmonitor | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /openc3-cosmos-init/plugins/packages/openc3-cosmos-tool-limitsmonitor… |
| AGPL | gem | openc3-cosmos-tool-packetviewer | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /openc3-cosmos-init/plugins/packages/openc3-cosmos-tool-packetviewer/… |
| AGPL | gem | openc3-cosmos-tool-scriptrunner | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /openc3-cosmos-init/plugins/packages/openc3-cosmos-tool-scriptrunner/… |
| AGPL | gem | openc3-cosmos-tool-tablemanager | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /openc3-cosmos-init/plugins/packages/openc3-cosmos-tool-tablemanager/… |
| AGPL | gem | openc3-cosmos-tool-tlmgrapher | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /openc3-cosmos-init/plugins/packages/openc3-cosmos-tool-tlmgrapher/op… |
| AGPL | gem | openc3-cosmos-tool-tlmviewer | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /openc3-cosmos-init/plugins/packages/openc3-cosmos-tool-tlmviewer/ope… |
| AGPL | gem | openc3-tool-base | 0.0.0' + ".#{time} | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /openc3-cosmos-init/plugins/packages/openc3-tool-base/openc3-tool-bas… |
| AGPL | pypi | openc3 | 7.1.2b0 | AGPL-3.0-only OR commercial (first-party; LI… | repo LICENSE.md (first-party) | transitive | /openc3/python/uv.lock |
| GPL | gem | diff-lcs | 1.6.2 | Artistic-1.0-Perl OR GPL-2.0-or-later OR MIT | registry | transitive | /openc3-cosmos-cmd-tlm-api/Gemfile.lock;/openc3-cosmos-script-runner-… |
| GPL | npm | jszip | 3.10.1 | (MIT OR GPL-3.0-or-later) | registry | direct | /playwright/pnpm-lock.yaml |
| LGPL | pypi | gprof2dot | 2025.4.14 | LGPL | registry | transitive | /openc3/python/uv.lock |
| LGPL | pypi | psycopg | 3.3.4 | LGPL-3.0-only | registry | direct | /openc3/python/uv.lock |
| LGPL | pypi | psycopg-binary | 3.3.4 | LGPL-3.0-only | registry | transitive | /openc3/python/uv.lock |
| LGPL | pypi | psycopg-pool | 3.3.1 | LGPL-3.0-only | registry | transitive | /openc3/python/uv.lock |
| none-declared | gem | websocket-native | 1.0.0 | — | none | direct | /openc3-cosmos-cmd-tlm-api/Gemfile.lock;/openc3-cosmos-script-runner-… |
| none-declared | npm | require-like | 0.1.2 | — | none | transitive | /docs.openc3.com/pnpm-lock.yaml |

Reading: the two GPL rows are dual/tri-licensed (`diff-lcs` Artistic/GPL/MIT; `jszip` MIT OR GPL-3.0) — MIT terms are available, so no copyleft obligation is triggered by choice of MIT. The four LGPL rows are the PostgreSQL client stack (`psycopg*`, LGPL-3.0) and the dev-only `gprof2dot`; LGPL permits dynamic linking without relicensing. `websocket-native` and `require-like` declare no license in registry metadata (check the package repository before redistribution). The 21 AGPL rows are first-party: 20 OpenC3 gems built from the tree (registry 404, not published) plus the pre-release `openc3` 7.1.2b0 Python package listed in `uv.lock`; they carry the repository's own AGPL-3.0/commercial terms, so they add no third-party copyleft obligation.

## Limitations

- Syft was run against the working tree at `v7.2.0` with the three generated `Gemfile.lock` files present; the repo does not commit lockfiles, so gem versions reflect `bundle lock` resolution on 2026-09-28 against rubygems.org, not a vendor-blessed lock.
- Grype's `openc3` gem matches come from GHSA records for the gem; Grype does not evaluate reachability or deployment configuration.
- The `go-module` findings describe the pre-built AnyCable 1.6.14 binaries (checksums match the public GitHub release; see `provenance/PROVENANCE.md`). Fixing them requires a newer upstream AnyCable build, not a manifest change.
- Docker registry pulls were rate-limited (Docker Hub HTTP 429; public ECR data limit), so no container-image SBOM was produced; this is a source-tree SBOM only.
- Registry license lookups cover 2,398 components; 21 first-party/pre-release packages returned 404 and are listed above rather than guessed.
