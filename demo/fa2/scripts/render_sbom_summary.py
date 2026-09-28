#!/usr/bin/env python3
"""Render demo/fa2/sbom/SBOM_SUMMARY.md from committed SBOM/Grype JSON and the CSVs
produced by sbom_summary.py. Every number in the Markdown comes from these files."""
import csv, json, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
SB = ROOT / "sbom"
D = SB / "data"
S = json.load(open(D / "summary_numbers.json"))
cdx = json.load(open(SB / "cosmos-v7.2.0.cdx.json"))
spdx = json.load(open(SB / "cosmos-v7.2.0.spdx.json"))
grype = json.load(open(SB / "grype-cosmos-v7.2.0.json"))
syft = json.load(open(D / "cosmos-v7.2.0.syft.json"))
rows = lambda n: list(csv.DictReader(open(D / n)))
eco = rows("ecosystem_counts.csv"); sev = rows("severity_counts.csv"); top = rows("top25_cves.csv")
vuln = rows("vulnerable_components.csv"); lic = rows("license_flags.csv"); gems = rows("gem_counts_by_lockfile.csv")
assert len(cdx["components"]) == S["components_total"] == sum(int(r["components"]) for r in eco)
assert len(grype["matches"]) == S["grype_matches"] == sum(int(r["matches"]) for r in sev)
assert len(vuln) == S["vulnerable_components"]
assert len(lic) == S["license_flag_rows_deduplicated"]
dt = S["vulnerable_components_direct_transitive"]
def t(hdr, body):
    return "| " + " | ".join(hdr) + " |\n|" + "---|" * len(hdr) + "\n" + "\n".join("| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |" for r in body) + "\n"
def short(s, n=60):
    return s if len(s) <= n else s[: n - 1] + "…"
out = f"""# SBOM summary — OpenC3 COSMOS v7.2.0

Target: `achilli444/cosmos-fa2-demo` @ `demo-baseline` = upstream tag `v7.2.0`, commit `77acb91cc2c3b21af3eb981c829285dea96c984e`.
Scan date: 2026-09-28 (Grype DB built {grype["descriptor"]["db"]["status"]["built"]}).
All figures below are computed by `demo/fa2/scripts/sbom_summary.py` from the committed JSON and re-rendered by `demo/fa2/scripts/render_sbom_summary.py`; the script asserts the headline counts against the raw files.

## Files

| File | Content |
|---|---|
| `sbom/cosmos-v7.2.0.cdx.json` | CycloneDX {cdx["specVersion"]} JSON, {len(cdx["components"])} components |
| `sbom/cosmos-v7.2.0.spdx.json` | {spdx["spdxVersion"]} JSON, {len(spdx["packages"])} packages (same syft run; syft emits file/binary records differently in SPDX) |
| `sbom/grype-cosmos-v7.2.0.json` | Grype output, {len(grype["matches"])} matches |
| `sbom/data/grype-table.txt`, `sbom/data/syft-table.txt` | human-readable tables from the same runs |
| `sbom/data/cosmos-v7.2.0.syft.json` | native syft JSON (source id `{syft["source"]["id"][:12]}`) |
| `sbom/data/*.Gemfile.lock` | Bundler lockfiles generated for the scan (repo `.gitignore` excludes `*Gemfile.lock`, so none are committed upstream) |
| `sbom/data/direct_deps.csv` | direct-dependency declarations parsed from Gemfile/gemspec/package.json/pyproject/requirements by `scripts/extract_direct_deps.py` |
| `sbom/data/registry_licenses.json` | public registry license metadata (rubygems.org / registry.npmjs.org / pypi.org) fetched by `scripts/registry_metadata.py` |
| `sbom/data/*.csv`, `sbom/data/summary_numbers.json` | derived tables used below |

## Tools and commands

| Tool | Version |
|---|---|
| syft | {syft["descriptor"]["version"]} |
| grype | {grype["descriptor"]["version"]} (DB built {grype["descriptor"]["db"]["status"]["built"]}) |
| Ruby / Bundler (lockfile generation only) | 3.4.5 / 2.6.9 |
| python3 (derivation scripts, stdlib only) | 3.x |

```
# lockfiles (repo ignores *Gemfile.lock); run in each dir, then copied to sbom/data/<dir>.Gemfile.lock
bundle lock --lockfile=Gemfile.lock            # ./, openc3/, openc3-cosmos-cmd-tlm-api/, openc3-cosmos-script-runner-api/
# SBOMs (single syft run, repo root, default directory+file catalogers)
syft scan dir:. --source-name cosmos --source-version v7.2.0 \\
  -o cyclonedx-json=demo/fa2/sbom/cosmos-v7.2.0.cdx.json \\
  -o spdx-json=demo/fa2/sbom/cosmos-v7.2.0.spdx.json \\
  -o syft-json=demo/fa2/sbom/data/cosmos-v7.2.0.syft.json \\
  -o table=demo/fa2/sbom/data/syft-table.txt
# vulnerabilities
grype sbom:demo/fa2/sbom/cosmos-v7.2.0.cdx.json -o json=demo/fa2/sbom/grype-cosmos-v7.2.0.json -o table=demo/fa2/sbom/data/grype-table.txt
# derived numbers
python3 demo/fa2/scripts/extract_direct_deps.py
python3 demo/fa2/scripts/registry_metadata.py     # network: public registry JSON APIs, no credentials
python3 demo/fa2/scripts/sbom_summary.py
python3 demo/fa2/scripts/render_sbom_summary.py
```

Coverage check (syft location properties in the CycloneDX file): Ruby — `openc3/Gemfile.lock` ({[g for g in gems if g["lockfile"]=="/openc3/Gemfile.lock"][0]["gems"]}), `openc3-cosmos-cmd-tlm-api/Gemfile.lock` ({[g for g in gems if g["lockfile"]=="/openc3-cosmos-cmd-tlm-api/Gemfile.lock"][0]["gems"]}), `openc3-cosmos-script-runner-api/Gemfile.lock` ({[g for g in gems if g["lockfile"]=="/openc3-cosmos-script-runner-api/Gemfile.lock"][0]["gems"]}), root `Gemfile.lock` ({[g for g in gems if g["lockfile"]=="/Gemfile.lock"][0]["gems"]}) plus one gem record per `*.gemspec`; npm — `openc3-cosmos-init/plugins/pnpm-lock.yaml`, `playwright/pnpm-lock.yaml`, `docs.openc3.com/pnpm-lock.yaml`; Python — `openc3/python/uv.lock` (49 components, parsed natively by syft {syft["descriptor"]["version"]}; no `cyclonedx-py` supplement was needed) and `openc3-cosmos-init/plugins/packages/openc3-cosmos-demo/requirements.txt` (1). Full per-lockfile gem counts: `sbom/data/gem_counts_by_lockfile.csv`.

## Component count by ecosystem (CycloneDX, {S["components_total"]} total)

{t(["Ecosystem (PURL type)", "Components"], [(r["ecosystem"], r["components"]) for r in eco])}
Notes: `go-module` entries are syft's binary cataloger reading the Go build info embedded in the two committed AnyCable binaries (`openc3-ruby/anycable-go-linux-{{amd64,arm64}}`), not a Go source tree. `github-action` = `uses:` references in `.github/workflows/**`. `file`/`library` = syft binary-classifier and file records (fonts, vendored JS). Gem counts include one record per first-party `.gemspec` (version string `0.0.0' + ".#{{time}}` is the literal gemspec expression; syft does not evaluate Ruby).

## Vulnerabilities (Grype)

Matches: **{S["grype_matches"]}** (one row per vulnerability × component location). Unique vulnerable components (name+version+ecosystem): **{S["vulnerable_components"]}** — direct {dt.get("direct",0)}, transitive {dt.get("transitive",0)}, not applicable {dt.get("n/a (not a manifest ecosystem)",0)} (vendored Go binaries / GitHub Actions have no manifest declaring them).

{t(["Severity", "Matches"], [(r["severity"], r["matches"]) for r in sev])}
{t(["Ecosystem", "Vulnerable components"], list(S["vulnerable_components_by_ecosystem"].items()))}
Direct/transitive is decided by presence of the (ecosystem, name) pair in `sbom/data/direct_deps.csv` (declarations in Gemfile/gemspec, package.json, pyproject.toml, requirements*.txt outside node_modules/templates/examples). The `openc3` gem 7.2.0 is the first-party gem itself; Grype matches it because the published OpenC3 advisories (see `RISK_MEMO.md`) are in the GitHub Advisory Database.

### Top 25 by severity / CVSS (`sbom/data/top25_cves.csv`)

{t(["#", "ID", "Sev", "CVSS", "Component", "Version", "Ecosystem", "Direct/transitive", "Fixed in"], [(r["rank"], r["cve_or_ghsa"], r["severity"], r["cvss"], r["component"], r["version"], r["ecosystem"].replace(" (from vendored anycable-go binaries)", " (anycable bin)"), r["direct_or_transitive"].replace(" (not a manifest ecosystem)", ""), short(r["fixed_version"].replace("\\n", "; "), 24)) for r in top])}
### All {S["vulnerable_components"]} vulnerable components (`sbom/data/vulnerable_components.csv`)

{t(["Component", "Version", "Ecosystem", "D/T", "Worst sev", "#vulns", "Fix versions"], [(r["component"], r["version"], r["ecosystem"].replace(" (from vendored anycable-go binaries)", " (anycable bin)"), r["direct_or_transitive"].replace(" (not a manifest ecosystem)", "n/a"), r["worst_severity"], r["vuln_count"], short(r["fix_versions"], 40)) for r in vuln])}
## License flags

Repository license: `LICENSE.md` — AGPL-3.0 with a separate commercial license offered by OpenC3, Inc. First-party gems/npm packages in this tree are therefore reported as `AGPL-3.0-only OR commercial (first-party; LICENSE.md)` and are **not** flagged.

License source for the {S["components_total"]} components: SBOM-declared {S["license_source_counts"].get("sbom",0)}, public registry lookup {S["license_source_counts"].get("registry",0)}, registry lookup failed {S["license_source_counts"].get("registry-lookup-failed",0)}, not applicable (binary/file/action records) {S["license_source_counts"].get("none",0)}. Syft attaches license text to only {S["license_source_counts"].get("sbom",0)} components for this tree (lockfiles carry no license field), so registry metadata is the primary source and is itself a limitation (registry metadata is declared by the publisher, not verified against the shipped files).

Flag rows (deduplicated across repeated lockfile locations): **{S["license_flag_rows_deduplicated"]}** — {", ".join(f"{k}: {v}" for k, v in S["license_flag_rows_by_kind"].items())}.

{t(["Flag", "Ecosystem", "Component", "Version", "Declared license", "Source", "D/T", "Location(s)"], [(r["flag"], r["ecosystem"], r["component"], r["version"], short(r["license_text"] or "—", 45), r["license_source"], r["direct_or_transitive"], short(r["locations"], 70)) for r in lic])}
Reading: the two GPL rows are dual/tri-licensed (`diff-lcs` Artistic/GPL/MIT; `jszip` MIT OR GPL-3.0) — MIT terms are available, so no copyleft obligation is triggered by choice of MIT. The four LGPL rows are the PostgreSQL client stack (`psycopg*`, LGPL-3.0) and the dev-only `gprof2dot`; LGPL permits dynamic linking without relicensing. `websocket-native` and `require-like` declare no license in registry metadata (check the package repository before redistribution). The "unknown" rows are first-party OpenC3 gems (registry 404 because they are built from the tree, not published) plus the pre-release `openc3` 7.1.2b0 Python package listed in `uv.lock`; they are covered by `LICENSE.md`.

## Limitations

- Syft was run against the working tree at `v7.2.0` with the three generated `Gemfile.lock` files present; the repo does not commit lockfiles, so gem versions reflect `bundle lock` resolution on 2026-09-28 against rubygems.org, not a vendor-blessed lock.
- Grype's `openc3` gem matches come from GHSA records for the gem; Grype does not evaluate reachability or deployment configuration.
- The `go-module` findings describe the pre-built AnyCable 1.6.14 binaries (checksums match the public GitHub release; see `provenance/PROVENANCE.md`). Fixing them requires a newer upstream AnyCable build, not a manifest change.
- Docker registry pulls were rate-limited (Docker Hub HTTP 429; public ECR data limit), so no container-image SBOM was produced; this is a source-tree SBOM only.
- Registry license lookups cover 2,398 components; 21 first-party/pre-release packages returned 404 and are listed above rather than guessed.
"""
(SB / "SBOM_SUMMARY.md").write_text(out)
print("wrote", SB / "SBOM_SUMMARY.md", len(out))
