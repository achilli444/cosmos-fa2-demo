#!/usr/bin/env python3
"""Render demo/fa2/provenance/PROVENANCE.md from the CSV/JSON/TSV under provenance/data/.
Numbers come from provenance_stats.py, registry_metadata.py and the shell commands listed in Methods."""
import csv, json, pathlib, re, collections
ROOT = pathlib.Path(__file__).resolve().parents[1]
P = ROOT / "provenance"; D = P / "data"; REPO = ROOT.parents[1]
S = json.load(open(D / "summary.json"))
rows = lambda n: list(csv.DictReader(open(D / n)))
tsv = lambda n: list(csv.DictReader(open(D / n), delimiter="\t"))
years = rows("commits_per_year.csv"); doms = rows("author_domains.csv"); cats = rows("domain_categories.csv")
tz = rows("tz_offsets.csv"); ftc = rows("first_time_contributors_sensitive.csv"); low = rows("low_volume_authors_touching_sensitive.csv")
scat = rows("sensitive_path_commits_by_category.csv"); ybc = rows("year_by_category.csv")
reg = rows("direct_dep_registry.csv"); up = tsv("vendored_blobs_upstream_check.tsv"); blobs = tsv("vendored_blobs_sha256.tsv")
direct = list(csv.DictReader(open(ROOT / "sbom" / "data" / "direct_deps.csv")))
psv = sum(1 for _ in open(D / "commits_all.psv"))
assert psv == S["total_commits"] == sum(int(r["commits"]) for r in years) == sum(int(r["commits"]) for r in doms)
def t(hdr, body):
    return "| " + " | ".join(hdr) + " |\n|" + "---|" * len(hdr) + "\n" + "\n".join("| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |" for r in body) + "\n"
def short(s, n=60): return s if len(s) <= n else s[: n - 1] + "…"
# Dockerfile FROM lines
froms = []
for line in open(D / "dockerfile_from_and_fetch.txt"):
    m = re.match(r"\./(\S+?):(\d+):FROM (.+)", line.strip())
    if m: froms.append(m.groups())
env = dict(l.strip().split("=", 1) for l in open(REPO / ".env") if "=" in l and not l.startswith("#"))
args = {}
for f in REPO.glob("openc3-*/Dockerfile*"):
    for l in open(f):
        m = re.match(r"ARG (\w+)=(\S+)", l.strip())
        if m: args.setdefault(m.group(1), m.group(2))
def resolve(s):
    def rep(m):
        k = m.group(1); v = env.get(k) or args.get(k)
        return v if v else "${" + k + "=unset}"
    return re.sub(r"\$\{(\w+)\}", rep, s)
from_rows = []
for path, ln, expr in froms:
    base = expr.split(" AS ")[0].strip()
    stage = " AS " in expr
    internal = base in [e.split(" AS ")[1].strip() for _, _, e in froms if " AS " in e]
    from_rows.append((f"`{path}:{ln}`", f"`{short(base, 70)}`", "stage alias" if internal else resolve(base), "no" if "@sha256:" not in base else "yes"))
digest_pinned = sum(1 for r in from_rows if r[3] == "yes")
# registry signals
single = [r for r in reg if r["owner_count"] == "1"]
by_eco = collections.Counter(r["ecosystem"] for r in reg)
single_eco = collections.Counter(r["ecosystem"] for r in single)
npm_hooks = [r for r in reg if r["ecosystem"] == "npm" and r["install_hooks"] not in ("", "{}", "[]", "None")]
pypi_sdist = sum(1 for r in reg if r["ecosystem"] == "pypi" and "sdist" in r["install_hooks"])
native = sorted({re.match(r"(\S+) \(", l.strip()).group(1) for f in (ROOT / "sbom" / "data").glob("*.Gemfile.lock") for l in open(f) if re.match(r"\s{4}\S+ \(.*-(linux|darwin|mingw|musl)", l)})
nonreg = sorted({(r["ecosystem"], r["name"], r["constraint"].split("#")[0].strip(), r["manifest"]) for r in direct if re.search(r"path|git|file:|link:|workspace:", r["constraint"])})
sens_total = sum(int(r["commits_touching_sensitive"]) for r in scat)
out = f"""# Provenance — OpenC3 COSMOS v7.2.0

Target: `achilli444/cosmos-fa2-demo` @ `demo-baseline` = upstream tag `v7.2.0`, commit `77acb91cc2c3b21af3eb981c829285dea96c984e`. History analysed: every commit reachable from `v7.2.0` (`git log v7.2.0`), {S["first_commit_date"][:10]} → {S["last_commit_date"][:10]}. Rendered by `demo/fa2/scripts/render_provenance.py` from `provenance/data/*` (the script asserts the totals against `commits_all.psv`).

Presentation rule: authors are aggregated by e-mail domain and UTC offset. Individual names appear nowhere in this document; commit SHAs are given so any row can be checked with `git show <sha>`.

## 1. Commit history

| Metric | Value |
|---|---|
| Commits reachable from v7.2.0 | {S["total_commits"]} |
| Distinct author e-mails | {S["distinct_author_emails"]} |
| Distinct author e-mail domains | {S["distinct_author_domains"]} |
| Commits whose *committer* is `noreply@github.com` (GitHub web UI / merge button / squash) | {S["github_web_committer_commits"]} ({100*S["github_web_committer_commits"]/S["total_commits"]:.1f}%) |
| Commits whose *author* is a `users.noreply.github.com` address | {[r for r in doms if r["domain"]=="users.noreply.github.com"][0]["commits"]} |

### Commits per year (`data/commits_per_year.csv`, `data/year_by_category.csv`)

{t(["Year", "Commits"] + list(ybc[0].keys())[1:], [(y["year"], y["commits"]) + tuple(b[k] for k in list(ybc[0].keys())[1:]) for y, b in zip(years, ybc)])}
Reading: the project was developed under Ball Aerospace domains through 2021 (`ball.com`, `ballaerospace.com`), and the vendor domain `openc3.com` appears from 2022 when the OpenC3 fork began; 2022 is the hand-over year. This is consistent with the public history of the project (Ball Aerospace COSMOS → OpenC3 COSMOS) and is stated here as what the data shows, not as a judgement.

### Author e-mail domains (`data/author_domains.csv`, top 12 of {S["distinct_author_domains"]})

{t(["Domain", "Category", "Commits", "%", "Distinct e-mails"], [(r["domain"], r["category"], r["commits"], r["pct"], r["distinct_emails"]) for r in doms[:12]])}
### Vendor / personal / other (`data/domain_categories.csv`)

{t(["Category", "Commits", "%"], [(r["category"], r["commits"], r["pct"]) for r in cats])}
Category rules (see `scripts/provenance_stats.py`): vendor = `openc3.com`; personal webmail = fixed list (gmail, yahoo, hotmail, outlook, icloud, protonmail, …); github noreply/web = `*users.noreply.github.com`; local/unresolvable = no `@`, `.local`, or single-label hosts; everything else = other org domain (which therefore includes `ball.com`, `ballaerospace.com`, universities and integrators).

## 2. Author time-zone offsets (`data/tz_offsets.csv`, from `git log --format=%ai`)

{t(["UTC offset", "Commits", "%"], [(r["utc_offset"], r["commits"], r["pct"]) for r in tz])}
What this does and does not indicate: {tz[0]["pct"]}% of commits carry `-0600` and {tz[1]["pct"]}% `-0700`, i.e. US Mountain time (MST/MDT) — consistent with both the Ball Aerospace (Colorado) and OpenC3 (Colorado) publicly stated locations; `+0000` ({tz[2]["pct"]}%) is dominated by GitHub-web/CI-authored commits, which are stamped in UTC. The offset is whatever the committing client's clock and locale said at commit time; it is user-supplied metadata, is trivially forgeable, does not identify a person, a nationality, or a physical location, and a low-volume offset is not evidence of anything by itself. It is useful only as a consistency signal: no sustained contributor block appears at an offset inconsistent with the stated developer locations. Per-year breakdown: `data/tz_by_year.csv`.

## 3. First-time contributors touching security-sensitive paths

Definition: for each author e-mail, commits are ordered by author date; a commit is *early* if it is within the author's first N = 5 commits. A commit is reported if it is early and touches at least one path in the sensitive set. Path set — **mandated by the task**: `openc3/lib/openc3/models/auth_model.rb`, `openc3/lib/openc3/utilities/authorization.rb`, `openc3/lib/openc3/utilities/authentication.rb`, `openc3/lib/openc3/models/plugin_model.rb`, `openc3/lib/openc3/models/gem_model.rb`, `openc3/lib/openc3/models/python_package_model.rb`, `openc3/lib/openc3/io/json_drb*.rb`, `openc3/lib/openc3/script/**`, `openc3-cosmos-script-runner-api/app/**`, `openc3-cosmos-cmd-tlm-api/app/controllers/{{auth,settings,plugins}}_controller.rb`, `openc3/bin/*`, `*/Dockerfile*`, `.github/workflows/**`. **Additions (this analysis)**: `openc3-cosmos-cmd-tlm-api/app/controllers/application_controller.rb`, `openc3-cosmos-script-runner-api/app/controllers/application_controller.rb`, `openc3/lib/openc3/api/**`, `openc3/lib/openc3/utilities/{{running_script,script}}.rb`, `compose.yaml`, `.env`. Historical paths (pre-rename `cosmos-*/Dockerfile`) match through the `*/Dockerfile*` glob.

Commits touching any sensitive path over the whole history: {sens_total} ({", ".join(f'{r["category"]} {r["commits_touching_sensitive"]}' for r in scat)}; per domain in `data/sensitive_path_commits_by_domain.csv`).

Early commits (first 5 of an author) touching sensitive paths: **{len(ftc)}** (`data/first_time_contributors_sensitive.csv`):

{t(["SHA", "Date", "Author domain", "Category", "Author's nth commit", "Author total commits", "Matched pattern(s)", "Files"], [(f"`{r['sha']}`", r["date"], r["author_domain"], r["category"], r["nth_commit_of_author"], r["author_total_commits"], short(r["matched_patterns"], 40), short(r["files"], 90)) for r in ftc])}
Low-volume authors (≤ 5 commits total) with early sensitive-path commits — the subset most worth a second look because there is no later track record to compare against (`data/low_volume_authors_touching_sensitive.csv`):

{t(["Author domain", "Category", "Author total commits", "Sensitive commits", "SHAs"], [(r["author_domain"], r["category"], r["author_total_commits"], r["commits_touching_sensitive"], r["shas"]) for r in low])}
Reading: all {len(low)} low-volume rows are Dockerfile / workflow / `.env` / `compose.yaml` / `openc3cli` / `plugin_model.rb` edits from integrator, lab or security-tooling domains, each merged through the vendor's PR process (committer `noreply@github.com` or an `openc3.com` committer — check with `git show --format=%ce <sha>`). `439b62128618` (stepsecurity.io, 20 workflow files) is a workflow-hardening bulk change of the kind that domain publicly produces. Nothing here is a finding; it is the list a reviewer should spot-check.

## 4. Dependency maintainer signals — direct dependencies ({len(reg)}: gem {by_eco["gem"]}, npm {by_eco["npm"]}, pypi {by_eco["pypi"]})

Source: `scripts/registry_metadata.py` → `data/direct_dep_registry.csv`, using `https://rubygems.org/api/v1/gems/<name>/owners.json`, `https://registry.npmjs.org/<name>` (`maintainers`), `https://pypi.org/pypi/<name>/json`. Direct-dependency list from `sbom/data/direct_deps.csv` (Gemfile/gemspec/package.json/pyproject/requirements outside node_modules/templates/examples).

| Signal | gem | npm | pypi |
|---|---|---|---|
| Direct deps queried | {by_eco["gem"]} | {by_eco["npm"]} | {by_eco["pypi"]} |
| Single owner/maintainer | {single_eco.get("gem",0)} | {single_eco.get("npm",0)} | not available (PyPI JSON API does not expose owners) |
| Maintainer-set change in last 24 months | not available (rubygems.org exposes current owners only) | not available (npm exposes current maintainers only) | not available |
| Install-time scripts | native-extension gems (see below); gemspec `extensions` not exposed by API | {len(npm_hooks)} of {by_eco["npm"]} declare `preinstall`/`install`/`postinstall` | {pypi_sdist} of {by_eco["pypi"]} publish an sdist with `setup.py`; network use inside `setup.py` **not verified** (would require downloading each sdist) |

Single-owner direct dependencies ({len(single)}): {", ".join(f"`{r['name']}`" for r in single)}. Owner handles are in the CSV; several "single owner" rows are organisation accounts (e.g. `opentelemetry-ruby`, `types`, `braintree`, `cure53`), so single-owner ≠ single-person.

Direct gems that resolve to platform-specific (native-extension) builds in the generated lockfiles: {", ".join(f"`{n}`" for n in native)}. These compile or ship prebuilt C code at install (`gem install` runs `extconf.rb`); RubyGems does not expose the `extensions` field via the JSON API, so this list is derived from lockfile platform suffixes, not from gemspecs.

Non-registry dependency sources in manifests ({len(nonreg)}):

{t(["Ecosystem", "Name", "Constraint", "Manifest"], [(e, n, f"`{short(c, 45)}`", m) for e, n, c, m in nonreg])}
All are `path:` references to the first-party `openc3` gem for in-tree development (`OPENC3_DEVEL`/`OPENC3_PATH` env gates); no `git:` or URL sources in any Gemfile, package.json, pyproject or requirements file. pnpm workspace packages (`@openc3/*`) are in-tree.

## 5. Vendored artifacts and URL-pinned downloads

Dockerfile `curl`/`wget`/`ADD https://` fetches: **none** (`data/dockerfile_from_and_fetch.txt`; the only `curl` token is `apk add … curl` in `openc3-ruby/Dockerfile:57`). Instead the release tarballs/binaries the images need are **committed to the repository** and copied in at build time. The Dockerfiles run `gem install`/`uv pip install`/`pnpm install` against `RUBYGEMS_URL`/`PYPI_URL`/`NPM_URL` build args (default public registries) and `apk`/`dnf` against distro mirrors. Downloads that do occur happen outside the Dockerfiles: `scripts/release/build_multi_arch.sh:43` and `scripts/linux/openc3_setup.sh:48` fetch `https://curl.se/ca/cacert.pem` (HTTPS, no checksum); `scripts/release/package_audit_lib.rb` fetches release metadata/assets from GitHub, jsDelivr and cdnjs when the maintainers run the package audit (developer tool, not part of the build).

Committed binaries/archives vs. public upstream (`data/vendored_blobs_sha256.tsv`, `data/vendored_blobs_upstream_check.tsv`; upstream files downloaded 2026-09-28 and hashed locally — none of these upstreams publish a checksum file the Dockerfile verifies against):

{t(["Path", "Bytes", "SHA-256 (local)", "Upstream compared", "Result"], [(f"`{r['path']}`", r["bytes"], f"`{r['sha256_local'][:16]}…`", short(r["upstream_url_compared"], 80), r["result"]) for r in up])}
Reading: every version-pinned artifact matches the public release byte-for-byte. `cacert.pem` is a rolling Mozilla CA bundle (curl.se republishes it on each Mozilla update), so the committed copy can only be dated, not matched. None of the Dockerfiles verify a checksum at build time — integrity rests on git history of the committed blob, which is checkable ({len(blobs)} blobs hashed).

## 6. Container base images (`FROM` lines, {len(froms)} in {len({p for p,_,_ in froms})} Dockerfiles)

Digest-pinned (`@sha256:`): **{digest_pinned} of {len(froms)}**. All base references are `${{VAR}}` expressions resolved from `.env` / Dockerfile `ARG` defaults (column 3 shows the value at `v7.2.0`; the UBI variants substitute `registry1.dso.mil/ironbank/redhat/ubi/ubi9-minimal:9.6`). Multi-stage aliases (`AS …`) reference earlier stages in the same file.

{t(["Dockerfile:line", "FROM (as written)", "Resolved at v7.2.0 / note", "Digest pinned"], from_rows)}
Reading: first-party images (`openc3-*`) chain from `openc3-ruby` (Alpine {env.get("ALPINE_VERSION")}.{env.get("ALPINE_BUILD")}) or `openc3-ruby-ubi` (Iron Bank UBI9-minimal 9.6). Third-party images: `valkey/valkey:{args.get("OPENC3_REDIS_VERSION")}`, `questdb/questdb:{args.get("OPENC3_TSDB_VERSION")}`, `traefik:{args.get("OPENC3_TRAEFIK_RELEASE")}`, all tag-pinned, none digest-pinned. `OPENC3_TAG=latest` in `.env` means a default `docker compose` pull is a floating tag; deployments should set `OPENC3_TAG` and pin digests (see `RISK_MEMO.md` remediations).

## 7. Methods

```
git rev-parse --is-shallow-repository                       # false after `git fetch upstream --tags`
git log v7.2.0 --format='%H|%ae|%ai|%ci|%ce' > demo/fa2/provenance/data/commits_all.psv
git log v7.2.0 --format='@@%H|%ae|%ai' --name-only > demo/fa2/provenance/data/commits_files.txt
python3 demo/fa2/scripts/provenance_stats.py                # -> summary.json, *.csv (domains, tz, years, sensitive paths)
python3 demo/fa2/scripts/extract_direct_deps.py             # -> sbom/data/direct_deps.csv
python3 demo/fa2/scripts/registry_metadata.py               # -> data/direct_dep_registry.csv, sbom/data/registry_licenses.json
grep -nE '^FROM|curl|wget|ADD https' */Dockerfile* > demo/fa2/provenance/data/dockerfile_from_and_fetch.txt
git ls-files -z | xargs -0 file --mime-type | grep -vE 'text/|inode/'    # binary inventory (heuristics/data/binary_files.tsv)
sha256sum <committed blobs> ; curl -fsSL <upstream url> | sha256sum       # data/vendored_blobs_upstream_check.tsv
python3 demo/fa2/scripts/render_provenance.py
```

Limitations:
- Author e-mail is self-asserted git metadata; domain ≠ employer, and one person may use several addresses (88 e-mails, {S["distinct_author_domains"]} domains). Counts are per e-mail, not per person.
- `noreply@github.com` as committer identifies GitHub-side commit creation (web merges, squash merges, suggestions), not the reviewer.
- "First N = 5 commits" is a heuristic window; a contributor's Nth commit may be years after the first.
- Registry APIs expose *current* owners/maintainers; history of ownership transfer is not public via API for RubyGems, npm or PyPI, so "changed in last 24 months" is reported as not available rather than inferred.
- PyPI `setup.py` network behaviour was not inspected (sdists not downloaded); npm hooks were read from the registry `scripts` field of the resolved version; gem `extensions` inferred from lockfile platform suffixes.
- Upstream checksum comparison downloaded the public artifact and hashed it locally; it confirms the committed blob equals today's public release asset, not that the asset is itself trustworthy.
- Docker image pulls were rate-limited during this run (Docker Hub 429, ECR data limit), so base-image digests were not resolved; the "digest pinned" column reflects only what the Dockerfiles state.
"""
(P / "PROVENANCE.md").write_text(out)
print("wrote", P / "PROVENANCE.md", len(out))
