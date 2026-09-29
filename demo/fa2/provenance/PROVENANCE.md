# Provenance — OpenC3 COSMOS v7.2.0

Target: `achilli444/cosmos-fa2-demo` @ `demo-baseline` = upstream tag `v7.2.0`, commit `77acb91cc2c3b21af3eb981c829285dea96c984e`. History analysed: every commit reachable from `v7.2.0` (`git log v7.2.0`), 2014-12-17 → 2026-06-01. Rendered by `demo/fa2/scripts/render_provenance.py` from `provenance/data/*` (the script asserts the totals against `commits_all.psv`).

Presentation rule: authors are aggregated by e-mail domain and UTC offset. Individual names appear nowhere in this document; commit SHAs are given so any row can be checked with `git show <sha>`.

## 1. Commit history

| Metric | Value |
|---|---|
| Commits reachable from v7.2.0 | 11443 |
| Distinct author e-mails | 88 |
| Distinct author e-mail domains | 28 |
| Commits whose *committer* is `noreply@github.com` (GitHub web UI / merge button / squash) | 2267 (19.8%) |
| Commits whose *author* is a `users.noreply.github.com` address | 720 |

### Commits per year (`data/commits_per_year.csv`, `data/year_by_category.csv`)

| Year | Commits | vendor (openc3.com) | other org domain | github noreply/web | personal webmail | local/unresolvable host |
|---|---|---|---|---|---|---|
| 2014 | 39 | 0 | 39 | 0 | 0 | 0 |
| 2015 | 495 | 0 | 428 | 4 | 63 | 0 |
| 2016 | 152 | 0 | 119 | 0 | 33 | 0 |
| 2017 | 651 | 0 | 618 | 0 | 22 | 11 |
| 2018 | 361 | 0 | 335 | 1 | 15 | 10 |
| 2019 | 235 | 0 | 209 | 2 | 23 | 1 |
| 2020 | 340 | 0 | 335 | 2 | 3 | 0 |
| 2021 | 1333 | 0 | 1321 | 6 | 6 | 0 |
| 2022 | 1436 | 583 | 656 | 63 | 134 | 0 |
| 2023 | 1475 | 1370 | 8 | 90 | 7 | 0 |
| 2024 | 1590 | 1478 | 21 | 84 | 7 | 0 |
| 2025 | 1906 | 1510 | 45 | 260 | 77 | 14 |
| 2026 | 1430 | 1189 | 4 | 208 | 29 | 0 |

Reading: the project was developed under Ball Aerospace domains through 2021 (`ball.com`, `ballaerospace.com`), and the vendor domain `openc3.com` appears from 2022 when the OpenC3 fork began; 2022 is the hand-over year. This is consistent with the public history of the project (Ball Aerospace COSMOS → OpenC3 COSMOS) and is stated here as what the data shows, not as a judgement.

### Author e-mail domains (`data/author_domains.csv`, top 12 of 28)

| Domain | Category | Commits | % | Distinct e-mails |
|---|---|---|---|---|
| openc3.com | vendor (openc3.com) | 6130 | 53.6 | 6 |
| ball.com | other org domain | 3806 | 33.3 | 10 |
| users.noreply.github.com | github noreply/web | 720 | 6.3 | 23 |
| gmail.com | personal webmail | 419 | 3.7 | 19 |
| ballaerospace.com | other org domain | 224 | 2.0 | 5 |
| sdl.usu.edu | other org domain | 42 | 0.4 | 2 |
| (no-domain) | local/unresolvable host | 22 | 0.2 | 1 |
| is4s.com | other org domain | 17 | 0.1 | 2 |
| emilys-macbook-pro.local | local/unresolvable host | 14 | 0.1 | 1 |
| windhoverlabs.com | other org domain | 8 | 0.1 | 1 |
| phillips101.com | other org domain | 7 | 0.1 | 1 |
| turionspace.com | other org domain | 5 | 0.0 | 1 |

### Vendor / personal / other (`data/domain_categories.csv`)

| Category | Commits | % |
|---|---|---|
| vendor (openc3.com) | 6130 | 53.6 |
| other org domain | 4138 | 36.2 |
| github noreply/web | 720 | 6.3 |
| personal webmail | 419 | 3.7 |
| local/unresolvable host | 36 | 0.3 |

Category rules (see `scripts/provenance_stats.py`): vendor = `openc3.com`; personal webmail = fixed list (gmail, yahoo, hotmail, outlook, icloud, protonmail, …); github noreply/web = `*users.noreply.github.com`; local/unresolvable = no `@`, `.local`, or single-label hosts; everything else = other org domain (which therefore includes `ball.com`, `ballaerospace.com`, universities and integrators).

## 2. Author time-zone offsets (`data/tz_offsets.csv`, from `git log --format=%ai`)

| UTC offset | Commits | % |
|---|---|---|
| -0600 | 6353 | 55.5 |
| -0700 | 4347 | 38.0 |
| +0000 | 568 | 5.0 |
| -0500 | 74 | 0.6 |
| -0800 | 50 | 0.4 |
| -0400 | 30 | 0.3 |
| -1000 | 10 | 0.1 |
| +0200 | 6 | 0.1 |
| +0100 | 5 | 0.0 |

What this does and does not indicate: 55.5% of commits carry `-0600` and 38.0% `-0700`, i.e. US Mountain time (MST/MDT) — consistent with both the Ball Aerospace (Colorado) and OpenC3 (Colorado) publicly stated locations; `+0000` (5.0%) is dominated by GitHub-web/CI-authored commits, which are stamped in UTC. The offset is whatever the committing client's clock and locale said at commit time; it is user-supplied metadata, is trivially forgeable, does not identify a person, a nationality, or a physical location, and a low-volume offset is not evidence of anything by itself. It is useful only as a consistency signal: no sustained contributor block appears at an offset inconsistent with the stated developer locations. Per-year breakdown: `data/tz_by_year.csv`.

## 3. First-time contributors touching security-sensitive paths

Definition: for each author e-mail, commits are ordered by author date; a commit is *early* if it is within the author's first N = 5 commits. A commit is reported if it is early and touches at least one path in the sensitive set. Path set — **mandated by the task**: `openc3/lib/openc3/models/auth_model.rb`, `openc3/lib/openc3/utilities/authorization.rb`, `openc3/lib/openc3/utilities/authentication.rb`, `openc3/lib/openc3/models/plugin_model.rb`, `openc3/lib/openc3/models/gem_model.rb`, `openc3/lib/openc3/models/python_package_model.rb`, `openc3/lib/openc3/io/json_drb*.rb`, `openc3/lib/openc3/script/**`, `openc3-cosmos-script-runner-api/app/**`, `openc3-cosmos-cmd-tlm-api/app/controllers/{auth,settings,plugins}_controller.rb`, `openc3/bin/*`, `*/Dockerfile*`, `.github/workflows/**`. **Additions (this analysis)**: `openc3-cosmos-cmd-tlm-api/app/controllers/application_controller.rb`, `openc3-cosmos-script-runner-api/app/controllers/application_controller.rb`, `openc3/lib/openc3/api/**`, `openc3/lib/openc3/utilities/{running_script,script}.rb`, `compose.yaml`, `.env`. Historical paths (pre-rename `cosmos-*/Dockerfile`) match through the `*/Dockerfile*` glob.

Commits touching any sensitive path over the whole history: 1491 (vendor (openc3.com) 1102, other org domain 246, github noreply/web 99, personal webmail 42, local/unresolvable host 2; per domain in `data/sensitive_path_commits_by_domain.csv`).

Early commits (first 5 of an author) touching sensitive paths: **25** (`data/first_time_contributors_sensitive.csv`):

| SHA | Date | Author domain | Category | Author's nth commit | Author total commits | Matched pattern(s) | Files |
|---|---|---|---|---|---|---|---|
| `abd3e1c85d4b` | 2021-07-02 | mailoo.org | other org domain | 2 | 5 | */Dockerfile* | cosmos-redis/Dockerfile |
| `ecf21d00e180` | 2021-07-02 | mailoo.org | other org domain | 3 | 5 | */Dockerfile* | cosmos-frontend-init/Dockerfile |
| `70be2ae5222f` | 2021-09-21 | ballaerospace.com | other org domain | 5 | 50 | */Dockerfile* | cosmos-init/Dockerfile;cosmos-ruby/Dockerfile |
| `f397dd07eedd` | 2022-02-01 | users.noreply.github.com | github noreply/web | 1 | 9 | .github/workflows/** | .github/workflows/build.yml |
| `6ad78b75a3ea` | 2022-07-16 | openc3.com | vendor (openc3.com) | 1 | 3970 | .github/workflows/** | .github/workflows/api_tests.yml;.github/workflows/playwright.yml;.github/workflows/releas… |
| `3f049eb2e2d8` | 2022-07-16 | openc3.com | vendor (openc3.com) | 2 | 3970 | .github/workflows/** | .github/workflows/api_tests.yml |
| `4e23f64b70ce` | 2022-07-22 | openc3.com | vendor (openc3.com) | 4 | 3970 | openc3/lib/openc3/models/plugin_model.rb | openc3/lib/openc3/models/plugin_model.rb |
| `e4119f05ffca` | 2022-07-22 | openc3.com | vendor (openc3.com) | 5 | 3970 | openc3/lib/openc3/api/** | openc3/lib/openc3/api/cmd_api.rb;openc3/lib/openc3/api/tlm_api.rb |
| `ccc9975cfe44` | 2022-07-27 | openc3.com | vendor (openc3.com) | 1 | 1451 | openc3/lib/openc3/script/** | openc3/lib/openc3/script/calendar.rb;openc3/lib/openc3/script/commands.rb;openc3/lib/open… |
| `42febf136cf5` | 2022-07-29 | openc3.com | vendor (openc3.com) | 3 | 1451 | .github/workflows/** | .github/workflows/release.yml |
| `5768b023ab86` | 2023-02-09 | turionspace.com | other org domain | 1 | 5 | .env | .env |
| `4487d9b6250a` | 2023-02-23 | turionspace.com | other org domain | 4 | 5 | openc3/bin/* | openc3/bin/openc3cli |
| `59dfc71ac2d1` | 2023-02-23 | turionspace.com | other org domain | 5 | 5 | openc3/bin/* | openc3/bin/openc3cli |
| `6f7236de9ced` | 2024-03-25 | ssclab.loc | other org domain | 1 | 1 | compose.yaml | compose.yaml |
| `89ba72aac85b` | 2024-06-24 | is4s.com | other org domain | 4 | 14 | .github/workflows/** | .github/workflows/playwright.yml |
| `f39210578682` | 2024-06-26 | is4s.com | other org domain | 3 | 3 | */Dockerfile* | openc3-cosmos-init/Dockerfile |
| `a3a733d21621` | 2025-06-12 | users.noreply.github.com | github noreply/web | 5 | 82 | .github/workflows/** | .github/workflows/generate-docs.yml |
| `e726ed98894c` | 2025-09-14 | gmail.com | personal webmail | 1 | 10 | openc3/lib/openc3/models/plugin_model.rb | openc3/lib/openc3/models/plugin_model.rb |
| `e746b020cd41` | 2025-10-29 | openc3.com | vendor (openc3.com) | 3 | 93 | .github/workflows/** | .github/workflows/eslint.yml |
| `a660b1f6da4b` | 2025-11-03 | gmail.com | personal webmail | 5 | 10 | openc3/lib/openc3/models/plugin_model.rb | openc3/lib/openc3/models/plugin_model.rb |
| `5e243d606080` | 2025-11-04 | sdl.usu.edu | other org domain | 1 | 41 | openc3/bin/* | openc3/bin/openc3cli |
| `c533ce7675d7` | 2025-11-04 | sdl.usu.edu | other org domain | 2 | 41 | openc3/bin/* | openc3/bin/openc3cli |
| `2ffac48ace91` | 2025-11-13 | sdl.usu.edu | other org domain | 5 | 41 | openc3/bin/*;openc3/lib/openc3/models/p… | openc3/bin/openc3cli;openc3/lib/openc3/models/plugin_model.rb |
| `439b62128618` | 2026-03-24 | stepsecurity.io | other org domain | 1 | 1 | .github/workflows/** | .github/workflows/api_tests.yml;.github/workflows/build_ubi.yml;.github/workflows/clamav.… |
| `caaf839934b6` | 2026-04-21 | users.noreply.github.com | github noreply/web | 1 | 1 | openc3/lib/openc3/models/plugin_model.rb | openc3/lib/openc3/models/plugin_model.rb |

Low-volume authors (≤ 5 commits total) with early sensitive-path commits — the subset most worth a second look because there is no later track record to compare against (`data/low_volume_authors_touching_sensitive.csv`):

| Author domain | Category | Author total commits | Sensitive commits | SHAs |
|---|---|---|---|---|
| turionspace.com | other org domain | 5 | 3 | 5768b023ab86;4487d9b6250a;59dfc71ac2d1 |
| mailoo.org | other org domain | 5 | 2 | abd3e1c85d4b;ecf21d00e180 |
| is4s.com | other org domain | 3 | 1 | f39210578682 |
| ssclab.loc | other org domain | 1 | 1 | 6f7236de9ced |
| stepsecurity.io | other org domain | 1 | 1 | 439b62128618 |
| users.noreply.github.com | github noreply/web | 1 | 1 | caaf839934b6 |

Reading: all 6 low-volume rows are Dockerfile / workflow / `.env` / `compose.yaml` / `openc3cli` / `plugin_model.rb` edits from integrator, lab or security-tooling domains, each merged through the vendor's PR process (committer `noreply@github.com` or an `openc3.com` committer — check with `git show --format=%ce <sha>`). `439b62128618` (stepsecurity.io, 20 workflow files) is a workflow-hardening bulk change of the kind that domain publicly produces. Nothing here is a finding; it is the list a reviewer should spot-check.

## 4. Dependency maintainer signals — direct dependencies (167: gem 80, npm 66, pypi 21)

Source: `scripts/registry_metadata.py` → `data/direct_dep_registry.csv`, using `https://rubygems.org/api/v1/gems/<name>/owners.json`, `https://registry.npmjs.org/<name>` (`maintainers`), `https://pypi.org/pypi/<name>/json`. Direct-dependency list from `sbom/data/direct_deps.csv` (Gemfile/gemspec/package.json/pyproject/requirements outside node_modules/templates/examples).

| Signal | gem | npm | pypi |
|---|---|---|---|
| Direct deps queried | 80 | 66 | 21 |
| Single owner/maintainer | 34 | 25 | not available (PyPI JSON API does not expose owners) |
| Maintainer-set change in last 24 months | not available (rubygems.org exposes current owners only) | not available (npm exposes current maintainers only) | not available |
| Install-time scripts | native-extension gems (see below); gemspec `extensions` not exposed by API | 0 of 66 declare `preinstall`/`install`/`postinstall` | 21 of 21 publish an sdist with `setup.py`; network use inside `setup.py` **not verified** (would require downloading each sdist) |

Single-owner direct dependencies (59): `anycable`, `anycable-rails`, `argon2`, `byebug`, `cbor`, `down`, `equivalent-xml`, `faraday-follow_redirects`, `faraday-multipart`, `flay`, `flog`, `hiredis-client`, `mock_redis`, `mqtt`, `openc3`, `opentelemetry-exporter-otlp`, `opentelemetry-instrumentation-action_pack`, `opentelemetry-instrumentation-aws_sdk`, `opentelemetry-instrumentation-faraday`, `opentelemetry-instrumentation-rack`, `opentelemetry-instrumentation-redis`, `opentelemetry-sdk`, `rack-cors`, `rackup`, `rails_semantic_logger`, `rspec`, `rspec-rails`, `rspec_junit_formatter`, `simplecov-cobertura`, `tzinfo-data`, `uuidtools`, `websocket`, `websocket-native`, `yard`, `@braintree/sanitize-url`, `@types/node`, `@types/systemjs`, `@vue-flow/background`, `@vue-flow/controls`, `@vue-flow/core`, `@vue-flow/minimap`, `@vue-flow/node-resizer`, `@vue-flow/node-toolbar`, `axios`, `clsx`, `date-fns`, `date-fns-tz`, `dompurify`, `import-map-overrides`, `lodash`, `lossless-json`, `minisearch`, `muuri`, `pinia`, `single-spa`, `splitpanes`, `sprintf-js`, `uplot`, `vite-plugin-style-inject`. Owner handles are in the CSV; several "single owner" rows are organisation accounts (e.g. `opentelemetry-ruby`, `types`, `braintree`, `cure53`), so single-owner ≠ single-person.

Direct gems that resolve to platform-specific (native-extension) builds in the generated lockfiles: `ffi`, `google-protobuf`, `grpc`, `nokogiri`, `pg`. These compile or ship prebuilt C code at install (`gem install` runs `extconf.rb`); RubyGems does not expose the `extensions` field via the JSON API, so this list is derived from lockfile platform suffixes, not from gemspecs.

Non-registry dependency sources in manifests (7):

| Ecosystem | Name | Constraint | Manifest |
|---|---|---|---|
| gem | openc3 | `:path => ENV['OPENC3_DEVEL']` | openc3-cosmos-cmd-tlm-api/Gemfile |
| gem | openc3 | `:path => ENV['OPENC3_DEVEL']` | openc3-cosmos-script-runner-api/Gemfile |
| gem | openc3 | `:path => ENV['OPENC3_PATH']` | openc3-cosmos-cmd-tlm-api/Gemfile |
| gem | openc3 | `:path => ENV['OPENC3_PATH']` | openc3-cosmos-script-runner-api/Gemfile |
| gem | openc3 | `path: '../../../..'` | openc3/test/integration/tsdb/ruby/Gemfile |
| gem | rexml | `'3.4.4'` | openc3/openc3.gemspec |
| pypi | jsonpath-ng | `jsonpath-ng (>=1.7.0,<2.0.0)` | openc3/python/pyproject.toml |

All are `path:` references to the first-party `openc3` gem for in-tree development (`OPENC3_DEVEL`/`OPENC3_PATH` env gates); no `git:` or URL sources in any Gemfile, package.json, pyproject or requirements file. pnpm workspace packages (`@openc3/*`) are in-tree.

## 5. Vendored artifacts and URL-pinned downloads

Dockerfile `curl`/`wget`/`ADD https://` fetches: **none** (`data/dockerfile_from_and_fetch.txt`; the only `curl` token is `apk add … curl` in `openc3-ruby/Dockerfile:57`). Instead the release tarballs/binaries the images need are **committed to the repository** and copied in at build time. The Dockerfiles run `gem install`/`uv pip install`/`pnpm install` against `RUBYGEMS_URL`/`PYPI_URL`/`NPM_URL` build args (default public registries) and `apk`/`dnf` against distro mirrors. Downloads that do occur happen outside the Dockerfiles: `scripts/release/build_multi_arch.sh:43` and `scripts/linux/openc3_setup.sh:48` fetch `https://curl.se/ca/cacert.pem` (HTTPS, no checksum); `scripts/release/package_audit_lib.rb` fetches release metadata/assets from GitHub, jsDelivr and cdnjs when the maintainers run the package audit (developer tool, not part of the build).

Committed binaries/archives vs. public upstream (`data/vendored_blobs_sha256.tsv`, `data/vendored_blobs_upstream_check.tsv`; upstream files downloaded 2026-09-28 and hashed locally — none of these upstreams publish a checksum file the Dockerfile verifies against):

| Path | Bytes | SHA-256 (local) | Upstream compared | Result |
|---|---|---|---|---|
| `cacert.pem` | 189462 | `86a1f3366afac7c6…` | https://curl.se/ca/cacert.pem (rolling; not version-pinned, see scripts/release… | not comparable (rolling bundle) |
| `openc3-buckets/versitygw_v1.4.1_Linux_arm64.tar.gz` | 20718431 | `489071c11a7efd09…` | https://github.com/versity/versitygw/releases/download/v1.4.1/versitygw_v1.4.1_… | MATCH |
| `openc3-buckets/versitygw_v1.4.1_Linux_x86_64.tar.gz` | 22527100 | `7328b1d3efa0955e…` | https://github.com/versity/versitygw/releases/download/v1.4.1/versitygw_v1.4.1_… | MATCH |
| `openc3-redis/valkey-9.0.4.tar.gz` | 4127664 | `8d65e12cc9edb14d…` | https://github.com/valkey-io/valkey/archive/refs/tags/9.0.4.tar.gz | MATCH |
| `openc3-ruby/anycable-go-linux-amd64` | 38441122 | `efd3107c955a67e5…` | https://github.com/anycable/anycable/releases/download/v1.6.14/anycable-go-linu… | MATCH |
| `openc3-ruby/anycable-go-linux-arm64` | 36110498 | `e518dec0096b9426…` | https://github.com/anycable/anycable/releases/download/v1.6.14/anycable-go-linu… | MATCH |
| `openc3-ruby/htop-3.4.1.tar.gz` | 427538 | `af9ec878f831b7c2…` | https://github.com/htop-dev/htop/archive/refs/tags/3.4.1.tar.gz | MATCH |
| `openc3-ruby/libcsp-6b6e2dd2870bd1f8ab4516123f1fa255d6c1b632.zip` | 897674 | `e6a496825c5f7365…` | https://github.com/libcsp/libcsp/archive/6b6e2dd2870bd1f8ab4516123f1fa255d6c1b6… | MATCH |
| `openc3-ruby/libsocketcan-0.0.12.tar.gz` | 42061 | `e4432d32afa6f34d…` | https://github.com/linux-can/libsocketcan/archive/refs/tags/v0.0.12.tar.gz | MATCH |
| `openc3-ruby/libzmq-34f7fa22022bed9e0e390ed3580a1c83ac4a2834.zip` | 1376048 | `9208b95f9355e821…` | https://github.com/zeromq/libzmq/archive/34f7fa22022bed9e0e390ed3580a1c83ac4a28… | MATCH |
| `openc3-ruby/rbspy-x86_64-unknown-linux-gnu-0.39.0.tar.gz` | 2116720 | `d109d10fff73e7e7…` | https://github.com/rbspy/rbspy/releases/download/v0.39.0/rbspy-x86_64-unknown-l… | MATCH |
| `openc3-ruby/ruby-3.4.7.tar.gz` | 23271433 | `23815a6d095696f7…` | https://cache.ruby-lang.org/pub/ruby/3.4/ruby-3.4.7.tar.gz | MATCH |
| `openc3-ruby/tini-0.19.0.tar.gz` | 32369 | `0fd35a7030052acd…` | https://github.com/krallin/tini/archive/refs/tags/v0.19.0.tar.gz | MATCH |

Reading: every version-pinned artifact matches the public release byte-for-byte. `cacert.pem` is a rolling Mozilla CA bundle (curl.se republishes it on each Mozilla update), so the committed copy can only be dated, not matched. None of the Dockerfiles verify a checksum at build time — integrity rests on git history of the committed blob, which is checkable (13 blobs hashed).

## 6. Container base images (`FROM` lines, 25 in 16 Dockerfiles)

Digest-pinned (`@sha256:`): **0 of 25**. All base references are `${VAR}` expressions resolved from `.env` / Dockerfile `ARG` defaults (column 3 shows the value at `v7.2.0`; the UBI variants substitute `registry1.dso.mil/ironbank/redhat/ubi/ubi9-minimal:9.6`). Multi-stage aliases (`AS …`) reference earlier stages in the same file.

| Dockerfile:line | FROM (as written) | Resolved at v7.2.0 / note | Digest pinned |
|---|---|---|---|
| `openc3-buckets/Dockerfile:7` | `${OPENC3_DEPENDENCY_REGISTRY}/alpine:${ALPINE_VERSION}.${ALPINE_BUILD}` | docker.io/alpine:3.23.4 | no |
| `openc3-buckets/Dockerfile-ubi:6` | `${OPENC3_UBI_REGISTRY}/${OPENC3_UBI_IMAGE}:${OPENC3_UBI_TAG}` | registry1.dso.mil/ironbank/redhat/ubi/ubi9-minimal:9.6 | no |
| `openc3-tsdb/Dockerfile:6` | `${OPENC3_DEPENDENCY_REGISTRY}/${OPENC3_TSDB_IMAGE}:${OPENC3_TSDB_VERS…` | docker.io/questdb/questdb:9.3.5 | no |
| `openc3-tsdb/Dockerfile-ubi:6` | `${OPENC3_DEPENDENCY_REGISTRY}/${OPENC3_TSDB_IMAGE}:${OPENC3_TSDB_VERS…` | docker.io/questdb/questdb:9.3.5-rhel | no |
| `openc3-cosmos-script-runner-api/Dockerfile:6` | `${OPENC3_REGISTRY}/${OPENC3_NAMESPACE}/${OPENC3_IMAGE}:${OPENC3_TAG}` | docker.io/openc3inc/openc3-base:latest | no |
| `openc3-redis/Dockerfile:5` | `${OPENC3_DEPENDENCY_REGISTRY}/${OPENC3_REDIS_IMAGE}:${OPENC3_REDIS_VE…` | docker.io/valkey/valkey:9.1.0-alpine | no |
| `openc3-redis/Dockerfile-ubi:5` | `${OPENC3_UBI_REGISTRY}/${OPENC3_UBI_IMAGE}:${OPENC3_UBI_TAG}` | registry1.dso.mil/ironbank/redhat/ubi/ubi9-minimal:9.6 | no |
| `openc3-redis/Dockerfile-ubi:6` | `base` | stage alias | no |
| `openc3-redis/Dockerfile-ubi:69` | `base` | stage alias | no |
| `openc3-cosmos-init/Dockerfile:9` | `${OPENC3_REGISTRY}/${OPENC3_NAMESPACE}/${OPENC3_NODE_IMAGE}:${OPENC3_…` | docker.io/openc3inc/openc3-node:latest | no |
| `openc3-cosmos-init/Dockerfile:49` | `openc3-frontend-tmp` | stage alias | no |
| `openc3-cosmos-init/Dockerfile:66` | `openc3-frontend-tmp` | stage alias | no |
| `openc3-cosmos-init/Dockerfile:83` | `openc3-frontend-tmp` | stage alias | no |
| `openc3-cosmos-init/Dockerfile:100` | `openc3-frontend-tmp` | stage alias | no |
| `openc3-cosmos-init/Dockerfile:116` | `${OPENC3_REGISTRY}/${OPENC3_NAMESPACE}/${OPENC3_BASE_IMAGE}:${OPENC3_…` | docker.io/openc3inc/openc3-base:latest | no |
| `openc3-cosmos-init/Dockerfile:117` | `openc3-frontend-tmp` | stage alias | no |
| `openc3-cosmos-init/Dockerfile:128` | `${OPENC3_REGISTRY}/${OPENC3_NAMESPACE}/${OPENC3_BASE_IMAGE}:${OPENC3_…` | docker.io/openc3inc/openc3-base:latest | no |
| `openc3-cosmos-cmd-tlm-api/Dockerfile:6` | `${OPENC3_REGISTRY}/${OPENC3_NAMESPACE}/${OPENC3_IMAGE}:${OPENC3_TAG}` | docker.io/openc3inc/openc3-base:latest | no |
| `openc3-traefik/Dockerfile:5` | `${OPENC3_DEPENDENCY_REGISTRY}/traefik:${OPENC3_TRAEFIK_RELEASE}` | docker.io/traefik:v3.7.1 | no |
| `openc3-node/Dockerfile:5` | `${OPENC3_REGISTRY}/${OPENC3_NAMESPACE}/openc3-ruby:${OPENC3_TAG}` | docker.io/openc3inc/openc3-ruby:latest | no |
| `openc3-node/Dockerfile-ubi:5` | `${OPENC3_REGISTRY}/${OPENC3_NAMESPACE}/openc3-ruby-ubi:${OPENC3_TAG}` | docker.io/openc3inc/openc3-ruby-ubi:latest | no |
| `openc3/Dockerfile:6` | `${OPENC3_REGISTRY}/${OPENC3_NAMESPACE}/${OPENC3_IMAGE}:${OPENC3_TAG}` | docker.io/openc3inc/openc3-base:latest | no |
| `openc3-ruby/Dockerfile:7` | `${OPENC3_DEPENDENCY_REGISTRY}/alpine:${ALPINE_VERSION}.${ALPINE_BUILD}` | docker.io/alpine:3.23.4 | no |
| `openc3-ruby/Dockerfile-ubi:5` | `${OPENC3_UBI_REGISTRY}/${OPENC3_UBI_IMAGE}:${OPENC3_UBI_TAG}` | registry1.dso.mil/ironbank/redhat/ubi/ubi9-minimal:9.6 | no |
| `openc3-operator/Dockerfile:6` | `${OPENC3_REGISTRY}/${OPENC3_NAMESPACE}/${OPENC3_IMAGE}:${OPENC3_TAG}` | docker.io/openc3inc/openc3-base:latest | no |

Reading: first-party images (`openc3-*`) chain from `openc3-ruby` (Alpine 3.23.4) or `openc3-ruby-ubi` (Iron Bank UBI9-minimal 9.6). Third-party images: `valkey/valkey:9.1.0-alpine`, `questdb/questdb:9.3.5`, `traefik:v3.7.1`, all tag-pinned, none digest-pinned. `OPENC3_TAG=latest` in `.env` means a default `docker compose` pull is a floating tag; deployments should set `OPENC3_TAG` and pin digests (see `RISK_MEMO.md` remediations).

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
- Author e-mail is self-asserted git metadata; domain ≠ employer, and one person may use several addresses (88 e-mails, 28 domains). Counts are per e-mail, not per person.
- `noreply@github.com` as committer identifies GitHub-side commit creation (web merges, squash merges, suggestions), not the reviewer.
- "First N = 5 commits" is a heuristic window; a contributor's Nth commit may be years after the first.
- Registry APIs expose *current* owners/maintainers; history of ownership transfer is not public via API for RubyGems, npm or PyPI, so "changed in last 24 months" is reported as not available rather than inferred.
- PyPI `setup.py` network behaviour was not inspected (sdists not downloaded); npm hooks were read from the registry `scripts` field of the resolved version; gem `extensions` inferred from lockfile platform suffixes.
- Upstream checksum comparison downloaded the public artifact and hashed it locally; it confirms the committed blob equals today's public release asset, not that the asset is itself trustworthy.
- Docker image pulls were rate-limited during this run (Docker Hub 429, ECR data limit), so base-image digests were not resolved; the "digest pinned" column reflects only what the Dockerfiles state.
