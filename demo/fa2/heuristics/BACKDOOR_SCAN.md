# Backdoor / malware heuristics — OpenC3 COSMOS v7.2.0

Target: `achilli444/cosmos-fa2-demo` @ `demo-baseline` = `v7.2.0`, commit `77acb91cc2c3b21af3eb981c829285dea96c984e`. Scan date 2026-09-28. Primary scope: `openc3/lib/openc3`, `openc3/python/openc3`, `openc3-cosmos-cmd-tlm-api/app`, `openc3-cosmos-script-runner-api/{app,scripts}`, `openc3-cosmos-init/plugins/packages`; credential, blob and binary sweeps are repo-wide. Raw output: `heuristics/data/*` (hit counts below are `wc -l` of the matching-line files; pattern-header lines excluded).

## Verdict table

| Heuristic | Raw hits | Confirmed suspicious | Notes |
|---|---|---|---|
| Ruby dynamic execution (`eval`, `*_eval`, `send`/`public_send`/`__send__`, backticks, `system`, `spawn`, `Open3`, `IO.popen`, `Marshal.load`, `ERB.new`) | 95 (`rg_ruby_dynamic_exec.txt`) + 103 extra-pattern lines (`rg_extra_patterns.txt`) | **0** backdoor; **4** exploitable-by-published-advisory at this tag; remainder by-design (auth-gated scripting engine), hardened, or internal-constant | see §1 |
| Python dynamic execution (`eval`/`exec`/`pickle`/`subprocess(shell=True)`) | 28 | 0 | Script Runner / conversion engine mirrors of the Ruby paths; no `pickle.loads`, no `shell=True` |
| JS/Vue (`eval`, `new Function`, `innerHTML`, `v-html`) | 19 | 0 backdoor; 1 exploitable (published) | 12 are inside vendored Vue/Vuetify/import-map-overrides bundles; `ButtonWidget.vue` `eval` is the GHSA-gvf2-2rh5-mpgf XSS sink; two `v-html` sites are DOMPurify-sanitised |
| `YAML.load` (non-safe), `constantize`, `pickle.loads`, `subprocess(shell=True)` | 0 | 0 | absent in scope |
| Long base64/hex literals | 7 | 0 | 2 HTML `data:image/png;base64` in generated docs, 2 docs webpack chunks, 1 vendored CSS, 2 Rails `credentials.yml.enc` (expected encrypted blobs; keys not in tree) |
| `Base64.decode64`/`atob` feeding `eval`/`require` | 21 decode sites / **0** feeding code execution | 0 | decoded data goes to packet templates, file writes, display, tests |
| Network calls in install hooks / Rakefiles / gemspecs / `openc3/bin/*` / init / scripts / Dockerfiles | 158 lines (63 in gemspec/Rakefile/Dockerfile) | 0 | no `postinstall` in any npm package; Rakefiles only run `gem build`; downloads are HTTPS to fixed hosts (curl.se, github.com, jsDelivr) in release/setup scripts, none checksum-verified; two `Net::HTTP.start` calls in `plugins_controller.rb` are plain HTTP **to localhost/host.docker.internal only** |
| Hard-coded credentials (`rg`) | 37 | 0 hidden credentials | fixtures/specs/docs, env-var *names*, one committed test **private key** (`examples/openc3-cosmos-mqtt-test/client.key`, public MQTT test fixture), documented `.env` defaults |
| gitleaks (`detect --no-git`) | 22 | 0 | 1 private-key (same MQTT fixture), 20 `generic-api-key` in docs/specs/generated search index/`.env` `SECRET_KEY_BASE`, 1 `curl-auth-user` in `compose.yaml` healthcheck using `$${VAR}` |
| CVE-2025-28388 cross-reference | n/a | 0 at v7.2.0 | no literal credential removed in the v6.0.1→v6.0.2 auth diff; `OPENC3_SERVICE_PASSWORD` default persists unchanged in `.env` at v6.0.1, v6.0.2 and v7.2.0 and is a **documented default** — see §5 |
| Binary inventory (`git ls-files` + `file`) | 867 files | 0 | 793 images/fonts/icons, 54 target fixtures/data, 2 ELF (AnyCable) + 10 tar.gz/zip release archives all matching public upstream hashes; `openc3/ext/**` is C **source** (13 `.c`, 12 `.rb`), no `.so/.dll/.jar/.pyc/.gem/.whl` |
| semgrep (`p/ruby`, `p/security-audit`, `p/python`, `p/javascript`) | 29 findings, 1543 files | 0 | 25 `python.lang` (`exec`/`eval` detected — same sites as above), 1 `ruby.lang` weak-hash SHA1 (`environment_controller.rb:65`, used as a Redis key, not for security), 3 `ruby.rails` `avoid-tainted-file-access` (`packages_controller.rb:86`, `storage_controller.rb:326,727` — admin/`authorization`-gated file paths; not re-traced here); 3 tool errors (1 parse error, 2 rule timeouts on vendored `vue.global-3.5.35.js`) |

Bottom line: no evidence of an intentionally hidden execution path, covert credential, exfiltration channel or tampered binary. COSMOS is a command-and-control framework whose core feature (Script Runner, conversions, screen definitions, plugin install) is *executing operator-supplied code under authentication*; the dynamic-execution hits are that feature. The security-relevant residue is (a) the four published advisories that make some of those paths reachable with less privilege than intended, all fixed in 7.3.0/7.4.0, and (b) deployment defaults that must be changed.

## 1. Dynamic code execution — notable hits with trace and triage

Legend: **exploitable** = reachable with less than the intended privilege per a published advisory at this tag; **by-design (auth)** = intended execution of operator-supplied code behind `authorization(...)`; **hardened** = input constrained before execution; **internal** = argument is a compile-time constant or internal object, no user data; **test-only**.

| File:line | Construct | Input source / trace | Verdict |
|---|---|---|---|
| `openc3/lib/openc3/io/json_drb.rb:261,263` | `@object.public_send(request.method…, *params)` | JSON-RPC method name from any authenticated API caller → `DANGEROUS_METHODS` denylist (`json_rpc.rb:230`: `__send__`, `send`, `instance_eval`, `instance_exec`) or optional whitelist | **exploitable** — GHSA-q2gf-g584-w94p / CVE-2026-92166: denylist does not cover inherited methods; fixed 7.3.0. Authenticated only. |
| `openc3/lib/openc3/models/plugin_model.rb:288` | `` `/openc3/bin/pipinstall #{pip_args}` `` with `pip_args = "-i #{pypi_url} #{gem_path}"` | `pypi_url` from `SettingModel` `pypi_url` (admin-writable setting) / `PYPI_URL` env; interpolated into a shell string | **exploitable** — GHSA-vp3w-52v9-q57f / CVE-2026-77601 (authenticated OS command injection); fixed 7.3.0. Compare `python_package_model.rb:95,103` which uses array-form `spawn([...] + pip_args)` (hardened). |
| `openc3/lib/openc3/utilities/running_script.rb:258,260,1023,1025,1346` | `eval(instrumented_script, binding…)` / `Object.class_eval` | Script text from Script Runner API (`openc3-cosmos-script-runner-api`), `authorization('script_run')`; `suiteRunner` parameters interpolated into generated Ruby | **by-design (auth)** for script bodies; **exploitable** for `suiteRunner` params — GHSA-hf9c-xwpr-cjvr / CVE-2026-92169 (bypasses script-approval lifecycle control); fixed 7.4.0. |
| `openc3/lib/openc3/utilities/bucket_utilities.rb:44` | `Object.class_eval(text, path, 1)` | `load`/`require` from a running script → path restricted to relative `TARGET/…` files (`bucket_utilities.rb:33-34` raises `LoadError` otherwise) → `TargetFile.body` from bucket | **by-design (auth)** + **hardened** (path check); target files are operator-deployed plugin content |
| `openc3/lib/openc3/conversions/generic_conversion.rb:54` | `eval(@code_to_eval)` | `GENERIC_CONVERSION` blocks in cmd/tlm definition files (plugin/target config) | **by-design (auth)** — config-as-code; reachable by whoever can write target config. GHSA-jjq7-m736-w977 / CVE-2026-77602 (fixed 7.3.0) is exactly this class: user-writable `targets_modified/` overlay lets an authenticated user inject definitions → RCE. **exploitable** at this tag. |
| `openc3/lib/openc3/models/{target,tool,microservice,widget}_model.rb` (ERB `.result(binding…)`), `config_parser.rb:166,402`, `meta_config_parser.rb:51`, `cli_generator.rb:346` | `ERB.new(data).result(binding)` | Plugin `plugin.txt`/target config files during plugin install (`authorization('admin')`) and CLI generation | **by-design (auth)** — plugin install is arbitrary-code by definition (plugins are gems); admin-only |
| `openc3-cosmos-cmd-tlm-api/app/controllers/redis_controller.rb:37,39` | `Store.instance.public_send(command, args)` | raw request body split on spaces; `DISALLOWED_COMMANDS = ['AUTH']` (line 19) | **by-design (auth)** — `authorization('admin')` at line 24 (admin Redis console). Denylist is minimal: an admin can `CONFIG`, `FLUSHALL`, `EVAL` (Redis Lua). Not a privilege escalation (admin already owns the data store) but a large blast radius for a UI feature. |
| `openc3-cosmos-cmd-tlm-api/app/controllers/{plugins,scopes,storage}_controller.rb:204,220,59,530`, `models/gem_model.rb:61`, `python_package_model.rb:95,103` | `ProcessManager.instance.spawn([...array...])` | admin-authorized controllers; arguments passed as array (no shell) | **hardened** (array exec, no interpolation) |
| `openc3/lib/openc3/top_level.rb:154` `Marshal.load(data)` | `data` comes from the same process' `Marshal.dump` in `OpenC3.marshal_load` after `File.exist?` check on an internal path | internal |
| `openc3/lib/openc3/top_level.rb:182,197` `system(command)`, `Open3.capture2e(command)` | `OpenC3.run_process` helpers; callers pass fixed strings (`openc3cli` subcommands) | internal |
| `openc3/lib/openc3/utilities/script.rb:315,386,427` `Open3.capture2e("#{process_name} \"#{runner_path}\" … \"#{tf.path}\"")` | `process_name` is `ruby`/`python`, `tf.path` a `Tempfile` created by the server; script text goes into the tempfile, not the command line | **hardened** (syntax-check pre-flight, no user data in argv) |
| `openc3/lib/openc3/script/api_shared.rb:750,777,830,843,881` `eval(exp_to_eval)` | `wait_check`/`check_expression` — expression strings written by the operator in their own script | **by-design (auth)** — executes inside the operator's already-running script context |
| `openc3/lib/openc3/core_ext/class.rb:50-67` `class_eval("def #{arg}…")` | `arg` = symbol literals at class-definition time (`instance_attr_accessor`) | internal |
| `openc3/lib/openc3/packets/packet_config.rb:600-696`, `parsers/xtce_converter.rb:452-761`, `utilities/simulated_target.rb:49` | `public_send("#{keyword}=")` with keyword from config parser / XTCE element names | **hardened** — keyword validated against parser grammar (`ConfigParser.verify_num_parameters`, fixed keyword tables); target config is operator-deployed |
| `openc3/lib/openc3/io/{udp_sockets,io_multiplexer}.rb`, `interfaces/tcpip_server_interface.rb`, `topics/topic.rb`, `utilities/store_{autoload,queued}.rb`, `script/{telemetry,limits,suite}.rb`, `utilities/reingest_job.rb:155`, `cli_generator.rb:702-705` | `public_send`/`send`/`__send__` delegation | method names are internal constants or `method_missing` forwarding to Redis/socket clients | internal |
| `openc3/lib/openc3/io/posix_serial_driver.rb:53` `Kernel.open(port_name, …)` | interface config `port_name` (e.g. `/dev/ttyUSB0`); Ruby `open` treats a leading `|` as a pipe | **hardened in practice** — set by admin in interface definition (plugin install); flag for defence-in-depth (`File.open` would remove the pipe semantics) |
| `openc3/python/openc3/utilities/running_script.py:236,646,652,1090,1443,1453`, `utilities/bucket_utilities.py:46`, `script/__init__.py:216`, `script/limits.py:33`, `script/api_shared.py:591,887-1060`, `api/api_shared.py:806-973`, `conversions/generic_conversion.py:72-73` | `exec`/`eval` | Python mirrors of the Ruby Script Runner / conversion / `check_expression` paths above | **by-design (auth)** (same authorization gates; the Python runner is launched by the Ruby API with the operator's token) |
| `openc3-cosmos-script-runner-api/scripts/run_suite_analysis.py:42,55` `exec(text, globals())` | suite file fetched from bucket (`TargetFile.body`) and executed to enumerate suites | **by-design (auth)** — invoked by Script Runner for operator scripts |
| `openc3/python/openc3/top_level.py:146,148,171`, `utilities/bucket.py:33,36`, `utilities/metric.py:143` `importlib.import_module` | module names from `OPENC3_CLOUD` env / fixed strings | internal |
| `openc3-cosmos-init/plugins/packages/openc3-vue-common/src/widgets/ButtonWidget.vue:78,109,143` `eval(lines[i])` / `eval(this.lastCmd)` | second parameter of a `BUTTON` widget in a telemetry screen definition, split on `;;` | **exploitable** — GHSA-gvf2-2rh5-mpgf / CVE-2026-77394: screens are user-editable and shared across users → stored cross-user XSS/JS execution in the browser; fixed 7.3.0. Historically by design (screen buttons run JS). |
| `openc3-vue-common/src/tools/base/UserMenu.vue:103-104` `v-html="sanitizeNews(newsItem.body)"`, `plugins/dialog/ConfirmDialog.vue:29-31` `v-html="sanitizedText"` | news feed body / dialog text → `DOMPurify.sanitize` (`UserMenu.vue:197-198`, `ConfirmDialog.vue:101-102`) | **hardened**. Note the news *write* path is GHSA-jmg5-qfmh-4jh3 / CVE-2026-92168 (missing authorization in `update_news`, fixed 7.4.0) — an unauthenticated writer can only place sanitised HTML. |
| `openc3-tool-base/public/js/vue.global-3.5.35.js:16060,18471,8027,10928,17820,17823,17909-17910`, `vue.global.prod-3.5.35.min.js`, `vuetify-labs-3.12.2.min.js`, `import-map-overrides-6.1.0.min.js` | `new Function`, `innerHTML`, `eval` inside vendored framework bundles | third-party library internals (Vue runtime compiler, Vuetify, import-map-overrides) — `library` records in the SBOM | internal (vendored; versions listed in `sbom/`) |

Counting: of the 95 Ruby lines, 6 are comments/denylist definitions, 34 are `public_send`/`send` delegation with internal method names, 9 are ERB template rendering at plugin install, 12 are array-form `spawn`/`Open3` with server-controlled argv, and the rest are the Script-Runner/conversion `eval` family. Four constructs are exploitable at this tag **because of published advisories**, not because of hidden functionality.

## 2. Obfuscated / encoded blobs (`rg_long_blobs.txt`, `rg_base64_decode.txt`)

Pattern: `[A-Za-z0-9+/=]{200,}` and `[0-9a-fA-F]{200,}` over `git ls-files`, excluding `*.png|*.jpg|*.gif|*.svg|*.woff*|*.ttf|*.eot|*.ico|*.bin|*.gz|*.zip|*.lock|pnpm-lock.yaml|uv.lock|*.map|*.min.js|*.min.css|node_modules|docs/assets` (fonts, images, minified bundles, lockfiles and the generated Docusaurus site are excluded because they are legitimately dense). 7 hits remain: `docs/docs/tools/{cmd-tlm-server,data-extractor}.html` (inline `data:image/png;base64` screenshots), `docs/assets/js/{d5d77c37.f20151fb,43652efd.f8f78972}.js` (webpack chunks embedding the same images), `openc3-tool-base/public/css/vuetify-labs-3.12.2.min.css` (font data URI), and `openc3-cosmos-{cmd-tlm,script-runner}-api/config/credentials.yml.enc` (Rails encrypted credentials; `config/master.key` is **not** in the tree — `git ls-files | grep master.key` returns nothing — so these blobs are undecryptable without the deployment key and are a standard Rails artifact).

Base64 decoding sites: 21. Ruby/Python: `packet_config.rb:623` / `packet_config.py:790` (`TEMPLATE_ENCODED` keyword → packet template bytes), `questdb_client.{rb,py}` (binary column values), `script/packages.rb:113` (file download written to disk), tests. JS: `atob` on API `contents` fields for display/download in Bucket Explorer, Table Manager, Script Runner, Admin tabs, `FiledisplayWidget`, `FilechecksumWidget`, `PluginProps.js:104` (image). **None** pipes decoded output into `eval`, `require`, `load`, `Function` or `import`.

## 3. Network behaviour in install/build paths (`rg_install_network.txt`)

- npm: none of the 66 direct packages, and no in-tree `package.json`, declares `preinstall`/`install`/`postinstall` (`provenance/data/direct_dep_registry.csv`, `install_hooks` column).
- Rakefiles (`openc3-cosmos-init/plugins/packages/*/Rakefile`, e.g. `openc3-cosmos-tool-admin/Rakefile:37`): `system("gem build #{PLUGIN_NAME}")` — constant, local. Rakefile hits in the raw file are rubydoc.info URLs in comments.
- gemspecs: `s.homepage` URLs only; no `extensions` in first-party gemspecs.
- `openc3/bin/openc3cli`: reads `OPENC3_CLOUD`/bucket policy env; network is to the configured bucket/Redis. `openc3/bin/pipinstall`: `uv pip install "$@"` against whatever `-i` index the caller passes (see plugin_model finding above).
- Dockerfiles: no `curl`/`wget`/`ADD https://`; package managers hit `RUBYGEMS_URL`/`PYPI_URL`/`NPM_URL` args (default public registries, HTTPS) and `apk`/`dnf` mirrors. Committed release blobs are copied in (hash-verified against upstream in `provenance/PROVENANCE.md §5`).
- `scripts/linux/openc3_setup.sh:48`, `scripts/release/build_multi_arch.sh:43`: `curl -q -L https://curl.se/ca/cacert.pem`; `scripts/windows/openc3_setup.bat:35`: PowerShell download of the same URL — fixed host, HTTPS (default TLS verification), no checksum.
- `scripts/release/package_audit_lib.rb`: maintainer tool; `Faraday` GETs to `api.github.com`, `registry.npmjs.org`, `pypi.org`, `registry.hub.docker.com`, `quay.io`; backtick `curl` to `cdnjs.cloudflare.com` (lines 732-737) / `cdn.jsdelivr.net` (791-826) and **plain-HTTP** `dl-cdn.alpinelinux.org` listings (lines 398, 409, 423) — read-only version checks, not executed at build.
- Runtime, not install: `plugins_controller.rb:47,62` `Net::HTTP.start(host, port)` without `use_ssl` — but the host is forced to `localhost`/`127.0.0.1`/`host.docker.internal` (line 36) for the local plugin-store probe; `openc3/lib/openc3/script/{storage,packages,plugins}.rb` use `use_ssl: uri.scheme == 'https'` against the configured API host.

## 4. Hard-coded credentials (`rg_credentials.txt`, `gitleaks-tree.json`)

Patterns: `password|passwd|secret|token|api_key|AKIA|-----BEGIN|Authorization:` (case-insensitive, `rg`, repo-wide excluding `node_modules`, lockfiles, images). 37 hits; classification:

| Class | Count | Locations | Verdict |
|---|---|---|---|
| Env-var *names* / lookups | 4 | `openc3/python/openc3/environment.py:26,27,34,42` | not a credential |
| Test/spec/Playwright fixtures | 24 | `openc3-cosmos-cmd-tlm-api/spec/controllers/auth_controller_spec.rb` (14), `openc3-cosmos-script-runner-api/spec/controllers/running_script_controller_spec.rb` (2), `openc3/spec/models/auth_model_spec.rb:21`, `playwright/tests/{fixture,auth.p.spec,script-runner/prompts.p.spec}.ts` (6), `openc3/test/integration/tsdb/insert_test_data.py:29` (QuestDB test-container password) | test-only |
| Compose/env indirection | 5 | `compose.yaml:33,36,71,73` (`"${VAR}"`), `openc3-buckets/docker-entrypoint.sh:13` | not a credential (variable reference) |
| Committed key material | 3 | `examples/openc3-cosmos-mqtt-test/{client.key,client.crt,mosquitto.org.crt}` | **test fixture** for the public `test.mosquitto.org` broker example; a private key in a repo is still bad hygiene — should not be reused anywhere |
| UI prop | 1 | `openc3-vue-common/src/tools/scriptrunner/ScriptRunner.vue:546` `:password="ask.password"` (prompt masking flag) | not a credential |
| `.env` defaults | (dotfile; not in the `rg` count, covered by gitleaks) | `.env:48,52,54,56,58,59,73` (`OPENC3_TSDB_PASSWORD`, `OPENC3_REDIS_PASSWORD`, `OPENC3_BUCKET_PASSWORD`, `OPENC3_SR_REDIS_PASSWORD`, `OPENC3_SR_BUCKET_PASSWORD`, `OPENC3_SERVICE_PASSWORD`, `SECRET_KEY_BASE`) | **documented default** — `docs.openc3.com/docs/getting-started/security.md:100-229` lists each variable with its default and instructs operators to change them. Values are intentionally not reproduced in this document. |

gitleaks 8.30.1 (`gitleaks detect --no-git --source . --report-format json`; in the committed `gitleaks-tree.json` the `Secret`/`Match`/`Line` fields are replaced by `<redacted sha256:…>` so no matched string is reproduced, and the `.env` default values are likewise redacted in `rg_credentials.txt`, the CVE-2025-28388 diff and the advisory JSON): 22 findings = 1 `private-key` (the MQTT fixture above), 20 `generic-api-key` (`docs/**` generated site and search index, `docs.openc3.com/docs/guides/curl.md:83-177` example tokens, `openc3/spec/utilities/aws_bucket_spec.rb:157-165` fake AWS keys, `.env:73` `SECRET_KEY_BASE`), 1 `curl-auth-user` (`compose.yaml:89` healthcheck `-u "$${QDB_HTTP_USER}:$${QDB_HTTP_PASSWORD}"`, variable reference). No AWS `AKIA…` live-format keys, no `Authorization: Bearer <literal>` outside docs examples.

## 5. CVE-2025-28388 cross-reference

Public record (`demo/fa2/data/CVE-2025-28388.osv.json`): "OpenC3 COSMOS before v6.0.2 was discovered to contain hardcoded credentials for the Service Account." OSV git range: introduced `6e0d24067e57572254471e0460bcc10931740c40` (version bump to 6.0.0, 2024-12-17), fixed `65fd4be2423c5d9d84642a7c0f049f0b36998dde` (version bump to 6.0.2, 2025-01-09). No advisory text names a file or a literal.

What the repository shows (`git diff v6.0.1 v6.0.2 -- openc3/lib/openc3/models/auth_model.rb openc3-cosmos-init/ .env compose.yaml` → `data/cve-2025-28388_v6.0.1_v6.0.2.diff`; `git log v6.0.1..v6.0.2 -- openc3/lib/openc3/models/auth_model.rb` → one commit `195974a019f375f7c5a35f48e4151babb40649ac` "Fix login issue", `data/cve-2025-28388_fix_commit_195974a0.diff`):

- The only `auth_model.rb` change moves the `ENV['OPENC3_SERVICE_PASSWORD'] == token` comparison from the end of `verify` (after the hashed-password cache check) into a new early return, and introduces `verify_no_service`. **No literal credential is removed**; the service password was already read from the environment at v6.0.1 (`openc3/lib/openc3/models/auth_model.rb:65-66` at that tag; `openc3-cosmos-script-runner-api/app/models/{running_script,script}.rb` pass it to child processes as `OPENC3_API_PASSWORD`).
- The `.env` diff between v6.0.1 and v6.0.2 changes only `ALPINE_BUILD`; the `OPENC3_SERVICE_PASSWORD=` line is byte-identical at v6.0.1, v6.0.2 **and v7.2.0** (`git show <tag>:.env | grep ^OPENC3_SERVICE_PASSWORD= | sha256sum` → same digest `6d106322c01627e5…` for all three).
- We therefore cannot, from public data, tie CVE-2025-28388 to a specific removed literal in these paths; the description is consistent with the *default* service password shipped in `.env` being treated as hard-coded, and with 6.0.2 changing how it is verified. This is stated as a limitation, not resolved.

Status at v7.2.0: `openc3/lib/openc3/models/auth_model.rb:verify(token, no_password:, service_only:)` still accepts `ENV['OPENC3_SERVICE_PASSWORD']` as a bearer credential (`return true if service_password and service_password == token`). `OPENC3_API_PASSWORD` does not appear in `.env` or `compose.yaml` at v7.2.0. Classification: **documented default, not hidden** — `docs.openc3.com/docs/getting-started/security.md:100-102,229` documents the variable, its default and the instruction to change it. Operational consequence: any deployment that keeps the shipped `.env` has a shared, publicly known service credential that grants API access; see `RISK_MEMO.md` remediation 3.

## 6. Binary inventory (`binary_files.tsv`, 867 files, `git ls-files -z | xargs -0 file --mime-type`)

| MIME type | Count | Assessment |
|---|---|---|
| `image/png` | 759 | docs screenshots, widget images, demo target images |
| `application/octet-stream` | 54 | 44 fonts (43 `.woff2`, 1 `.woff`, `openc3-tool-base/public/fonts/**`), 8 demo-target fixtures (`openc3-cosmos-demo/targets/INST*/{cmd_tlm/_cbor_template.bin,data/{attitude,position}.bin,tables/bin/ConfigTables.bin}`), 2 protocol test captures (`openc3/{spec,python/test}/interfaces/protocols/2025_05_01_12_00_00_tlm.bin`) |
| `image/jpeg` | 13 | demo target images |
| `image/gif` | 12 | UI/status icons |
| `application/gzip` | 12 | 4 spec fixtures (`openc3-cosmos-cmd-tlm-api/spec/fixtures/files/*.{bin,idx}.gz` telemetry logs); 8 release archives copied into images: `openc3-buckets/versitygw_v1.4.1_Linux_{arm64,x86_64}.tar.gz`, `openc3-redis/valkey-9.0.4.tar.gz`, `openc3-ruby/{htop-3.4.1,libsocketcan-0.0.12,rbspy-x86_64-unknown-linux-gnu-0.39.0,ruby-3.4.7,tini-0.19.0}.tar.gz` — **all match upstream SHA-256** (`provenance/data/vendored_blobs_upstream_check.tsv`) |
| `image/svg+xml` | 9 | icons/logos |
| `application/zip` | 2 | `openc3-ruby/libcsp-6b6e2dd2….zip`, `openc3-ruby/libzmq-34f7fa22….zip` — GitHub commit archives, **match upstream** |
| `application/x-executable` (ELF) | 2 | `openc3-ruby/anycable-go-linux-{amd64,arm64}` — AnyCable-Go 1.6.14 release binaries, **match upstream release hashes**; these carry the `go-module` CVEs in the SBOM |
| fonts (`font/sfnt`, `application/vnd.ms-fontobject`) | 2 | Material Design Icons webfont |
| `image/vnd.microsoft.icon`, `image/x-xcf` | 2 | favicon, GIMP source of an icon |

Not present anywhere in the tree: `.so`, `.dll`, `.dylib`, `.jar`, `.class`, `.pyc`, `.gem`, `.whl`, `.exe`, `.node`. `openc3/ext/openc3/ext/**` (13 `.c`, 12 `extconf.rb`/`.rb`) is C-extension **source** compiled at `gem build`/`rake build`; GHSA-g7jg-9chv-jq9j / CVE-2026-92167 (heap OOB read, fixed 7.4.0) is in `openc3/ext/openc3/ext/structure/structure.c:427` of that source.

## 7. Methods

```
# dynamic execution
rg -n -g '!node_modules' -g '!**/spec/**' -g '!**/test/**' -e '\beval\(' -e 'instance_eval|class_eval|module_eval' -e '\.(public_send|send|__send__)\(' -e '`[^`]*#\{' -e '\bsystem\(|\bspawn\(|Open3\.|IO\.popen|Marshal\.load|ERB\.new' \
   openc3/lib openc3-cosmos-cmd-tlm-api/app openc3-cosmos-script-runner-api/app > heuristics/data/rg_ruby_dynamic_exec.txt
rg -n -g '!**/test/**' -e '\b(eval|exec)\(' -e 'pickle\.loads?' -e 'shell\s*=\s*True' -e 'importlib\.import_module' openc3/python/openc3 openc3-cosmos-script-runner-api/scripts > heuristics/data/rg_python_dynamic_exec.txt
rg -n -g '!node_modules' -e '\beval\(' -e 'new Function\(' -e '\.innerHTML' -e 'v-html' openc3-cosmos-init/plugins/packages > heuristics/data/rg_js_dynamic_exec.txt
# extra patterns (YAML.load, constantize, ERB.new, spawn, Kernel.open, system, Marshal.load, pickle, shell=True, subprocess, new Function, innerHTML, v-html, URI.open, Net::HTTP, Open3/popen)
for pat in …; do rg -n -g '!node_modules' -g '!**/spec/**' -g '!**/test/**' -g '!**/*.min.js' -e "$pat" <scoped dirs>; done > heuristics/data/rg_extra_patterns.txt
semgrep scan --config p/ruby --config p/security-audit --config p/python --config p/javascript --json --output heuristics/data/semgrep.json --metrics=off <scoped dirs>
# blobs / base64 / network / credentials
rg -n -e '[A-Za-z0-9+/=]{200,}' -e '[0-9a-fA-F]{200,}' --glob '!*.{png,jpg,gif,svg,woff,woff2,ttf,eot,ico,bin,gz,zip,lock,map}' --glob '!*.min.*' --glob '!pnpm-lock.yaml' --glob '!uv.lock' --glob '!node_modules' --glob '!docs/assets/**' . > heuristics/data/rg_long_blobs.txt
rg -n -e 'Base64\.(strict_)?decode64|b64decode|atob\(' openc3 openc3-cosmos-cmd-tlm-api openc3-cosmos-script-runner-api openc3-cosmos-init/plugins/packages -g '!node_modules' > heuristics/data/rg_base64_decode.txt
rg -n -e 'Net::HTTP|curl|wget|URI\.open|open-uri|fetch\(|ENV\.fetch|https?://' <gemspecs, Rakefiles, openc3/bin, openc3-cosmos-init, scripts, */Dockerfile*> > heuristics/data/rg_install_network.txt
rg -n -i -e 'password|passwd|secret|token|api_key|AKIA|-----BEGIN|Authorization:' --glob '!node_modules' --glob '!*.lock' --glob '!docs/**' --glob '!*.{png,jpg,gif,svg}' . > heuristics/data/rg_credentials.txt
gitleaks detect --no-git --source . --report-format json --report-path heuristics/data/gitleaks-tree.json   # gitleaks 8.30.1
# CVE-2025-28388
git diff v6.0.1 v6.0.2 -- openc3/lib/openc3/models/auth_model.rb openc3-cosmos-init/ .env compose.yaml > heuristics/data/cve-2025-28388_v6.0.1_v6.0.2.diff
git log v6.0.1..v6.0.2 -- openc3/lib/openc3/models/auth_model.rb ; git show 195974a0 > heuristics/data/cve-2025-28388_fix_commit_195974a0.diff
# binaries
git ls-files -z | xargs -0 file --mime-type | grep -vE ': (text/|inode/|application/json|application/xml)' > heuristics/data/binary_files.txt   # -> binary_files.tsv
```

Tool versions: ripgrep 14.x (system, no PCRE2 — patterns use RE2 syntax), semgrep 1.178.0 (rulesets fetched from semgrep.dev at run time; 3 errors recorded in `semgrep.json`), gitleaks 8.30.1, `file` 5.x.

Limitations: `rg` is textual — it cannot follow data flow; the "user-controlled" column is from reading the call sites and the published advisories, not from taint analysis. semgrep timed out on the vendored Vue bundle and skipped one Python file with a parse error (`limits_event_topic.py:39`). The credential grep excluded `docs/**` (generated site) to reduce noise, so gitleaks (which did cover it) is the authoritative repo-wide credential pass. Vendored third-party JS was inventoried, not audited line by line. Nothing was executed; no dynamic analysis.
