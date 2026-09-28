# FIX_COMPARISON.md — pypi_url OS command injection

Advisory: GHSA-vp3w-52v9-q57f / CVE-2026-77601
Vulnerable code: `openc3/lib/openc3/models/plugin_model.rb`, `PluginModel.install_phase2` (backtick `/openc3/bin/pipinstall #{pip_args}` with `pypi_url` from `get_setting('pypi_url')`), `demo-baseline` = upstream `v7.2.0` = `77acb91cc2c3b21af3eb981c829285dea96c984e`.

| | This fork | Upstream |
|---|---|---|
| Commit | `8a497ac6040891f00acb1c31c01fae6823333606` on `fix/pypi-url-command-injection` (PR https://github.com/achilli444/cosmos-fa2-demo/pull/1) | `be70d1d836c83c3b084e768e31a399312d4cbe0b` "fix(plugin_model): prevent OS command injection via pypi_url setting", 2026-06-18, first in `v7.2.1` |
| Files | `openc3/lib/openc3/models/plugin_model.rb`, `openc3/lib/openc3/utilities/pypi_url.rb` (new), `openc3/spec/models/plugin_model_spec.rb`, `openc3/spec/utilities/pypi_url_spec.rb` (new) | `openc3/lib/openc3/models/plugin_model.rb`, `openc3/lib/openc3/models/python_package_model.rb`, `openc3/lib/openc3/utilities/pypi_url.rb` (new), `openc3/spec/utilities/pypi_url_spec.rb` (new) |
| Diff size | 4 files, +286/-32 | 4 files, +134/-14 |

## Where the fixes agree

1. **Root-cause fix is identical: no shell.** Both replace the backtick with
   `output, status = Open3.capture2e('/openc3/bin/pipinstall', *pip_args)` and build `pip_args` as an array
   (`['-i', url]`, optional `['--trusted-host', URI.parse(url).host]` when `ENV['PIP_ENABLE_TRUSTED_HOST']` is set,
   then `gem_path` or `['-r', requirements_path]`). Both add `require 'open3'` and `require 'openc3/utilities/pypi_url'`
   to `plugin_model.rb`. This alone closes the injection regardless of validation.
2. **Non-fatal contract preserved.** Both keep `puts output`, `status.success?` check and
   `Logger.warn "Python package installation failed..."`; a bad/unreachable index never aborts plugin install.
3. **Validation is factored into a new `OpenC3::PypiUrl` utility** at the same path
   (`openc3/lib/openc3/utilities/pypi_url.rb`) with a dedicated spec at `openc3/spec/utilities/pypi_url_spec.rb`.
4. **Validation core:** both use `URI.parse`, require scheme `http`/`https` (upstream: `uri.is_a?(URI::HTTP)`;
   fork: `ALLOWED_SCHEMES.include?(uri.scheme)`), require a non-empty `uri.host`, and treat `URI::InvalidURIError` as invalid.
5. **Same validation applied to the `ENV['PYPI_URL']` fallback and to the hard-coded default** — both validate the
   *resolved* value after the setting → ENV → default chain.

## Where they differ

### 1. Strictness of the validator
- **Upstream** accepts any `URI::HTTP` with a host. Because RFC 3986 allows sub-delims in `reg-name`/`path`,
  values that still contain shell metacharacters pass, e.g. (verified with Ruby 3.4.11 against upstream `PypiUrl.validate`):
  `https://pypi.org$(id)/simple` → ACCEPT, `https://pypi.org;id/simple` → ACCEPT, `https://pypi.org&id/simple` → ACCEPT,
  `https://user:pass@pypi.org/simple` → ACCEPT. Only values `URI.parse` rejects (whitespace, `` ` ``, `|`, ...) fail.
  This is safe *only because* the argv change removed the shell; the validator is a sanity check, not a security boundary.
- **Fork** adds a character allowlist `%r{\A[A-Za-z0-9\-._~:/%+]+\z}` (rejects whitespace, quotes, `@`, `;`, `$`, `()`,
  `` ` ``, `|`, `&`, `#`, `?`, ...) and explicitly rejects userinfo (`uri.userinfo.nil?`). All of the above payloads → REJECT;
  `http://localhost:8080`, `https://mirror.example.com/root/pypi` → ACCEPT. Defense in depth per the task
  requirements ("no whitespace/shell metacharacters, no userinfo"). Cost: query strings and credential-embedded mirror URLs
  (`https://user:token@artifactory/...`) that worked on v7.2.0 and still work upstream are now rejected in the fork.

### 2. Behavior on an invalid value
- **Upstream** `PypiUrl.validate(url)` logs `Logger.error("Invalid pypi_url '...'; falling back to https://pypi.org/simple")`
  and **returns `PypiUrl::DEFAULT`** — the install proceeds against the public index.
- **Fork** `PypiUrl.index_url(url)` returns `nil`; `install_phase2` logs `Logger.error("Invalid pypi_url ...: must be an
  http(s) URL with no userinfo or shell metacharacters. Skipping Python package installation. ...")` and **skips
  pipinstall entirely**; plugin install continues (`needs_dependencies = true` still set). Rationale: don't silently
  redirect a misconfigured private mirror to pypi.org. Neither raises.

### 3. Where `/simple` is appended / constant shape
- **Upstream** keeps the original flow (`pypi_url += '/simple'` in both the setting and ENV branches; `DEFAULT = 'https://pypi.org/simple'`)
  and validates the final `.../simple` string.
- **Fork** collapses the `begin/rescue/ensure` into `pypi_url = setting || ENV['PYPI_URL'] || PypiUrl::DEFAULT_URL`
  (`DEFAULT_URL = 'https://pypi.org'`) and appends `/simple` once inside `PypiUrl.index_url`. Same resulting argv for
  valid inputs (verified by spec: `-i https://pypi.org/simple` when nothing is configured).

### 4. API shape of the utility
- Upstream: `class PypiUrl`, `self.validate(url) -> String` (url or DEFAULT), depends on `openc3/utilities/logger`.
- Fork: `module PypiUrl`, `self.valid?(url) -> Boolean`, `self.index_url(url) -> String|nil`, pure (no logging; caller logs).

## Upstream covers, fork does not
- `openc3/lib/openc3/models/python_package_model.rb` (`PythonPackageModel.install`): upstream also routes its resolved
  `pypi_url` through `PypiUrl.validate` (defense in depth). That code path already used an argv array
  (`ProcessManager.instance.spawn(["/openc3/bin/pipinstall"] + pip_args, ...)`) on v7.2.0, so it was not injectable;
  the fork left it untouched to keep the change minimal. Follow-up candidate if the fork wants parity.

## Fork covers, upstream does not
- Rejects userinfo and non-URI-error shell metacharacters (`$()`, `;`, `&`, `#`, ...) in `pypi_url` (see §1 above).
- Refuses to run pipinstall on an invalid URL instead of substituting pypi.org.
- Regression tests at the injection site (`plugin_model_spec.rb`), not just the utility.

## Tests
- **Upstream** (`openc3/spec/utilities/pypi_url_spec.rb`, 10 examples): `validate` returns https/http/host:port URLs
  unchanged; rejects `"https://pypi.org ; id > /tmp/PWNED ; #"`, `ftp://`, `https:///simple`, `"not a url"`, `""` by
  returning DEFAULT and logging an error; `DEFAULT == 'https://pypi.org/simple'`. **No test touches
  `install_phase2` or asserts that a shell is never invoked**; the upstream spec passes against the vulnerable
  `plugin_model.rb` if only the utility is present.
- **Fork**:
  - `openc3/spec/utilities/pypi_url_spec.rb`: `valid?`/`index_url` for valid http(s)/ports/paths/IPs; rejects non-String,
    empty, no host, `ftp`/`file`/`ssh`/relative, userinfo, whitespace/newline, each shell metacharacter payload
    (`; touch /tmp/pwned #`, `$(id)`, `` `id` ``, `|`, `&&`), `DEFAULT_URL`.
  - `openc3/spec/models/plugin_model_spec.rb` `"with python dependencies"` context (12 examples): real gem extraction with
    `requirements.txt`, `get_setting` stubbed; `expect(PluginModel).not_to receive(:`)` / `:system`;
    `Open3.capture2e` stubbed and argv asserted element-by-element for `https://mirror.example.com`
    (`['/openc3/bin/pipinstall','-i','https://mirror.example.com/simple','-r',<path>]`); 7 malicious payloads
    (`https://pypi.org; touch /tmp/pwned #`, `https://pypi.org$(id)`, `$(id)`, `` https://pypi.org`id` ``, newline,
    userinfo, `file:///etc/passwd`) → `Logger.error(/Invalid pypi_url/)`, no `Open3`/`Process.spawn` call, install
    still completes; `PYPI_URL` ENV malicious → rejected, valid → passed through, default when unset; non-zero
    pipinstall status → `Logger.warn` only.
  - Before/after on the required spec: `demo-baseline` → `12 examples, 12 failures` (each failure shows the payload inside
    the single backtick string, e.g. `` `("/openc3/bin/pipinstall -i https://pypi.org; touch /tmp/pwned #/simple -r .../requirements.txt")``);
    fix → `50 examples, 0 failures` (`plugin_model_spec.rb` + `pypi_url_spec.rb`, Ruby 3.4.11).
