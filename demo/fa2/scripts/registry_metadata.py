#!/usr/bin/env python3
"""Fetch public registry metadata (rubygems.org / registry.npmjs.org / pypi.org).
 1. Licenses for every gem/npm/pypi component in the CycloneDX SBOM -> sbom/data/registry_licenses.json
 2. Maintainer/owner + install-hook signals for the direct dependencies -> provenance/data/direct_dep_registry.csv
No credentials; read-only GETs; results are cached in the JSON so the run is reproducible offline.
"""
import csv, json, os, subprocess, sys, time, urllib.request, urllib.parse, urllib.error
from concurrent.futures import ThreadPoolExecutor
REPO = subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip()
S = f'{REPO}/demo/fa2/sbom'; P = f'{REPO}/demo/fa2/provenance/data'
UA = {'User-Agent': 'fa2-sbom-license-lookup (public metadata only)'}
def get(url, tries=3):
    last = 'retries exhausted'
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404: return {'__error__': 'HTTP 404'}
            if e.code == 429: last = 'HTTP 429 (retries exhausted)'; time.sleep(2 + 2 * i); continue
            return {'__error__': f'HTTP {e.code}'}
        except Exception as e:
            time.sleep(1 + i); last = str(e)
    return {'__error__': last}

def gem_version(name, ver):
    d = get(f'https://rubygems.org/api/v2/rubygems/{urllib.parse.quote(name)}/versions/{urllib.parse.quote(ver)}.json')
    if '__error__' in d and '-' in ver:  # platform-specific gem (e.g. 1.17.4-x86_64-linux-gnu): query the base version
        d = get(f'https://rubygems.org/api/v2/rubygems/{urllib.parse.quote(name)}/versions/{urllib.parse.quote(ver.split("-")[0])}.json')
    if '__error__' in d: return {'error': d['__error__']}
    return {'licenses': d.get('licenses') or [], 'authors': d.get('authors'), 'sha': d.get('sha')}
def npm_version(name, ver):
    d = get(f'https://registry.npmjs.org/{urllib.parse.quote(name, safe="@")}/{urllib.parse.quote(ver)}')
    if '__error__' in d: return {'error': d['__error__']}
    lic = d.get('license')
    if isinstance(lic, dict): lic = lic.get('type')
    if lic is None and d.get('licenses'): lic = ' OR '.join(x.get('type', '') for x in d['licenses'] if isinstance(x, dict))
    return {'licenses': [lic] if lic else [], 'scripts': {k: v for k, v in (d.get('scripts') or {}).items() if k in ('preinstall', 'install', 'postinstall', 'prepare')},
            'hasInstallScript': d.get('hasInstallScript', False)}
def pypi_version(name, ver):
    d = get(f'https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(ver)}/json')
    if '__error__' in d: return {'error': d['__error__']}
    info = d.get('info', {}); lic = info.get('license_expression') or info.get('license') or ''
    if not lic or len(lic) > 80:
        cls = [c.split('::')[-1].strip() for c in info.get('classifiers', []) if c.startswith('License ::')]
        lic = ' OR '.join(cls) if cls else (lic[:60] + '...' if lic else '')
    return {'licenses': [lic] if lic else [], 'has_sdist_setup_py': any(u.get('packagetype') == 'sdist' for u in d.get('urls', []))}

cdx = json.load(open(f'{S}/cosmos-v7.2.0.cdx.json'))
cache_path = f'{S}/data/registry_licenses.json'
cache = json.load(open(cache_path)) if os.path.exists(cache_path) else {}
todo = []
for c in cdx['components']:
    purl = (c.get('purl') or '').split('?')[0]
    if not purl: continue
    hit = cache.get(purl)
    if hit is not None and hit.get('error') in (None, 'HTTP 404'): continue  # re-query transient failures (429, timeouts) on the next run
    t = purl.split(':', 1)[1].split('/', 1)[0]
    if t not in ('gem', 'npm', 'pypi'): continue
    todo.append((purl, t, c['name'], c['version']))
print(f'license lookups: {len(todo)} (cached {len(cache)})', flush=True)
def work(item):
    purl, t, n, v = item
    fn = {'gem': gem_version, 'npm': npm_version, 'pypi': pypi_version}[t]
    return purl, fn(n, v)
with ThreadPoolExecutor(12) as ex:
    for i, (purl, res) in enumerate(ex.map(work, todo), 1):
        cache[purl] = res
        if i % 200 == 0:
            print(f'  {i}/{len(todo)}', flush=True); json.dump(cache, open(cache_path, 'w'), indent=0, sort_keys=True)
json.dump(cache, open(cache_path, 'w'), indent=0, sort_keys=True)
errs = sum(1 for v in cache.values() if 'error' in v)
print(f'done: {len(cache)} cached, {errs} errors', flush=True)

# ---------- direct-dependency maintainer signals
direct = {}
for r in csv.DictReader(open(f'{S}/data/direct_deps.csv')):
    direct.setdefault((r['ecosystem'], r['name']), set()).add(r['manifest'])
def gem_owner(name):
    o = get(f'https://rubygems.org/api/v1/gems/{urllib.parse.quote(name)}/owners.json')
    g = get(f'https://rubygems.org/api/v1/gems/{urllib.parse.quote(name)}.json')
    if '__error__' in g: return {'error': g['__error__']}
    owners = [x.get('handle') for x in o] if isinstance(o, list) else []
    return {'owner_count': len(owners), 'owners': owners, 'latest_version': g.get('version'), 'licenses': g.get('licenses') or [],
            'downloads': g.get('downloads'), 'source_code_uri': g.get('source_code_uri') or g.get('homepage_uri'),
            'maintainer_history': 'not available (rubygems.org API exposes current owners only)',
            'install_hooks': 'gem extensions -> see gemspec (not exposed by API)'}
npm_resolved = {}  # npm package name -> purls of the versions actually resolved in the SBOM
for c in cdx['components']:
    purl = (c.get('purl') or '').split('?')[0]
    if purl.startswith('pkg:npm/'): npm_resolved.setdefault(c['name'], set()).add(purl)
def npm_owner(name):
    d = get(f'https://registry.npmjs.org/{urllib.parse.quote(name, safe="@")}')
    if '__error__' in d: return {'error': d['__error__']}
    m = d.get('maintainers') or []; latest = d.get('dist-tags', {}).get('latest'); lv = d.get('versions', {}).get(latest, {})
    hooks = {}
    for purl in sorted(npm_resolved.get(name, ())):
        e = cache.get(purl) or {}
        sc = {k: v for k, v in (e.get('scripts') or {}).items() if k in ('preinstall', 'install', 'postinstall')}
        if sc or e.get('hasInstallScript'): hooks[purl.rsplit('@', 1)[-1]] = sc or {'hasInstallScript': True}
    return {'owner_count': len(m), 'owners': [x.get('name') for x in m], 'latest_version': latest, 'licenses': [lv.get('license')] if lv.get('license') else [],
            'resolved_versions': ';'.join(sorted(p.rsplit('@', 1)[-1] for p in npm_resolved.get(name, ()))),
            'install_hooks': hooks, 'maintainer_history': 'not available (npm registry document exposes current maintainers only)',
            'repository': (lv.get('repository') or {}).get('url') if isinstance(lv.get('repository'), dict) else lv.get('repository')}
def pypi_owner(name):
    d = get(f'https://pypi.org/pypi/{urllib.parse.quote(name)}/json')
    if '__error__' in d: return {'error': d['__error__']}
    info = d.get('info', {})
    return {'owner_count': None, 'owners': 'not available (PyPI JSON API does not expose project owners/maintainers)',
            'latest_version': info.get('version'), 'licenses': [info.get('license_expression') or info.get('license') or ''],
            'author_email_domain': (info.get('author_email') or info.get('maintainer_email') or '').split('@')[-1][:60],
            'maintainer_history': 'not available', 'install_hooks': 'sdist setup.py present' if any(u.get('packagetype') == 'sdist' for u in d.get('urls', [])) else 'wheel only',
            'project_urls': list((info.get('project_urls') or {}).values())[:3]}
def owork(k):
    e, n = k
    return k, {'gem': gem_owner, 'npm': npm_owner, 'pypi': pypi_owner}[e](n)
rows = []
with ThreadPoolExecutor(8) as ex:
    for (e, n), r in ex.map(owork, sorted(direct)):
        rows.append({'ecosystem': e, 'name': n, 'manifests': ';'.join(sorted(direct[(e, n)])), **{kk: (json.dumps(vv) if isinstance(vv, (list, dict)) else vv) for kk, vv in r.items()}})
keys = ['ecosystem', 'name', 'manifests', 'owner_count', 'owners', 'latest_version', 'resolved_versions', 'licenses', 'install_hooks', 'maintainer_history', 'downloads', 'source_code_uri', 'repository', 'author_email_domain', 'project_urls', 'error']
with open(f'{P}/direct_dep_registry.csv', 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=keys, extrasaction='ignore'); w.writeheader(); w.writerows(rows)
print('direct deps:', len(rows), 'errors:', sum(1 for r in rows if r.get('error')))
