#!/usr/bin/env python3
"""Derive every SBOM_SUMMARY.md number from the committed SBOM/grype JSON.
Inputs : demo/fa2/sbom/cosmos-v7.2.0.cdx.json, demo/fa2/sbom/grype-cosmos-v7.2.0.json,
         demo/fa2/sbom/data/direct_deps.csv, demo/fa2/sbom/data/registry_licenses.json (optional)
Outputs: demo/fa2/sbom/data/{ecosystem_counts.csv,vulnerable_components.csv,top25_cves.csv,severity_counts.csv,license_flags.csv,summary_numbers.json}
"""
import csv, json, os, subprocess, collections
REPO = subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip()
S = os.path.join(REPO, 'demo/fa2/sbom'); D = os.path.join(S, 'data')
cdx = json.load(open(f'{S}/cosmos-v7.2.0.cdx.json'))
gry = json.load(open(f'{S}/grype-cosmos-v7.2.0.json'))
direct = {(r['ecosystem'], r['name'].lower()) for r in csv.DictReader(open(f'{D}/direct_deps.csv'))}
SEV = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Negligible': 4, 'Unknown': 5}

def eco(purl, typ=None):
    if purl:
        t = purl.split(':', 1)[1].split('/', 1)[0]
        return {'gem': 'gem', 'npm': 'npm', 'pypi': 'pypi', 'golang': 'go-module (from vendored anycable-go binaries)',
                'github': 'github-action', 'generic': 'other'}.get(t, t)
    return typ or 'other (no purl)'

def location(c):
    return ';'.join(sorted({p['value'] for p in c.get('properties', []) if p['name'].endswith(':path')}))

# ---- component counts by ecosystem
comps = cdx['components']
ecount = collections.Counter(eco(c.get('purl'), c.get('type')) for c in comps)
with open(f'{D}/ecosystem_counts.csv', 'w', newline='') as f:
    w = csv.writer(f); w.writerow(['ecosystem', 'components']); [w.writerow(r) for r in sorted(ecount.items(), key=lambda x: -x[1])]
# per-lockfile gem counts
lock = collections.Counter()
for c in comps:
    if (c.get('purl') or '').startswith('pkg:gem/'):
        for l in location(c).split(';'): lock[l] += 1
with open(f'{D}/gem_counts_by_lockfile.csv', 'w', newline='') as f:
    w = csv.writer(f); w.writerow(['lockfile', 'gems']); [w.writerow(r) for r in sorted(lock.items())]

# ---- grype
matches = gry['matches']
sevc = collections.Counter(m['vulnerability']['severity'] for m in matches)
with open(f'{D}/severity_counts.csv', 'w', newline='') as f:
    w = csv.writer(f); w.writerow(['severity', 'matches']); [w.writerow((s, sevc[s])) for s in SEV if sevc[s]]
def cve_of(m):
    v = m['vulnerability']['id']
    if v.startswith('CVE-'): return v
    for r in m.get('relatedVulnerabilities', []):
        if r['id'].startswith('CVE-'): return r['id']
    return v
def is_direct(m):
    a = m['artifact']; e = eco(a.get('purl'), a.get('type'))
    if e not in ('gem', 'npm', 'pypi'): return 'n/a (not a manifest ecosystem)'
    return 'direct' if (e, a['name'].lower()) in direct else 'transitive'
bycomp = collections.OrderedDict()
for m in matches:
    a = m['artifact']; k = (a['name'], a['version'], eco(a.get('purl'), a.get('type')))
    bycomp.setdefault(k, {'ids': [], 'worst': 9, 'fix': set(), 'loc': set(), 'direct': is_direct(m)})
    e = bycomp[k]; e['ids'].append(m['vulnerability']['id']); e['worst'] = min(e['worst'], SEV.get(m['vulnerability']['severity'], 5))
    e['fix'].update(m['vulnerability'].get('fix', {}).get('versions') or []); e['loc'].update(l['path'] for l in a.get('locations', []))
inv = {v: k for k, v in SEV.items()}
rows = sorted(bycomp.items(), key=lambda kv: (kv[1]['worst'], kv[0][2], kv[0][0]))
with open(f'{D}/vulnerable_components.csv', 'w', newline='') as f:
    w = csv.writer(f); w.writerow(['component', 'version', 'ecosystem', 'direct_or_transitive', 'worst_severity', 'vuln_count', 'vuln_ids', 'fix_versions', 'locations'])
    for (n, v, e), x in rows:
        w.writerow([n, v, e, x['direct'], inv[x['worst']], len(x['ids']), ';'.join(x['ids']), ';'.join(sorted(x['fix'])), ';'.join(sorted(x['loc']))])
vc_eco = collections.Counter(k[2] for k in bycomp)
vc_dir = collections.Counter(x['direct'] for x in bycomp.values())
# top 25 (one row per match, sorted by severity then CVSS if present)
def cvss(m):
    best = 0.0
    for c in m['vulnerability'].get('cvss', []) or []:
        try: best = max(best, float(c['metrics']['baseScore']))
        except Exception: pass
    return best
top = sorted(matches, key=lambda m: (SEV.get(m['vulnerability']['severity'], 5), -cvss(m), m['artifact']['name']))
seen = set(); top25 = []
for m in top:
    key = (cve_of(m), m['artifact']['name'], m['artifact']['version'])
    if key in seen: continue
    seen.add(key); top25.append(m)
    if len(top25) == 25: break
with open(f'{D}/top25_cves.csv', 'w', newline='') as f:
    w = csv.writer(f); w.writerow(['rank', 'cve_or_ghsa', 'grype_id', 'severity', 'cvss', 'component', 'version', 'ecosystem', 'direct_or_transitive', 'fixed_version', 'location'])
    for i, m in enumerate(top25, 1):
        a = m['artifact']; fx = m['vulnerability'].get('fix', {})
        w.writerow([i, cve_of(m), m['vulnerability']['id'], m['vulnerability']['severity'], cvss(m) or '', a['name'], a['version'],
                    eco(a.get('purl'), a.get('type')), is_direct(m), ','.join(fx.get('versions') or []) or fx.get('state', ''), ';'.join(l['path'] for l in a.get('locations', []))])

# ---- licenses: SBOM-declared + registry supplement
reg = {}
if os.path.exists(f'{D}/registry_licenses.json'):
    reg = json.load(open(f'{D}/registry_licenses.json'))
def lic_of(c):
    ls = []
    for l in c.get('licenses') or []:
        ls.append(l.get('license', {}).get('id') or l.get('license', {}).get('name') or l.get('expression') or '')
    return ls
FLAG = ('GPL', 'LGPL', 'AGPL')
flags = []; lic_src = collections.Counter(); lic_kind = collections.Counter()
for c in comps:
    purl = c.get('purl') or ''
    e = eco(purl or None, c.get('type'))
    sbom_l = [x for x in lic_of(c) if x and not x.startswith('sha256:')]
    key = purl.split('?')[0]
    r = reg.get(key)
    reg_l = (r or {}).get('licenses') or []
    first_party = e in ('gem', 'pypi') and (c.get('name') or '').startswith('openc3') and (not r or bool(r.get('error')))
    if first_party:
        reg_l = ['AGPL-3.0-only OR commercial (first-party; LICENSE.md)']; r = {'licenses': reg_l}
    src = 'repo LICENSE.md (first-party)' if first_party else 'sbom' if sbom_l else ('registry' if reg_l else ('registry-lookup-failed' if r and r.get('error') else 'none'))
    lic_src[src] += 1
    lics = sbom_l or reg_l
    text = ' OR '.join(sorted(set(lics))) if lics else ''
    up = text.upper()
    if not lics:
        if e not in ('gem', 'npm', 'pypi'): kind = 'not-applicable (non-registry component)'
        elif src == 'registry-lookup-failed': kind = 'unknown (registry lookup failed)'
        else: kind = 'none-declared'
    elif any(k in up for k in FLAG) and 'LGPL' not in up and 'AGPL' not in up: kind = 'GPL'
    elif 'AGPL' in up: kind = 'AGPL'
    elif 'LGPL' in up: kind = 'LGPL'
    elif up in ('UNKNOWN', 'UNLICENSED', 'NOASSERTION', 'OTHER', 'SEE LICENSE IN LICENSE', 'CUSTOM') or 'SEE LICENSE' in up: kind = 'unknown'
    else: kind = 'ok'
    lic_kind[kind] += 1
    if kind not in ('ok', 'not-applicable (non-registry component)'):
        flags.append([c.get('name'), c.get('version'), e, kind, text, src, 'direct' if (e, (c.get('name') or '').lower()) in direct else 'transitive', location(c)])
# de-duplicate identical (component, version, ecosystem) rows that appear in several lockfiles
merged = collections.OrderedDict()
for r in flags:
    k = tuple(r[:3])
    if k in merged: merged[k][7] = ';'.join(sorted(set(merged[k][7].split(';') + r[7].split(';'))))
    else: merged[k] = r
flags = list(merged.values())
flags.sort(key=lambda r: ({'AGPL': 0, 'GPL': 1, 'LGPL': 2, 'unknown': 3, 'unknown (registry lookup failed)': 4, 'none-declared': 5}[r[3]], r[2], r[0]))
with open(f'{D}/license_flags.csv', 'w', newline='') as f:
    w = csv.writer(f); w.writerow(['component', 'version', 'ecosystem', 'flag', 'license_text', 'license_source', 'direct_or_transitive', 'locations']); w.writerows(flags)
summary = {'components_total': len(comps), 'components_by_ecosystem': dict(ecount), 'gems_by_lockfile': dict(lock),
           'grype_matches': len(matches), 'grype_matches_by_severity': dict(sevc), 'vulnerable_components': len(bycomp),
           'vulnerable_components_by_ecosystem': dict(vc_eco), 'vulnerable_components_direct_transitive': dict(vc_dir),
           'license_source_counts': dict(lic_src), 'license_flag_counts_all_components': dict(lic_kind), 'license_flag_rows_deduplicated': len(flags),
           'license_flag_rows_by_kind': dict(collections.Counter(r[3] for r in flags)),
           'registry_license_lookups': len(reg)}
json.dump(summary, open(f'{D}/summary_numbers.json', 'w'), indent=1)
print(json.dumps(summary, indent=1))
