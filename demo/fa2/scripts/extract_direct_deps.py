#!/usr/bin/env python3
"""Extract direct dependencies declared in repo manifests at the checked-out commit.
Output: demo/fa2/sbom/data/direct_deps.csv (ecosystem,name,constraint,manifest,scope)
"""
import csv, json, os, re, subprocess, sys, tomllib
REPO = subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip()
OUT = os.path.join(REPO, 'demo/fa2/sbom/data/direct_deps.csv')
files = subprocess.check_output(['git', 'ls-files'], cwd=REPO, text=True).split('\n')
rows = []
gem_re = re.compile(r"""^\s*gem\s+['"]([^'"]+)['"]\s*(?:,\s*(.*))?$""")
spec_re = re.compile(r"""add_(?:runtime_|development_)?dependency\s+['"]([^'"]+)['"]\s*(?:,\s*(.*))?$""")
for f in files:
    if 'node_modules' in f or f.startswith('demo/') or '/templates/' in f or f.startswith('examples/'):
        continue
    p = os.path.join(REPO, f)
    base = os.path.basename(f)
    if base == 'Gemfile':
        for line in open(p, encoding='utf-8', errors='replace'):
            m = gem_re.match(line)
            if m:
                rows.append(('gem', m.group(1), (m.group(2) or '').strip(), f, 'gemfile'))
    elif base.endswith('.gemspec'):
        for line in open(p, encoding='utf-8', errors='replace'):
            m = spec_re.search(line)
            if m:
                scope = 'development' if 'add_development_dependency' in line else 'runtime'
                rows.append(('gem', m.group(1), (m.group(2) or '').strip(), f, scope))
    elif base == 'package.json':
        try:
            d = json.load(open(p, encoding='utf-8'))
        except Exception as e:
            print('skip', f, e, file=sys.stderr); continue
        for key, scope in (('dependencies', 'runtime'), ('devDependencies', 'development'),
                           ('peerDependencies', 'peer'), ('optionalDependencies', 'optional')):
            for name, ver in (d.get(key) or {}).items():
                if str(ver).startswith('workspace:') or name.startswith('@openc3/') or name.startswith('openc3-'):
                    continue
                rows.append(('npm', name, ver, f, scope))
    elif base == 'pyproject.toml':
        d = tomllib.load(open(p, 'rb'))
        proj = d.get('project', {})
        for dep in proj.get('dependencies', []):
            rows.append(('pypi', re.split(r'[<>=!~\[; ]', dep, 1)[0], dep, f, 'runtime'))
        for grp, deps in (proj.get('optional-dependencies') or {}).items():
            for dep in deps:
                rows.append(('pypi', re.split(r'[<>=!~\[; ]', dep, 1)[0], dep, f, f'optional:{grp}'))
        for grp, deps in (d.get('dependency-groups') or {}).items():
            for dep in deps:
                if isinstance(dep, str):
                    rows.append(('pypi', re.split(r'[<>=!~\[; ]', dep, 1)[0], dep, f, f'group:{grp}'))
        for grp, deps in ((d.get('tool', {}).get('uv', {}) or {}).get('dev-dependencies') and {'uv-dev': d['tool']['uv']['dev-dependencies']} or {}).items():
            for dep in deps:
                rows.append(('pypi', re.split(r'[<>=!~\[; ]', dep, 1)[0], dep, f, f'group:{grp}'))
    elif re.match(r'requirements.*\.txt$', base):
        for line in open(p, encoding='utf-8', errors='replace'):
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('-'):
                rows.append(('pypi', re.split(r'[<>=!~\[; ]', line, 1)[0], line, f, 'requirements'))
rows.sort()
with open(OUT, 'w', newline='') as fh:
    w = csv.writer(fh); w.writerow(['ecosystem', 'name', 'constraint', 'manifest', 'scope']); w.writerows(rows)
uniq = {(r[0], r[1].lower()) for r in rows}
print(f'{len(rows)} declarations, {len(uniq)} unique (ecosystem,name):',
      {e: len({n for ee, n in uniq if ee == e}) for e in ('gem', 'npm', 'pypi')})
