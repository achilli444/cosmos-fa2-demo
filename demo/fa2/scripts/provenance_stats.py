import csv, re, sys, collections, fnmatch, json
from datetime import datetime
REPO='/home/ubuntu/repos/cosmos-fa2-demo'
OUT=REPO+'/demo/fa2/provenance/data'
rows=[l.rstrip('\n').split('|') for l in open(REPO+'/demo/fa2/provenance/data/commits_all.psv')]
# sha|author_email|author_date|committer_date|committer_email
total=len(rows)
emails=collections.Counter(r[1].lower() for r in rows)
def dom(e):
    e=e.lower()
    if '@' not in e: return '(no-domain)'
    d=e.split('@')[-1]
    if d.endswith('users.noreply.github.com'): return 'users.noreply.github.com'
    return d
doms=collections.Counter(dom(r[1]) for r in rows)
years=collections.Counter(r[2][:4] for r in rows)
tz=collections.Counter(r[2].split(' ')[2] for r in rows)
PERSONAL={'gmail.com','yahoo.com','hotmail.com','outlook.com','icloud.com','protonmail.com','me.com','live.com','aol.com','comcast.net','msn.com','ymail.com','pm.me'}
def cat(d):
    if d in ('openc3.com',): return 'vendor (openc3.com)'
    if d in PERSONAL: return 'personal webmail'
    if d=='users.noreply.github.com' or d.endswith('github.com'): return 'github noreply/web'
    if d=='(no-domain)' or d.endswith('.local') or d.endswith('.localdomain') or d.endswith('.lan') or '.' not in d: return 'local/unresolvable host'
    if d.startswith('dependabot') or 'bot' in d: return 'bot'
    return 'other org domain'
cats=collections.Counter(cat(dom(r[1])) for r in rows)
# web-flow committer (GitHub web merges)
webflow=sum(1 for r in rows if r[4].lower()=='noreply@github.com')
with open(OUT+'/summary.json','w') as f:
    json.dump({'total_commits':total,'distinct_author_emails':len(emails),'distinct_author_domains':len(doms),'github_web_committer_commits':webflow,
               'first_commit_date':min(r[2] for r in rows),'last_commit_date':max(r[2] for r in rows)},f,indent=1)
def wcsv(name,header,rowsx):
    with open(OUT+'/'+name,'w',newline='') as f:
        w=csv.writer(f); w.writerow(header); w.writerows(rowsx)
wcsv('commits_per_year.csv',['year','commits'],sorted(years.items()))
wcsv('author_domains.csv',['domain','category','commits','pct','distinct_emails'],
     [(d,cat(d),c,f'{100*c/total:.1f}',len({r[1].lower() for r in rows if dom(r[1])==d})) for d,c in doms.most_common()])
wcsv('domain_categories.csv',['category','commits','pct'],[(k,v,f'{100*v/total:.1f}') for k,v in cats.most_common()])
wcsv('tz_offsets.csv',['utc_offset','commits','pct'],[(k,v,f'{100*v/total:.1f}') for k,v in sorted(tz.items(),key=lambda x:-x[1])])
# per-year domain-category mix
ycat=collections.defaultdict(collections.Counter)
for r in rows: ycat[r[2][:4]][cat(dom(r[1]))]+=1
allcats=[k for k,_ in cats.most_common()]
wcsv('year_by_category.csv',['year']+allcats,[[y]+[ycat[y][c] for c in allcats] for y in sorted(ycat)])
# tz by year (top 6)
ytz=collections.defaultdict(collections.Counter)
for r in rows: ytz[r[2][:4]][r[2].split(' ')[2]]+=1
toptz=[k for k,_ in tz.most_common(8)]
wcsv('tz_by_year.csv',['year']+toptz+['other'],[[y]+[ytz[y][t] for t in toptz]+[sum(v for k,v in ytz[y].items() if k not in toptz)] for y in sorted(ytz)])

# --- first-time contributors touching sensitive paths
SENS=['openc3/lib/openc3/models/auth_model.rb','openc3/lib/openc3/utilities/authorization.rb','openc3/lib/openc3/utilities/authentication.rb',
 'openc3/lib/openc3/models/plugin_model.rb','openc3/lib/openc3/models/gem_model.rb','openc3/lib/openc3/models/python_package_model.rb',
 'openc3/lib/openc3/io/json_drb*.rb','openc3/lib/openc3/script/**','openc3-cosmos-script-runner-api/app/**',
 'openc3-cosmos-cmd-tlm-api/app/controllers/auth_controller.rb','openc3-cosmos-cmd-tlm-api/app/controllers/settings_controller.rb',
 'openc3-cosmos-cmd-tlm-api/app/controllers/plugins_controller.rb','openc3/bin/*','*/Dockerfile*','.github/workflows/**',
 # additions (documented): API auth middleware + RBAC-adjacent + compose/env
 'openc3-cosmos-cmd-tlm-api/app/controllers/application_controller.rb','openc3-cosmos-script-runner-api/app/controllers/application_controller.rb',
 'openc3/lib/openc3/api/**','compose.yaml','.env','openc3/lib/openc3/utilities/running_script.rb','openc3/lib/openc3/utilities/script.rb']
def sens(p):
    for pat in SENS:
        if pat.endswith('/**'):
            if p.startswith(pat[:-2]): return pat
        elif pat.startswith('*/'):
            if fnmatch.fnmatch(p, pat) or fnmatch.fnmatch(p, pat[2:]): return pat
        elif fnmatch.fnmatch(p, pat): return pat
    return None
# parse commits_files (newest first) -> build chronological
commits=[]; cur=None
for line in open(REPO+'/demo/fa2/provenance/data/commits_files.txt'):
    line=line.rstrip('\n')
    if line.startswith('@@'):
        sha,email,date=line[2:].split('|',2); cur={'sha':sha,'email':email.lower(),'date':date,'files':[]}; commits.append(cur)
    elif line.strip() and cur is not None:
        cur['files'].append(line.strip())
commits.sort(key=lambda c:(c['date'],c['sha']))
seen=collections.Counter(); N=5
ftc=[]
for c in commits:
    e=c['email']; seen[e]+=1
    if seen[e]<=N:
        hits=[(f,sens(f)) for f in c['files'] if sens(f)]
        if hits:
            ftc.append([c['sha'][:12],c['date'][:10],dom(e),cat(dom(e)),seen[e],emails[e],len(hits),';'.join(sorted({h[1] for h in hits})),';'.join(sorted({h[0] for h in hits}))[:400]])
wcsv('first_time_contributors_sensitive.csv',['sha','date','author_domain','category','nth_commit_of_author','author_total_commits','sensitive_files_touched','matched_patterns','files'],ftc)
# aggregate per author (anonymised by index)
agg=collections.OrderedDict()
for r in ftc:
    k=(r[2],r[5])
firsts=collections.Counter(); domain_first=collections.Counter()
for e in emails: pass
# authors with <=N commits total who touched sensitive paths at all
low=collections.defaultdict(lambda:{'commits':0,'sens_commits':0,'shas':[]})
for c in commits:
    e=c['email']
    if emails[e]<=N:
        low[e]['commits']=emails[e]
        hs=[f for f in c['files'] if sens(f)]
        if hs: low[e]['sens_commits']+=1; low[e]['shas'].append(c['sha'][:12])
lowrows=[(dom(e),cat(dom(e)),v['commits'],v['sens_commits'],';'.join(v['shas'])) for e,v in low.items() if v['sens_commits']]
lowrows.sort(key=lambda x:(-x[3],x[0]))
wcsv('low_volume_authors_touching_sensitive.csv',['author_domain','category','author_total_commits','commits_touching_sensitive','shas'],lowrows)
# sensitive path churn overall: commits touching sensitive paths, by domain category
sc=collections.Counter(); scd=collections.Counter()
for c in commits:
    if any(sens(f) for f in c['files']):
        sc[cat(dom(c['email']))]+=1; scd[dom(c['email'])]+=1
wcsv('sensitive_path_commits_by_category.csv',['category','commits_touching_sensitive'],sc.most_common())
wcsv('sensitive_path_commits_by_domain.csv',['domain','commits_touching_sensitive'],scd.most_common())
print(json.dumps({'total':total,'emails':len(emails),'domains':len(doms),'webflow':webflow,'ftc_rows':len(ftc),'low_rows':len(lowrows),'sens_total':sum(sc.values())}))
print('years',sorted(years.items()))
print('cats',cats.most_common())
print('tz',tz.most_common(12))
print('topdoms',doms.most_common(15))
