#!/usr/bin/env python3
"""eval-corpus.py - mesure precision/rappel du scanner sur le corpus synthetique.

Usage: eval-corpus.py <corpus_dir> <findings.jsonl>
Compare les detections au manifeste verite-terrain et liste, par regle:
  - rappel   : secrets plantes retrouves
  - manques  : secrets plantes NON retrouves (avec fichier + extrait)
  - faux pos.: detections dont le secret n'est pas plante (hors regles connues)
"""
import json, sys, os, collections

corpus, findings_path = sys.argv[1], sys.argv[2]
TARGETS = {'aws-ses-smtp-username', 'aws-ses-smtp-password', 'aws-ses-smtp-endpoint',
           'openai-token-strict', 'anthropic-token-strict', 'sendgrid-token-strict',
           'mailjet-key', 'smtp-endpoint', 'smtp-credential'}

man = collections.defaultdict(list)          # (rule) -> [(file, secret)]
for l in open(os.path.join(corpus, 'MANIFEST.jsonl'), encoding='utf-8'):
    m = json.loads(l)
    if m['rule_id'] in TARGETS:
        man[m['rule_id']].append((m['file'].replace('\\', '/'), m['secret']))

found = collections.defaultdict(list)        # rule -> [(file, secret)]
all_det = collections.Counter()
for l in open(findings_path, encoding='utf-8', errors='replace'):
    if not l.strip():
        continue
    try:
        f = json.loads(l)
    except Exception:
        continue
    r = f.get('rule_id')
    all_det[r] += 1
    if r in TARGETS:
        loc = f.get('location') or {}
        found[r].append(((loc.get('file') or '').replace('\\', '/'), f.get('secret', '')))

print('%-28s %6s %6s %6s' % ('regle', 'plante', 'trouve', 'rappel'))
tot_p = tot_f = 0
misses = collections.defaultdict(list)
for r in sorted(TARGETS):
    planted = man.get(r, [])
    dets = found.get(r, [])
    hit = 0
    for file_, secret in planted:
        # le secret detecte peut englober (ex: paire user/pass) -> sous-chaine
        ok = any(secret in dsec and (file_ == dfile or dfile.endswith(file_) or file_.endswith(dfile))
                 for dfile, dsec in dets)
        if ok:
            hit += 1
        else:
            misses[r].append((file_, secret))
    pct = (100.0 * hit / len(planted)) if planted else 100.0
    tot_p += len(planted); tot_f += hit
    print('%-28s %6d %6d %5.1f%%' % (r, len(planted), hit, pct))

print()
print('RAPPEL GLOBAL: %d/%d (%.1f%%)' % (tot_f, tot_p, 100.0 * tot_f / tot_p if tot_p else 100))

print()
print('=== exemples de manques ===')
for r, lst in misses.items():
    print(' %s (%d manques)' % (r, len(lst)))
    for file_, secret in lst[:4]:
        print('    %s | %s' % (file_, secret[:56]))

# faux positifs: detections dont le secret n'est pas dans le manifeste
print()
print('=== detections suspectes (secret non plante) ===')
for r in sorted(TARGETS):
    planted_secrets = set(s for _, s in man.get(r, []))
    extra = [(f2, s) for f2, s in found.get(r, []) if not any(p in s for p in planted_secrets)]
    if extra:
        print(' %s : %d' % (r, len(extra)))
        for f2, s in extra[:4]:
            print('    %s | %s' % (f2, s[:56]))
