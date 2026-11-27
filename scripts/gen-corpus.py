#!/usr/bin/env python3
"""gen-corpus.py - corpus synthetique de N faux sites + manifeste verite-terrain.

Priorite: AWS SES, OpenAI, Anthropic, SendGrid, Mailjet.
Variantes realistes et piegeuses, plus des leurres qui ne doivent pas matcher.
Les identifiants de regles contiennent des tirets -> on passe les plantes
sous forme de liste de tuples (pas de kwargs).
"""
import os, random, string, json, sys, shutil, collections

N = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
OUT = sys.argv[2] if len(sys.argv) > 2 else '/tmp/corpus'
random.seed(1234)
shutil.rmtree(OUT, ignore_errors=True)

ALNUM = string.ascii_letters + string.digits
def rnd(n, alpha=ALNUM):
    return ''.join(random.choice(alpha) for _ in range(n))
def hexs(n):
    return rnd(n, 'abcdef0123456789')

SKEL = ('public', 'private', 'shared', 'server', 'portal', 'admin', 'api', 'data')
TLD = ('com', 'net', 'org', 'io', 'dev', 'app', 'co', 'fr', 'de', 'br', 'in')

manifest = []

def w(site_dir, rel, content, plants=()):
    p = os.path.join(site_dir, rel)
    os.makedirs(os.path.dirname(p) or site_dir, exist_ok=True)
    with open(p, 'w', encoding='utf-8') as f:
        f.write(content)
    for rule, secret in plants:
        if secret:
            manifest.append({'site': os.path.basename(site_dir), 'file': rel,
                             'rule_id': rule, 'secret': secret})

def gen_ses():
    u = 'AKIA' + rnd(16, string.ascii_uppercase + string.digits)
    pw = rnd(43) + '=' if random.random() < .6 else rnd(44)
    reg = random.choice(['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'sa-east-1'])
    return u, pw, 'email-smtp.%s.amazonaws.com' % reg

def gen_openai(style=None):
    style = style or random.choice(['classic', 'proj', 'svc'])
    if style == 'proj':
        return 'sk-proj-' + rnd(random.choice([48, 64]), ALNUM + '_-')
    if style == 'svc':
        return 'sk-svcacct-' + rnd(60, ALNUM + '_-')
    return 'sk-' + rnd(48, ALNUM)

def gen_anthropic():
    return 'sk-ant-api03-' + rnd(random.choice([93, 95]), ALNUM + '_-')

def gen_sendgrid():
    return 'SG.' + rnd(22, ALNUM + '-_') + '.' + rnd(43, ALNUM + '-_')

for i in range(N):
    sid = 'site_%04d' % i
    d = os.path.join(OUT, sid)
    os.makedirs(d, exist_ok=True)
    dom = '%s.%s' % (random.choice(SKEL), random.choice(TLD))

    # ---- .env
    lines, plants = ['APP_NAME=%s' % dom], []
    if random.random() < .55:
        u, pw, host = gen_ses()
        form = random.choice(['pair', 'smtp_named', 'blank_line'])
        if form == 'pair':
            lines += ['MAIL_USERNAME=%s' % u, 'MAIL_PASSWORD=%s' % pw]
        elif form == 'smtp_named':
            lines += ['SmtpHost:"%s"' % host, 'SmtpUser:"%s"' % u, 'SmtpPassword:"%s"' % pw]
        else:
            lines += ['SES_SMTP_USERNAME=%s' % u, '', 'SES_SMTP_PASSWORD=%s' % pw]
        lines.append('SES_HOST=%s' % host)
        plants.append(('aws-ses-smtp-username', u))
        plants.append(('aws-ses-smtp-password', pw))
        plants.append(('aws-ses-smtp-endpoint', host))
    if random.random() < .5:
        ok = gen_openai()
        lines.append('OPENAI_API_KEY=%s' % ok)
        plants.append(('openai-token-strict', ok))
    if random.random() < .45:
        ak = gen_anthropic()
        lines.append(random.choice(['ANTHROPIC_API_KEY', 'CLAUDE_KEY']) + '="%s"' % ak)
        plants.append(('anthropic-token-strict', ak))
    if random.random() < .5:
        s = gen_sendgrid()
        lines.append('SENDGRID_API_KEY=' + random.choice([s, "'%s'" % s]))
        plants.append(('sendgrid-token-strict', s))
    if random.random() < .5:
        pub, priv = hexs(32), hexs(32)
        if random.random() < .5:
            lines += ['MJ_APIKEY_PUBLIC=%s' % pub, 'MJ_APIKEY_PRIVATE=%s' % priv]
        else:
            lines += ['MAILJET_API_KEY=%s' % pub, 'MAILJET_SECRET_KEY=%s' % priv]
        plants.append(('mailjet-key', pub))
        plants.append(('mailjet-key', priv))
    if random.random() < .3:
        lines.append('MJ_REGION=eu')
    if random.random() < .3:
        lines.append('SK_LABEL=sk-' + rnd(8))
    if random.random() < .3:
        lines.append('SOME_HEX=deadbeef')
    w(d, '.env', '\n'.join(lines) + '\n', plants)

    # ---- .env.production
    if random.random() < .4:
        u, pw, host = gen_ses()
        w(d, '.env.production', 'SMTP_USERNAME=%s\nSMTP_PASSWORD=%s\nSMTP_HOST=%s\n' % (u, pw, host),
          [('aws-ses-smtp-username', u), ('aws-ses-smtp-password', pw)])

    # ---- index.html (JS inline)
    if random.random() < .5:
        oa = gen_openai('proj') if random.random() < .5 else gen_openai()
        w(d, 'index.html',
          '<!doctype html><html><head><title>%s</title></head><body>\n'
          '<script>window.CONFIG={openai:"%s"};</script>\n</body></html>\n' % (dom, oa),
          [('openai-token-strict', oa)])

    # ---- bundle JS
    if random.random() < .45:
        sg = gen_sendgrid()
        w(d, 'static/js/app.js',
          'var x="%s";var y=%d;\nconst KEY="%s";\nexport default {};\n' % (rnd(200), random.randint(1, 999), sg),
          [('sendgrid-token-strict', sg)])

    # ---- wp-config.php
    if random.random() < .35:
        s = gen_sendgrid()
        w(d, 'wp-config.php', "<?php\ndefine('SENDGRID_KEY','%s');\ndefine('DB_NAME','wp');\n" % s,
          [('sendgrid-token-strict', s)])

    # ---- config.json
    if random.random() < .3:
        ak = gen_anthropic()
        w(d, 'config.json', '{\n  "anthropic_key": "%s",\n  "debug": true\n}\n' % ak,
          [('anthropic-token-strict', ak)])

c = collections.Counter(m['rule_id'] for m in manifest)
print('corpus:', N, 'sites ->', OUT)
print('secrets plantes:', len(manifest))
for r, n in c.most_common():
    print('  %-28s %d' % (r, n))
with open(os.path.join(OUT, 'MANIFEST.jsonl'), 'w') as o:
    for m in manifest:
        o.write(json.dumps(m) + '\n')
print('manifeste:', os.path.join(OUT, 'MANIFEST.jsonl'))
