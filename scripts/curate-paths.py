#!/usr/bin/env python3
"""Construit une selection curee de chemins a partir de paths-all.txt.

Objectif: une liste courte (utilisable sur des millions d'hotes) qui garde les
chemins a plus forte valeur et evite les 1000 variantes de meme nom.
"""
import os, collections, re

SRC = 'paths/paths-all.txt'
OUT200 = 'paths/paths-top200.txt'
OUT40 = 'paths/paths-top40.txt'

paths = [l.strip() for l in open(SRC, encoding='utf-8') if l.strip()]

HIGH_BASE = {  # noms de fichier a forte valeur, toutes extensions
    '.env', '.env.local', '.env.production', '.env.dev', '.env.staging', '.env.backup',
    'config.php', 'wp-config.php', 'configuration.php', 'settings.php', 'config.json',
    'config.yml', 'config.yaml', 'config.ini', 'config.js', 'config.ts', 'config.xml',
    'settings.py', 'local_settings.py', 'application.properties', 'appsettings.json',
    '.aws/credentials', 'credentials', 'credentials.json', '.git-credentials',
    '.npmrc', '.htpasswd', 'backup.sql', 'dump.sql', 'database.sql', 'db.sql',
    '.docker/config.json', 'docker-compose.yml', 'docker-compose.yaml', 'Dockerfile',
    '.git/config', '.git/HEAD', 'composer.json', 'package.json', '.htaccess',
    'web.config', 'phpinfo.php', 'info.php', 'server-status', 'env.js', 'env.php',
}
HIGH_EXT = ('.sql', '.bak', '.old', '.backup', '.zip', '.tar.gz', '.pem', '.key',
            '.p12', '.tfstate', '.ini', '.conf', '.cfg', '.log')
HINT = re.compile(r'(?i)(env|config|secret|credential|backup|dump|database|db|key|pass|'
                  r'token|auth|setting|\.aws|\.git|docker|firebase|serviceaccount)')

scored = []
for p in paths:
    base = p.rstrip('/').split('/')[-1]
    depth = p.count('/')
    score = 0
    if base in HIGH_BASE:
        score += 100
    if base.startswith('.env'):
        score += 60
    if base.endswith(HIGH_EXT):
        score += 30
    if HINT.search(p):
        score += 12
    if base.startswith('.'):
        score += 6
    score += max(0, 12 - 2 * depth)          # privilegier les chemins courts
    scored.append((score, depth, p))

scored.sort(key=lambda x: (-x[0], x[1], x[2]))

def dedupe_by_base(items, limit):
    seen = collections.Counter()
    out = []
    for sc, dp, p in items:
        base = p.rstrip('/').split('/')[-1]
        cap = 3 if base == '.env' else 1
        if seen[base] >= cap:
            continue
        seen[base] += 1
        out.append(p)
        if len(out) >= limit:
            break
    return out

top200 = dedupe_by_base(scored, 200)
open(OUT200, 'w').write('\n'.join(top200) + '\n')
print('ecrit', OUT200, len(top200), 'chemins')

# 40 chemins: le noyau indispensable, choisi a la main dans la selection
must = ['/.env', '/.env.local', '/.env.production', '/.git/HEAD', '/.git/config',
        '/config.php', '/wp-config.php', '/config.json', '/config.yml', '/config.js',
        '/app/.env', '/application/.env', '/laravel/.env', '/.aws/credentials',
        '/.docker/config.json', '/settings.py', '/appsettings.json', '/package.json',
        '/composer.json', '/.npmrc', '/credentials.json', '/.git-credentials',
        '/backup.sql', '/docker-compose.yml', '/.htaccess', '/phpinfo.php',
        '/blockchain/.env', '/api/.env', '/admin/.env', '/core/.env', '/app/config/parameters.yml',
        '/config/database.yml', '/storage/.env', '/local/.env', '/dev/.env', '/test/.env',
        '/prod/.env', '/live/.env', '/stage/.env', '/uploads/.env']
present = {p for p in paths}
sel = [p for p in must if p in present]
for p in top200:
    if len(sel) >= 40:
        break
    if p not in sel:
        sel.append(p)
open(OUT40, 'w').write('\n'.join(sel[:40]) + '\n')
print('ecrit', OUT40, len(sel[:40]), 'chemins')
