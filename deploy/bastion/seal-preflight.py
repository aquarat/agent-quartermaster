#!/usr/bin/python3
"""Local operator preflight. Never read or print credential contents.

Before the import record the effective LoadCredential name:path pairs in a
root-controlled JSON object. Afterwards run with CONFIG and that INVENTORY.
Refuse ambiguous (encrypted, implicit, changing or unrecorded) mappings.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tomllib


def protected(path):
    p = Path(path)
    if not p.is_absolute() or '..' in p.parts:
        raise ValueError('expected absolute path')
    for parent in [*reversed(p.parents), p]:
        s = parent.lstat()
        if s.st_uid or s.st_mode & 0o022 or stat.S_ISLNK(s.st_mode):
            raise ValueError('unsafe ownership or mode on pin/inventory path')
    if not stat.S_ISREG(p.lstat().st_mode):
        raise ValueError('expected regular file')
    return p


def main(config, sources):
    if os.geteuid() != 0:
        raise ValueError('run preflight as root')
    cfg = tomllib.loads(protected(config).read_text()); seal = cfg['seal']
    if not seal['required'] or len(seal['manifest_sha256']) != 64 or cfg.get('ntfy', {}).get('topic_url'):
        raise ValueError('incomplete seal pin or normal topic still in config')
    inventory = json.loads(protected(sources).read_text())
    if not isinstance(inventory, dict):
        raise ValueError('invalid source inventory')
    paths = list(inventory.values()); cf = cfg.get('cloudflare', {})
    for role in ['proxy', 'minter']:
        name = cf.get(role + '_token_credential'); path = cf.get(role + '_token_file')
        if name and name not in inventory:
            raise ValueError('missing original credential source in inventory')
        if path:
            paths.append(path)
    ca = Path(cfg.get('data_dir', '/var/lib/aqmas')) / 'ca'
    for p in [*paths, ca/'ssh_user_ca', ca/'client_ca.key']:
        if not Path(p).is_absolute() or os.path.lexists(p):
            raise ValueError('retired source path exists or is ambiguous')
    # Fail closed on implicit directory imports too: normal service needs no
    # systemd credentials for the two parents on this sealed installation.
    for prop in ['LoadCredential','LoadCredentialEncrypted','ImportCredential','SetCredential','SetCredentialEncrypted']:
        if subprocess.run(['systemctl','show','aqmasd.service','-p',prop,'--value'],
                          check=True, capture_output=True).stdout.strip():
            raise ValueError('remove effective credential mappings before starting sealed service')
    print('Root pin and listed online source retirements verified. Historical copies are operator-attested.')


if __name__ == '__main__':
    try:
        main(*sys.argv[1:])
    except Exception:
        sys.exit('seal preflight failed: check root pin, recorded source paths and effective unit mappings')
