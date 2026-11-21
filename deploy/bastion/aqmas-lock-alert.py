#!/usr/bin/python3
"""Read one local metadata file. No daemon-supplied URL, header or body."""
import hashlib
import http.client
import os
from pathlib import Path
import re
import stat
import time
from urllib.parse import urlsplit

MESSAGE = 'aqmas locked or unavailable — open your bookmarked approval page'.encode()
STATUS = '/run/aqmas-lock/seal-status'
STATE = Path('/var/lib/aqmas-lock-alert/last')


def generation():
    try:
        with os.fdopen(os.open(STATUS, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                return b'down'
            match = re.fullmatch(rb'(locked|unlocked) ([a-zA-Z0-9_-]{43})\n', f.read(100))
            if not match:
                return b'down'
            return match[2] if match[1] == b'locked' else None
    except OSError:
        return b'down'


def publish():
    d = Path(os.environ['CREDENTIALS_DIRECTORY'])
    u = urlsplit((d / 'topic-url').read_text().strip())
    token = (d / 'publish-token').read_text().strip()
    if u.scheme != 'https' or not u.hostname or u.username or u.password or u.query or u.fragment or not token:
        raise ValueError('invalid provisioning')
    c = http.client.HTTPSConnection(u.hostname, u.port, timeout=8)
    try:
        c.request('POST', u.path, MESSAGE, {'Authorization': 'Bearer ' + token, 'Content-Type': 'text/plain; charset=utf-8'})
        return 200 <= c.getresponse().status < 300
    finally:
        c.close()


def main():
    # Persistent across helper restarts; a hostile status writer must not be
    # able to choose published text or turn generation changes into a flood.
    try:
        last = STATE.read_text().strip()
    except FileNotFoundError:
        last = ''
    current, tries, next_try = None, 0, 0
    while True:
        g = generation()
        digest = hashlib.sha256(g).hexdigest() if g else ''
        if digest != current:
            current, tries = digest, 0
        if not digest and last:
            STATE.write_text(''); last = ''
        if digest and digest != last and tries < 5 and time.monotonic() >= next_try:
            try:
                ok = publish()
            except (OSError, ValueError, KeyError, http.client.HTTPException):
                ok = False
            if ok:
                STATE.write_text(digest); last = digest
            else:
                print('fixed lock alert delivery failed', flush=True)
            tries += 1
            next_try = time.monotonic() + min(300, 30 * 2 ** (tries - 1))
        time.sleep(3)


if __name__ == '__main__':
    main()
