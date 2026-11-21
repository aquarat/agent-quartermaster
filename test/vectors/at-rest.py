"""Regenerate suite1.json using independent Python HKDF and libsodium AEAD.
All bytes are public test constants. Never use these keys/nonces in a store.
"""
import ctypes
import ctypes.util
import hmac
import json
from pathlib import Path
import struct

lib = ctypes.CDLL(ctypes.util.find_library('sodium'))
lib.sodium_init()


def u64(n):
    return struct.pack('>Q', n)


def ctx(role, *pieces):
    return b''.join(struct.pack('>I', len(p)) + p for p in
                    (b'aqmas-seal', u64(1), role.encode(), *pieces))


def seal(key, nonce, plain, aad):
    out = ctypes.create_string_buffer(len(plain) + 16)
    rc = lib.crypto_aead_xchacha20poly1305_ietf_encrypt(
        out, None, plain, ctypes.c_ulonglong(len(plain)), aad,
        ctypes.c_ulonglong(len(aad)), None, bytes([nonce]) * 24, key)
    assert rc == 0
    return (b'\x01' + bytes([nonce]) * 24 + out.raw).hex()


install, salt, mk, dek, blob, prf = [bytes([n]) * 32 for n in range(1, 7)]
bind = [install, b'example.test', b'\xff\x01', u64(7), salt]
info = ctx('mk-kek', *bind)
prk = hmac.digest(install, prf, 'sha256')
kek = hmac.digest(prk, info + b'\x01', 'sha256')
v = dict(kek=kek.hex(), kek_info=info.hex(),
         wrap=seal(kek, 1, mk, ctx('mk-wrap', *bind)),
         check=seal(mk, 2, b'aqmas installation master key check', ctx('mk-check', install, u64(7))),
         records={})
for n, role in enumerate(['ssh-ca', 'internal-ca', 'ntfy-topic', 'cf-proxy', 'cf-minter', 'env-draft', 'env-revision']):
    path = [b'global', b'global-id'] if n < 3 else [b'scoped', b'org', b'service', b'set']
    f = [install, *path, role.encode(), u64(2), blob]
    if role.startswith('cf-'):
        f += [b'issuer', b'account', u64(3)]
    v['records'][role] = dict(payload=seal(dek, 8 + n, b'vector payload', ctx('payload', *f)),
                              wrap=seal(mk, 20 + n, dek, ctx('dek-wrap', *f, u64(7))))
Path(__file__).with_name('suite1.json').write_text(json.dumps(v, indent=2) + '\n')
