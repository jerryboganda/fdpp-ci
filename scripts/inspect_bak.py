#!/usr/bin/env python3
"""Inspect SQL Server .BAK media headers.

Subcommands:
  entropy     - sample entropy of the file (detects compressed/encrypted payloads)
  calibrate   - find how SQL Server stores the backup password verifier by
                comparing backups made with known passwords, then extract the
                verifier from the user's backup
  crack       - dictionary attack against the extracted verifier
  stringscan  - scan the raw backup for username/password-looking strings
                (SQL backup passwords gate restore, they do NOT encrypt data)
"""
import argparse
import base64
import hashlib
import json
import math
import os

ENCS = {'utf16le': 'utf-16-le', 'utf8': 'utf-8'}
ALGOS = {'md5': hashlib.md5, 'sha1': hashlib.sha1}
FORMS = {'id': lambda s: s, 'upper': str.upper, 'lower': str.lower}
HDR = 65536


def verifier_bytes(pw, enc, algo, form):
    return ALGOS[algo](FORMS[form](pw).encode(ENCS[enc])).digest()


def find_hits(hdr, pw):
    hits = []
    for form in FORMS:
        for enc in ENCS:
            for algo in ALGOS:
                h = verifier_bytes(pw, enc, algo, form)
                start = 0
                while True:
                    off = hdr.find(h, start)
                    if off == -1:
                        break
                    hits.append((form, enc, algo, off, len(h)))
                    start = off + 1
    return hits


def diff_runs(a, b, minlen=8, gap=3):
    n = min(len(a), len(b))
    diffs = [i for i in range(n) if a[i] != b[i]]
    runs = []
    if not diffs:
        return runs
    s = p = diffs[0]
    for i in diffs[1:]:
        if i - p <= gap:
            p = i
            continue
        runs.append((s, p))
        s = p = i
    runs.append((s, p))
    return [(o, e - o + 1, a[o:e + 1].hex(), b[o:e + 1].hex())
            for (o, e) in runs if e - o + 1 >= minlen]


def cmd_entropy(a):
    import collections
    size = os.path.getsize(a.file)
    print(f"file size: {size} bytes")
    offs = [0, size // 4, size // 2, (3 * size) // 4]
    for off in offs:
        with open(a.file, 'rb') as f:
            f.seek(off)
            data = f.read(1024 * 1024)
        cnt = collections.Counter(data)
        ent = -sum((c / len(data)) * math.log2(c / len(data)) for c in cnt.values())
        print(f"offset 0x{off:x}: entropy {ent:.3f} bits/byte")


def cmd_calibrate(a):
    rd = lambda p: open(p, 'rb').read(HDR)
    u, c1, c2 = rd(a.user), rd(a.calib1), rd(a.calib2)
    h1, h2 = find_hits(c1, a.pw1), find_hits(c2, a.pw2)
    print("calib1 hits:", h1)
    print("calib2 hits:", h2)
    common = [h for h in h1 if h in h2]
    print("COMMON verifier configs:", common)
    runs = diff_runs(c1, c2)
    print("===== diff runs calib1 vs calib2 (len>=8) =====")
    for (off, ln, xa, xb) in runs:
        print(f"offset 0x{off:x} len {ln}\n  pw1: {xa}\n  pw2: {xb}")
    print("===== user header bytes at those offsets =====")
    for (off, ln, _xa, _xb) in runs:
        print(f"offset 0x{off:x}: {u[off:off + ln].hex()}")
    if not common:
        print("RESULT: NO_FAST_VERIFIER_FOUND")
        return
    cfgs = []
    for (form, enc, algo, off, ln) in common:
        th = u[off:off + ln]
        cfgs.append({'form': form, 'enc': enc, 'algo': algo,
                     'offset': off, 'len': ln, 'target': th.hex()})
        print(f"config {form}|{enc}|{algo}@0x{off:x}: target={th.hex()}")
    json.dump(cfgs, open(a.out, 'w'), indent=1)
    print("RESULT: VERIFIER_FOUND")


def cmd_crack(a):
    cfgs = json.load(open(a.configs))
    targets = {bytes.fromhex(c['target']) for c in cfgs}
    print(f"target hashes: {sorted(t.hex() for t in targets)}")

    def check(pw):
        for c in cfgs:
            if verifier_bytes(pw, c['enc'], c['algo'], c['form']) in targets:
                return pw
        return None

    found = None
    tried = 0
    for path in a.wordlists:
        if not os.path.exists(path):
            print(f"skip missing wordlist {path}")
            continue
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                w = line.rstrip('\r\n')
                if not w:
                    continue
                tried += 1
                if check(w):
                    found = w
                    break
        if found:
            break
    if not found:
        print(f"NOT CRACKED ({tried} candidates tried)")
        return
    print(f"CRACKED: {found!r}")
    if a.github_env:
        with open(a.github_env, 'a') as f:
            f.write(f"BAK_PWD_B64={base64.b64encode(found.encode()).decode()}\n")


def cmd_stringscan(a):
    pats = {
        'admin_u16': 'admin'.encode('utf-16-le'),
        'admin_ascii': b'admin',
        'password_u16': 'password'.encode('utf-16-le'),
        'username_u16': 'username'.encode('utf-16-le'),
    }
    counts = dict.fromkeys(pats, 0)
    CH = 8 * 1024 * 1024
    overlap = 4096
    prev = b''
    off = 0
    with open(a.file, 'rb') as f:
        while True:
            chunk = f.read(CH)
            if not chunk:
                break
            buf = prev + chunk
            base = off - len(prev)
            for name, p in pats.items():
                if counts[name] >= a.max_hits:
                    continue
                start = 0
                while True:
                    i = buf.find(p, start)
                    if i == -1:
                        break
                    start = i + 1
                    abs_i = base + i
                    counts[name] += 1
                    lo = max(0, i - a.ctx)
                    hi = min(len(buf), i + len(p) + a.ctx)
                    ctxb = buf[lo:hi]
                    printable = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctxb)
                    print(f"== {name} @0x{abs_i:x} ==")
                    print(f"HEX: {ctxb.hex()}")
                    print(f"TXT: {printable}")
                    if counts[name] >= a.max_hits:
                        break
            off += len(chunk)
            prev = chunk[-overlap:]
    print("hit counts:", counts)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('entropy')
    p.add_argument('--file', required=True)
    p.set_defaults(func=cmd_entropy)

    p = sub.add_parser('calibrate')
    p.add_argument('--user', required=True)
    p.add_argument('--calib1', required=True)
    p.add_argument('--pw1', required=True)
    p.add_argument('--calib2', required=True)
    p.add_argument('--pw2', required=True)
    p.add_argument('--out', required=True)
    p.set_defaults(func=cmd_calibrate)

    p = sub.add_parser('crack')
    p.add_argument('--configs', required=True)
    p.add_argument('--wordlists', nargs='+', required=True)
    p.add_argument('--github-env')
    p.set_defaults(func=cmd_crack)

    p = sub.add_parser('stringscan')
    p.add_argument('--file', required=True)
    p.add_argument('--max-hits', type=int, default=25)
    p.add_argument('--ctx', type=int, default=256)
    p.set_defaults(func=cmd_stringscan)

    a = ap.parse_args()
    a.func(a)


if __name__ == '__main__':
    main()
