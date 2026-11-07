#!/usr/bin/env python3
"""Regenerates the pgfplots tables of paper-eval/6-dpf-data.tex from the
CSVs in results-gen/, results-eval/ and results-template/.

    python3 -I scripts/paper_data.py [paper-eval/6-dpf-data.tex]

Rewrites every \\pgfplotstableread{...}\\T<name> block in place and leaves the
rest of the file (macros, colours, styles) as it is. Several rows for the same
(in_bits, out_bits) (the 1-rep processes from --reps-from on) are averaged.

Gen tables hold the **amortized** cost of one key pair: n, comp, total LAN,
total WAN (s), comm (KB), see `amortize`. Measured rows go into \\T<p>A/B, the
last measured row plus the `+est` rows into \\T<p>XA/XB. Full-domain Eval
tables: n, comp, LAN, WAN (s); measured rows into \\T<p>EA/EB, the last
measured row plus `+est` rows into \\T<p>XEA/XEB. \\TOenv* is the maximum over
our four variants. \\TP* are the tables of our template's section
(results-template/): Floram, Half-Tree, and ours with AES--MMO (\\TPAes<ν>) and
with the LPN-PRG (\\TPLpn<ν>), ν spelled out (one, five, seventeen).

Also prints, for the prose: the smallest n from which every one of our four
variants has a lower amortized Gen total than each baseline (LAN, WAN, at
ℓ = 64, over all measured and extrapolated n up to 42), the same for each
instance and ν of the template section against Floram and Half-Tree, and how
many key pairs the COT pool of one Ferret setup covers (n ≥ 8).
"""
import csv
import re
import sys
from collections import defaultdict

PROTOS = {  # table prefix -> CSV name
    'Fl': 'floram', 'HT': 'ht', 'HTm': 'ht-mal-ferret', 'FA': 'floram-arith',
    'Fb': 'fssnn-bin', 'Fa': 'fssnn-arith', 'Dtwo': 'duoram-2p',
}
OURS = ['ht-aes-sh-bin', 'ht-aes-sh', 'ht-aes-mal', 'ht-aes-mal-arith']
WIDTH = {64: 'A', 128: 'B'}
NU = {1: 'one', 5: 'five', 17: 'seventeen'}
PRF = {'PFl': 'floram', 'PHT': 'ht',  # results-template/{gen,full}/ CSV names
       **{f'PAes{w}': f'ht-aes-sh-bin-nu{v}' for v, w in NU.items()},
       **{f'PLpn{w}': f'ggm-lpn-bin-nu{v}' for v, w in NU.items()}}
PRF_FULL_NU = 5

# Amortization. The one-time session setup (base OTs, the IKNP base OTs of
# the OT extension, Ferret's bootstrap with its first main iteration) is
# removed. A protocol on Ferret instead pays every COT its key pair draws from
# the setup's pool at Ferret's marginal rate: 0.443 bits (CCS:YWLZW20) and
# 23.3 ns (our Ferret, Tab. prf-2pc), the cost of the next main iteration once
# the pool runs dry. OT extension by IKNP already runs inside preprocessing
# and stays as measured.
COT_BITS, COT_NS = 0.443, 23.3
LAN, WAN = (10.0, 1000.0), (100.0, 100.0)  # ms per round, Mbit/s
# Ferret B13 (crates/common/src/ot/ferret.rs): COTs per direction in the pool
# after the bootstrap, main.n - (main.k + main.t * main.log_bin + 128).
POOL = 10_485_760 - (452_000 + 1_280 * 13 + 128)
# FssNN's `cots` counts every COT of its CotPair, including the base COTs
# that bootstrap Ferret, pre.t * pre.log_bin + pre.k + 128 per direction (both
# directions as each party sees them); these are part of the setup.
FERRET_BASE = 2 * (918 * 9 + 32_768 + 128)


def ferret_cots(name, cots):
    """COTs a key pair draws from a Ferret pool (0 without Ferret)."""
    if name.startswith(('ht-aes', 'ggm-lpn')) or name == 'ht-mal-ferret':
        return cots
    if name.startswith('fssnn'):
        return cots - FERRET_BASE
    return 0


def net(rounds, nbytes, link):
    lat, mbps = link
    return rounds * lat + 8 * nbytes / (mbps * 1e3)  # ms


def amortize(name, row):
    """[comp, LAN, WAN, comm] in ms, ms, ms, bytes for one Gen row."""
    comp, nbytes, rounds = float(row[12]), float(row[10]), float(row[11])
    setup_ms, setup_bytes = float(row[17]), float(row[21])
    pre_rounds, gen_rounds = float(row[23]), float(row[26])
    f = ferret_cots(name, float(row[28]))
    comp = comp - setup_ms + f * COT_NS / 1e6
    nbytes = nbytes - setup_bytes + f * COT_BITS / 8
    rounds = pre_rounds + gen_rounds  # rounds = setup + pre + gen
    return [comp, comp + net(rounds, nbytes, LAN), comp + net(rounds, nbytes, WAN), nbytes]


def load(path, mode, name):
    """{(est, out_bits): {n: [c, l, w(, b)]}} in s (and KB), rows averaged;
    Gen rows amortized."""
    acc = defaultdict(lambda: defaultdict(list))
    with open(path) as f:
        for row in csv.reader(l for l in f if not l.startswith('#')):
            if not row or row[0] != mode:
                continue
            n, m = int(float(row[3])), int(row[4])
            est = row[1].endswith('+est')
            if mode == 'gen':
                v = amortize(name, row)
            else:
                v = [float(row[12]), float(row[14]), float(row[16])]
            acc[(est, m)][n].append([x / 1e3 for x in v])
    return {k: {n: [sum(c) / len(c) for c in zip(*v)] for n, v in d.items()}
            for k, d in acc.items()}


def fmt(x):
    return f'{x:.4g}'


def table(rows, cols):
    lines = ['\\pgfplotstableread{n ' + ' '.join(cols)]
    for n in sorted(rows):
        lines.append(' '.join([str(n)] + [fmt(v) for v in rows[n][:len(cols)]]))
    return '\n'.join(lines) + '\n}'


def add(tables, p, tag, cols, data):
    for m, w in WIDTH.items():
        meas = data.get((False, m), {})
        if not meas:
            continue
        tables[f'T{p}{tag}{w}'] = table(meas, cols)
        est = data.get((True, m), {})
        if est:
            last = max(meas)
            tables[f'T{p}X{tag}{w}'] = table({last: meas[last], **est}, cols)


def series(data, m=64):
    """Measured and extrapolated rows of one width, {n: [c, l, w, b]}."""
    return {**data.get((True, m), {}), **data.get((False, m), {})}


def report(gen, ours):
    """Crossovers against our four variants, and keys per Ferret pool."""
    env = {}
    for o in ours:
        for n, v in series(o).items():
            env.setdefault(n, []).append(v)
    env = {n: [max(x[i] for x in vs) for i in range(4)] for n, vs in env.items() if len(vs) == len(ours)}
    print('Ours faster from (amortized, ℓ = 64; smallest n0 with ours lower at every n ≥ n0):')
    for p, d in gen.items():
        s = series(d)
        out = []
        for i, link in [(1, 'LAN'), (2, 'WAN')]:
            ns = sorted(n for n in s if n in env)
            win = [n for n in ns if all(env[k][i] < s[k][i] for k in ns if k >= n)]
            out.append(f'{link} {"all" if win and win[0] == ns[0] else win[0] if win else "never"}')
        print(f'  {PROTOS[p]:16s} {", ".join(out)}  (n = {min(s)}..{max(s)})')


def report_prf(prf):
    """Our template's section: each instance and ν against Floram and Half-Tree."""
    print('Template section (amortized Gen, ℓ = 64): smallest n0 from which the instance is faster at every n ≥ n0')
    for p in prf:
        if not p.startswith(('PAes', 'PLpn')):
            continue
        o = series(prf[p])
        out = []
        for b in ['PFl', 'PHT']:
            s = series(prf[b])
            for i, link in [(1, 'LAN'), (2, 'WAN')]:
                ns = sorted(n for n in o if n in s)
                win = [n for n in ns if all(o[k][i] < s[k][i] for k in ns if k >= n)]
                out.append(f'{PRF[b]} {link} {("all" if win[0] == ns[0] else win[0]) if win else "never"}')
        print(f'  {PRF[p]:22s} {", ".join(out)}  (n = {min(o)}..{max(o)})')


def keys_per_pool(csvs):
    print(f'Key pairs per Ferret pool ({POOL:,} COTs per direction, both directions):')
    for name, path in csvs:
        ks = []
        with open(path) as f:
            for row in csv.reader(l for l in f if not l.startswith('#')):
                if row and row[0] == 'gen' and not row[1].endswith('+est') and float(row[3]) >= 8:
                    c = ferret_cots(name, float(row[28]))
                    if c > 0:
                        ks.append((2 * POOL / c, int(float(row[3])), int(row[4])))
        if ks:
            lo, hi = min(ks), max(ks)
            print(f'  {name:22s} {lo[0]:9,.0f} (n={lo[1]}, ℓ={lo[2]}) .. {hi[0]:9,.0f} (n={hi[1]}, ℓ={hi[2]})')


def main():
    tex = sys.argv[1] if len(sys.argv) > 1 else 'paper-eval/6-dpf-data.tex'
    tables = {}
    gen = {}
    for mode, d, cols, tag in [('gen', 'results-gen', 'clwb', ''),
                               ('full', 'results-eval', 'clw', 'E')]:
        for p, name in PROTOS.items():
            data = load(f'{d}/{name}.csv', mode, name)
            if mode == 'gen':
                gen[p] = data
            add(tables, p, tag, cols, data)
        ours = [load(f'{d}/{name}.csv', mode, name) for name in OURS]
        if mode == 'gen':
            ours_gen = ours
        for m, w in WIDTH.items():
            ns = set.intersection(*(set(o[(False, m)]) for o in ours))
            env = {n: [max(o[(False, m)][n][i] for o in ours) for i in range(len(cols))] for n in ns}
            tables[f'TOenv{tag}{w}'] = table(env, cols)
    prf = {}
    for p, name in PRF.items():
        # n ≥ 8 as for the baselines (ours runs from n = ν + 1)
        prf[p] = {k: {n: v for n, v in d.items() if n >= 8}
                  for k, d in load(f'results-template/gen/{name}.csv', 'gen', name).items()}
        add(tables, p, '', 'clwb', prf[p])
        if name in ('floram', 'ht') or name.endswith(f'-nu{PRF_FULL_NU}'):
            add(tables, p, 'E', 'clw', load(f'results-template/full/{name}.csv', 'full', name))

    report(gen, ours_gen)
    report_prf(prf)
    keys_per_pool([(n, f'results-gen/{n}.csv') for n in ['ht-mal-ferret', 'fssnn-bin', 'fssnn-arith', *OURS]]
                  + [(f'{n}-nu{v}', f'results-template/gen/{n}-nu{v}.csv') for n in ['ht-aes-sh-bin', 'ggm-lpn-bin'] for v in NU])

    src = open(tex).read()
    block = re.compile(r'\\pgfplotstableread\{n [^\n]*\n.*?\n\}\\(T\w+)\n', re.S)
    seen = set()

    def repl(mt):
        name = mt.group(1)
        seen.add(name)
        if name not in tables:
            sys.exit(f'{tex}: no data for \\{name}')
        return tables[name] + '\\' + name + '\n'

    out = block.sub(repl, src)
    missing = sorted(set(tables) - seen)
    if missing:  # new tables (e.g. a new +est series) go after the last one
        out = out.rstrip('\n') + '\n' + ''.join(tables[t] + '\\' + t + '\n' for t in missing)
    open(tex, 'w').write(out)
    print(f'{tex}: {len(seen)} tables rewritten, added: {", ".join(missing) or "none"}')


if __name__ == '__main__':
    main()
