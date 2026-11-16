#!/usr/bin/env python3
"""Regenerates the pgfplots tables of Fig. eval-gen (paper-eval/6-dpf-data.tex)
from the CSVs in results-gen/.

    python3 -I scripts/paper_data.py [file.tex]

Rewrites every \\pgfplotstableread{...}\\T<name> block of the file in place and
leaves the rest of it (macros, colours, styles) as it is. Without the file
(default paper-eval/6-dpf-data.tex), it writes a new one with every table. A
CSV that is missing only drops its tables (a warning names it), and a block of
the file without data is kept as it is. Several rows for the same
(in_bits, out_bits) (the 1-rep processes from --reps-from on) are averaged.

Only the tables Fig. eval-gen plots, all at ℓ = 64. Each holds the cost of
preprocessing and generation of one key pair, without the session setup and
the COTs drawn from its pool: n, comp, total LAN, total WAN (s), comm (KB),
see `gen_cost`. The tree-based baselines (Fl, HT, HTm, FA, Dtwo): measured
rows in \\T<p>A, the last measured row plus the `+est` rows in \\T<p>XA.
\\TV<v>A, measured and `+est` rows from n = 12 on: ours (Osb sh-bin, Osa sh,
Omb mal, Oma mal-arith), FssNN (Fb, Fa) and our GGM instance (Lb, La:
ggm-lpn-{bin,arith} at ν = 2).

Also prints, for the prose: the four crossovers the dotted lines of Fig.
eval-gen mark (where both our half-tree variants, sh-bin and mal or sh and
mal-arith, become faster than every baseline of the panel, linearly
interpolated in n), the smallest n from which every one of our four
variants has a lower Gen total than each baseline (LAN, WAN, at
ℓ = 64, over all measured and extrapolated n up to 42), and how
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
# Fig. eval-gen: per-variant tables \TV<key>A, CSV names
VARIANTS = {'Osb': 'ht-aes-sh-bin', 'Osa': 'ht-aes-sh', 'Omb': 'ht-aes-mal', 'Oma': 'ht-aes-mal-arith',
            'Fb': 'fssnn-bin', 'Fa': 'fssnn-arith', 'Lb': 'ggm-lpn-bin', 'La': 'ggm-lpn-arith'}  # Lb, La: Π_GenGGM, ν = 2
# The panels of Fig. eval-gen: (our two half-tree variants, the baselines)
PANELS = {'Boolean': (['ht-aes-sh-bin', 'ht-aes-mal'], ['floram', 'ht', 'ht-mal-ferret', 'fssnn-bin']),
          'arithmetic': (['ht-aes-sh', 'ht-aes-mal-arith'], ['floram-arith', 'duoram-2p', 'fssnn-arith'])}

# The one-time session setup (base OTs, the IKNP base OTs of the OT extension,
# Ferret's bootstrap with its first main iteration) is removed. With
# charge_cots, used only for the extrapolated applications, a protocol on Ferret
# also pays every COT its key pair draws from the setup's pool at Ferret's
# marginal rate: 0.443 bits (CCS:YWLZW20) and 22.2 ns (our Ferret, Tab.
# prf-2pc). OT extension by IKNP already runs inside preprocessing and stays as
# measured. The LAN latency is the paper's, and the CSVs' lan_* columns, written
# by the benches at their default of 10 ms, are not read for Gen.
COT_BITS, COT_NS = 0.443, 22.2
LAN, WAN = (0.5, 1000.0), (100.0, 100.0)  # ms per round, Mbit/s
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


def gen_cost(name, row, charge_cots=False):
    """[comp, LAN, WAN, comm] in ms, ms, ms, bytes for one Gen row."""
    comp, nbytes, rounds = float(row[12]), float(row[10]), float(row[11])
    setup_ms, setup_bytes = float(row[17]), float(row[21])
    pre_rounds, gen_rounds = float(row[23]), float(row[26])
    f = ferret_cots(name, float(row[28]))
    if f > 0:
        # A Ferret session also spends ~59 ms, constant in n, outside its
        # setup, preprocessing and Gen timers (at least ~33 ms of it the pool's
        # teardown): a one-off per session, so only the per-key phases count.
        comp = float(row[18]) + max(float(row[19]), float(row[20]))
    else:
        comp -= setup_ms
    nbytes -= setup_bytes
    if charge_cots:
        comp += f * COT_NS / 1e6
        nbytes += f * COT_BITS / 8
    rounds = pre_rounds + gen_rounds  # rounds = setup + pre + gen
    return [comp, comp + net(rounds, nbytes, LAN), comp + net(rounds, nbytes, WAN), nbytes]


MISSING = []


def load(path, mode, name, charge_cots=False):
    """{(est, out_bits): {n: [c, l, w(, b)]}} in s (and KB), rows averaged;
    {} (and a warning at the end) if the CSV is missing."""
    acc = defaultdict(lambda: defaultdict(list))
    try:
        f = open(path)
    except FileNotFoundError:
        MISSING.append(path)
        return {}
    with f:
        for row in csv.reader(l for l in f if not l.startswith('#')):
            if not row or row[0] != mode:
                continue
            n, m = int(float(row[3])), int(row[4])
            est = row[1].endswith('+est')
            if mode == 'gen':
                v = gen_cost(name, row, charge_cots)
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


def add(tables, p, data):
    """\\T<p>A (measured) and \\T<p>XA (last measured row and `+est` rows), ℓ = 64."""
    meas = data.get((False, 64), {})
    if not meas:
        return
    tables[f'T{p}A'] = table(meas, 'clwb')
    est = data.get((True, 64), {})
    if est:
        last = max(meas)
        tables[f'T{p}XA'] = table({last: meas[last], **est}, 'clwb')


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
    print('Ours faster from (Gen without setup, ℓ = 64; smallest n0 with ours lower at every n ≥ n0):')
    for p, d in gen.items():
        s = series(d)
        out = []
        for i, link in [(1, 'LAN'), (2, 'WAN')]:
            ns = sorted(n for n in s if n in env)
            win = [n for n in ns if all(env[k][i] < s[k][i] for k in ns if k >= n)]
            out.append(f'{link} {"all" if win and win[0] == ns[0] else win[0] if win else "never"}')
        print(f'  {PROTOS[p]:16s} {", ".join(out)}  (n = {min(s)}..{max(s)})')


def crossovers():
    """The dotted lines of Fig. eval-gen: the n (linearly interpolated) from
    which both our half-tree variants of a panel are faster than every
    baseline of it, at ℓ = 64."""
    print('Fig. eval-gen, dotted lines (both our half-tree variants faster than every baseline from n =):')
    for panel, (ours, base) in PANELS.items():
        o = [series(load(f'results-gen/{p}.csv', 'gen', p)) for p in ours]
        b = [series(load(f'results-gen/{p}.csv', 'gen', p)) for p in base]
        if not all(o + b):
            continue
        ns = sorted(set.intersection(*(set(s) for s in o + b)))
        out = []
        for i, link in [(1, 'LAN'), (2, 'WAN')]:
            d = {n: max(s[n][i] for s in o) - min(s[n][i] for s in b) for n in ns}
            x = None
            for lo, hi in zip(ns, ns[1:]):
                if d[lo] >= 0 > d[hi]:
                    x = lo + d[lo] / (d[lo] - d[hi])
            out.append(f'{link} {x:.2f}' if x is not None else f'{link} never')
        print(f'  {panel:10s} {", ".join(out)}')


def keys_per_pool(csvs):
    print(f'Key pairs per Ferret pool ({POOL:,} COTs per direction, both directions):')
    for name, path in csvs:
        ks = []
        try:
            f = open(path)
        except FileNotFoundError:
            continue
        with f:
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
    gen = {p: load(f'results-gen/{name}.csv', 'gen', name) for p, name in PROTOS.items()}
    for p, data in gen.items():
        if p not in VARIANTS:  # FssNN is plotted from \TVFbA, \TVFaA
            add(tables, p, data)
    ours_gen = [load(f'results-gen/{name}.csv', 'gen', name) for name in OURS]
    for v, name in VARIANTS.items():
        g = {k: {n: x for n, x in d.items() if n >= 12} for k, d in load(f'results-gen/{name}.csv', 'gen', name).items()}
        if (False, 64) in g:
            tables[f'TV{v}A'] = table(series(g), 'clwb')

    crossovers()
    if all(gen.values()) and all(ours_gen):
        report(gen, ours_gen)
    keys_per_pool([(n, f'results-gen/{n}.csv') for n in ['ht-mal-ferret', 'fssnn-bin', 'fssnn-arith', *OURS, 'ggm-lpn-bin', 'ggm-lpn-arith']])

    try:
        src = open(tex).read()
    except FileNotFoundError:
        src = '% plot data of Fig. eval-gen, written by scripts/paper_data.py\n'
        print(f'{tex} not found: writing a new file with every table')
    block = re.compile(r'\\pgfplotstableread\{n [^\n]*\n.*?\n\}\\(T\w+)\n', re.S)
    seen, kept = set(), []

    def repl(mt):
        name = mt.group(1)
        seen.add(name)
        if name not in tables:
            kept.append(name)
            return mt.group(0)
        return tables[name] + '\\' + name + '\n'

    out = block.sub(repl, src)
    missing = sorted(set(tables) - seen)
    if missing:  # new tables (e.g. a new +est series) go after the last one
        out = out.rstrip('\n') + '\n' + ''.join(tables[t] + '\\' + t + '\n' for t in missing)
    open(tex, 'w').write(out)
    print(f'{tex}: {len(seen) - len(kept)} tables rewritten, added: {", ".join(missing) or "none"}')
    if kept:
        print(f'  kept without data: {", ".join(kept)}')
    if MISSING:
        print(f'  missing CSVs (their tables skipped): {", ".join(sorted(set(MISSING)))}')


if __name__ == '__main__':
    main()
