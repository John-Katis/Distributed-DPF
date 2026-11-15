#!/usr/bin/env python3
"""Prints the two tables of §6 that are not plots, from the CSVs of the sweeps:

    python3 -I scripts/paper_tables.py [comm|apps]   (default: both)

* comm: Tab. eval-comm-rounds. Gen communication (KB, 1 KB = 1000 B) and
  rounds of one key pair at n = 20 and n = 32, ℓ = 64, without the session
  setup and the COTs drawn from its pool (as Fig. eval-gen, see
  paper_data.gen_cost), and the time per point of full-domain Eval at n = 32
  (extrapolated rows `+est` where n = 32 was not measured).

* apps: Tab. eval-apps, extrapolated from the same CSVs (§6b, "Method"); no
  application is run. Per key, the measured cost of its domain: Gen without
  the session setup, plus every COT it draws from Ferret at 0.443 bits and
  22.2 ns (`experimental_code/prf-bench ... ferret`), since millions of keys
  exhaust the pool of one setup. Half-Tree's COTs come from IKNP, charged at
  κ = 128 bits each for a batch of keys instead of the one IKNP block a
  single key pays. A fractional n interpolates the integer rows linearly,
  and above n = 42 the cost continues linearly with the slope of n = 41..42.
  Gen runs all keys of an application in the WAN, batched into the same
  rounds: Σ comp + max rounds · 100 ms + Σ bytes / 100 Mbit/s. A DCF key
  costs the DPF key of its domain with twice the cost of each joint level
  (n − ν + 1 for the half-tree instance, n − ν for the GGM instance) and two
  more rounds; FssNN's DCF is charged at its DPF, a lower bound. Eval: the
  measured full-domain Eval of every key (PCG, lookup table); for single
  points, n nodes at the per-node rate of a single-point Eval at n = 32 (two
  per level for a DCF), the half-tree rate from ht-aes sh-bin and the
  LPN-PRG rate from FssNN (our GGM keys evaluate the same PRG per node); for
  the PCF, 0.62·10⁶ nodes per triple (HR25, Tab. 2). PCG rows use the
  arithmetic variants at ℓ = 64, all others the Boolean ones; Half-Tree is
  Boolean only. "--": Half-Tree for a single key above its measured n = 29
  (Grotto, SIGMA-cDPF, threshold decryption), or where its Gen exceeds a year.

Reads results-gen/, results-eval/, results-single-point/ and
results-template/{gen,full}/ (GGM instance: Gen at ν = 2, full Eval at ν = 5).
"""
import csv
import sys

sys.path.insert(0, __import__('os').path.dirname(__file__))
from paper_data import gen_cost, net, WAN, COT_BITS, COT_NS  # noqa: E402

GGM_GEN, GGM_FULL = 'results-template/gen/ggm-lpn-{}-nu2.csv', 'results-template/full/ggm-lpn-{}-nu5.csv'
COMM_ROWS = [  # (block, label, CSV name, Gen CSV, full Eval CSV)
    ('Boolean payload, semi-honest', 'Floram', 'floram'),
    (None, 'Half-Tree', 'ht'),
    (None, 'FssNN', 'fssnn-bin'),
    (None, 'Ours, PiGenSH', 'ht-aes-sh-bin'),
    (None, 'Ours, PiGenGGM', 'ggm-lpn-bin-nu2'),
    ('Boolean payload, malicious', 'Zhang et al.', 'ht-mal-ferret'),
    (None, 'Ours, PiGenMal', 'ht-aes-mal'),
    ('Arithmetic payload, semi-honest', 'Xing et al.', 'floram-arith'),
    (None, 'Duoram-2P', 'duoram-2p'),
    (None, 'FssNN', 'fssnn-arith'),
    (None, 'Ours, PiGenSH', 'ht-aes-sh'),
    (None, 'Ours, PiGenGGM', 'ggm-lpn-arith-nu2'),
    ('Arithmetic payload, malicious', 'Ours, PiGenMal', 'ht-aes-mal-arith'),
]


def paths(name):
    if name.startswith('ggm-lpn'):
        v = name.split('-')[2]
        return GGM_GEN.format(v), GGM_FULL.format(v)
    return f'results-gen/{name}.csv', f'results-eval/{name}.csv'


def rows(path, mode, m=64):
    """{n: [rows]} of one mode at out-bits m (measured and `+est`)."""
    out = {}
    with open(path) as f:
        for r in csv.reader(l for l in f if not l.startswith('#')):
            if r and r[0] == mode and int(r[4]) == m:
                out.setdefault(int(float(r[3])), []).append(r)
    return out


def mean(xs):
    return sum(xs) / len(xs)


# ---------------------------------------------------------------- Tab. eval-comm-rounds

def comm_table():
    print('Tab. eval-comm-rounds: Gen of one key pair (without setup and pool COTs), full Eval at n = 32; ℓ = 64')
    print(f'  {"protocol":18s} {"KB n=20":>9s} {"KB n=32":>9s} {"rnd 20":>7s} {"rnd 32":>7s} {"ns/pt":>8s}')
    for block, label, name in COMM_ROWS:
        if block:
            print(f'  {block}')
        g, e = paths(name)
        G, E = rows(g, 'gen'), rows(e, 'full')
        cells = []
        for n in (20, 32):
            cells.append(f'{mean([gen_cost(name, r)[3] for r in G[n]]) / 1e3:9.1f}')
        for n in (20, 32):
            cells.append(f'{mean([float(r[23]) + float(r[26]) for r in G[n]]):7.0f}')
        ns = mean([float(r[12]) for r in E[32]]) * 1e6 / 2 ** 32
        est = '*' if E[32][0][1].endswith('+est') else ' '
        print(f'    {label:16s} {cells[0]} {cells[1]} {cells[2]} {cells[3]} {ns:7.1f}{est}')
    print('  *: extrapolated at the last measured time per point')


# ---------------------------------------------------------------- Tab. eval-apps

def ferret_charged(name, r):
    """[comp ms, bytes, rounds] of one Gen row as the applications charge it."""
    c = gen_cost(name, r, charge_cots=True)
    nbytes = c[3]
    if name == 'ht':  # IKNP: κ = 128 bits per OT in a batch of keys
        nbytes = float(r[24]) + 16 * float(r[28])
    return [c[0], nbytes, float(r[23]) + float(r[26])]


def per_key(name):
    """{n: [comp ms, bytes, rounds]} at ℓ = 64, measured and estimated rows."""
    g = rows(paths(name)[0], 'gen')
    return {n: [mean(x) for x in zip(*(ferret_charged(name, r) for r in rs))] for n, rs in g.items()}


def at(d, n):
    """Linear in n between integer rows, and above the last row with its slope."""
    top = max(d)
    lo = min(int(n), top - 1)
    return [d[lo][i] + (n - lo) * (d[lo + 1][i] - d[lo][i]) for i in range(3)]


def dcf(d, n, nu, joint):
    """Our DCF key: the DPF key with each of its `joint` levels counted twice, two more rounds."""
    c, top = at(d, n), max(d)
    s = [d[top][i] - d[top - 1][i] for i in range(2)]
    return [c[0] + joint * s[0], c[1] + joint * s[1], c[2] + 2]


def batch(keys):
    """[(count, [comp ms, bytes, rounds])] -> (bytes, WAN seconds), batched into the same rounds."""
    comp = sum(k * v[0] for k, v in keys)
    nbytes = sum(k * v[1] for k, v in keys)
    rounds = max(v[2] for _, v in keys)
    return nbytes, (comp + net(rounds, nbytes, WAN)) / 1e3


def node_rate(name):
    """ns per node: single-point Eval at n = 32 over its 32 levels."""
    e = rows(f'results-single-point/{name}.csv', 'eval')
    return mean([float(r[18]) for r in e[32]]) / 32


def full_ms(name, n):
    return mean([float(r[12]) for r in rows(paths(name)[1], 'full')[n]])


def fb(x):
    for u, s in [(1e12, 'TB'), (1e9, 'GB'), (1e6, 'MB'), (1e3, 'KB')]:
        if x >= u:
            return f'{x / u:.3g} {s}'
    return f'{x:.3g} B'


def ft(sec):
    for u, s in [(365 * 86400, 'yr'), (100 * 86400, 'days'), (3600, 'h'), (60, 'min'), (1, 's'), (1e-3, 'ms')]:
        if sec >= u:
            return f'{sec / u:.3g} {s}'
    return f'{sec * 1e6:.3g} µs'


def apps_table():
    HT, FS, OS, GG = 'Half-Tree', 'FssNN', 'PiGenSH', 'PiGenGGM'
    bin_ = {HT: 'ht', FS: 'fssnn-bin', OS: 'ht-aes-sh-bin', GG: 'ggm-lpn-bin-nu2'}
    ari = {HT: 'ht', FS: 'fssnn-arith', OS: 'ht-aes-sh', GG: 'ggm-lpn-arith-nu2'}
    K = {p: per_key(p) for p in {*bin_.values(), *ari.values()}}
    nu = {OS: 17, GG: 2}
    joint = {OS: lambda n: n - nu[OS] + 1, GG: lambda n: n - nu[GG]}
    aes, lpn = node_rate('ht-aes-sh-bin'), node_rate('fssnn-bin')
    rate = {HT: aes, OS: aes, FS: lpn, GG: lpn}
    print(f'Tab. eval-apps (semi-honest; per node {aes:.1f} ns with AES-MMO, {lpn:.0f} ns with the LPN-PRG;'
          f' COTs at {COT_BITS} bits and {COT_NS} ns)')
    res = {}

    def row(app, gen, ev):
        """gen: {proto: [(count, cost)] or None}, ev: {proto: seconds or None}"""
        print(f'  {app}')
        res[app] = {}
        for p in (HT, FS, OS, GG):
            g = gen.get(p)
            if g is None:
                print(f'    {p:9s} {"--":>10s} {"--":>10s} {"--":>10s}')
                continue
            b, t = batch(g)
            e = ev.get(p)
            infeasible = t > 365 * 86400
            res[app][p] = (b, t, e)
            print(f'    {p:9s} {"--" if infeasible else fb(b):>10s} {ft(t):>10s} '
                  f'{"--" if infeasible or e is None else ft(e):>10s}')

    print(f'    {"":9s} {"Comm.":>10s} {"Gen, WAN":>10s} {"Eval":>10s}')
    # Ring-LPN PCG (BCGIKS20), (c, w) = (4, 64): 4,096 DPF keys on 22 bits, each expanded in full
    row('PCG, (c,w) = (4,64): 4,096 DPF keys, n = 22',
        {p: [(4096, at(K[ari[p]], 22))] for p in ari},
        {p: 4096 * full_ms(ari[p], 22) / 1e3 for p in ari})
    # Beaver-triple PCF (HR25, L = 3): 8 cross terms of t² = 2^20 pair DPFs each, on these domains
    doms = [19.6, 24.2, 24.2, 28.8, 29.3, 29.3, 33.9, 33.9]
    row('PCF, L = 3: 8.4 M DPF keys, n = 19.6..33.9',
        {p: [(2 ** 20, at(K[bin_[p]], n)) for n in doms] for p in bin_},
        {p: 0.62e6 * rate[p] / 1e9 for p in (FS, OS, GG)})
    for app, n in [('Grotto-spline: 1 DPF key, n = 64', 64),
                   ('SIGMA-cDPF: 1 DPF key, n = 36', 36), ('SIGMA-cDPF: 1 DPF key, n = 50', 50)]:
        row(app, {p: [(1, at(K[bin_[p]], n))] for p in (FS, OS, GG)},
            {p: n * rate[p] / 1e9 for p in (FS, OS, GG)})
    row('SIGMA-LUT: 1 DPF key, n = 13 (expanded once)',
        {p: [(1, at(K[bin_[p]], 13))] for p in bin_},
        {p: full_ms(bin_[p], 13) / 1e3 for p in bin_})
    n = 63
    row('Thrs. Dec.: 1 DCF key, n = 63',
        {FS: [(1, at(K[bin_[FS]], n))], **{p: [(1, dcf(K[bin_[p]], n, nu[p], joint[p](n)))] for p in (OS, GG)}},
        {FS: n * rate[FS] / 1e9, **{p: 2 * n * rate[p] / 1e9 for p in (OS, GG)}})

    # The prose of §6b: where the half-tree instance repays its slower Gen against the GGM instance
    def repay(app):
        (_, to, eo), (_, tg, eg) = res[app][OS], res[app][GG]
        return (to - tg) / (eg - eo)
    print('  Half-tree instance repays its slower Gen against the GGM instance after')
    print(f'    PCF: {repay("PCF, L = 3: 8.4 M DPF keys, n = 19.6..33.9"):.3g} triples')
    for app in res:
        if app.startswith(('Grotto', 'SIGMA-cDPF')):
            print(f'    {app}: {repay(app):.3g} evaluations')


def main():
    what = sys.argv[1] if len(sys.argv) > 1 else 'all'
    if what in ('comm', 'all'):
        comm_table()
    if what in ('apps', 'all'):
        if what == 'all':
            print()
        apps_table()


if __name__ == '__main__':
    try:
        main()
    except FileNotFoundError as e:
        sys.exit(f'paper_tables.py: {e.filename} missing; run the sweeps of README §2, step 1, first')
