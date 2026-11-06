#!/usr/bin/env python3
"""Regenerates the pgfplots tables of paper-eval/8-dpf-data.tex from the
CSVs in results-gen/ and results-eval/.

    python3 -I scripts/paper_data.py [paper-eval/8-dpf-data.tex]

Rewrites every \\pgfplotstableread{...}\\T<name> block in place and leaves the
rest of the file (macros, colours, styles) as it is. Several rows for the same
(in_bits, out_bits) (the 1-rep processes from --reps-from on) are averaged.
Gen tables: n, comp, total LAN, total WAN (s), comm incl. setup (KB);
measured rows go into \\T<p>A/B, the last measured row plus the `+est` rows
into \\T<p>XA/XB. Full-domain Eval tables: n, comp, LAN, WAN (s); measured
rows into \\T<p>EA/EB, the last measured row plus `+est` rows into
\\T<p>XEA/XEB. \\TOenv* is the maximum over our four variants.
"""
import csv
import re
import sys
from collections import defaultdict

PROTOS = {  # table prefix -> CSV name
    'Fl': 'floram', 'HT': 'ht', 'HTm': 'ht-mal-ferret', 'FA': 'floram-arith',
    'Fb': 'fssnn-bin', 'Fa': 'fssnn-arith', 'Dtwo': 'duoram-2p', 'Dthree': 'duoram-3p',
}
OURS = ['ht-aes-sh-bin', 'ht-aes-sh', 'ht-aes-mal', 'ht-aes-mal-arith']
WIDTH = {64: 'A', 128: 'B'}


def load(path, mode):
    """{(est, out_bits): {n: [c, l, w, b]}} in s and KB, rows averaged."""
    acc = defaultdict(lambda: defaultdict(list))
    with open(path) as f:
        for row in csv.reader(l for l in f if not l.startswith('#')):
            if not row or row[0] != mode:
                continue
            n, m = int(float(row[3])), int(row[4])
            est = row[1].endswith('+est')
            acc[(est, m)][n].append([float(row[12]) / 1e3,
                                     float(row[14]) / 1e3, float(row[16]) / 1e3,
                                     float(row[10]) / 1e3])
    return {k: {n: [sum(c) / len(c) for c in zip(*v)] for n, v in d.items()}
            for k, d in acc.items()}


def fmt(x):
    return f'{x:.4g}'


def table(rows, cols):
    lines = ['\\pgfplotstableread{n ' + ' '.join(cols)]
    for n in sorted(rows):
        lines.append(' '.join([str(n)] + [fmt(v) for v in rows[n][:len(cols)]]))
    return '\n'.join(lines) + '\n}'


def main():
    tex = sys.argv[1] if len(sys.argv) > 1 else 'paper-eval/8-dpf-data.tex'
    tables = {}
    for mode, d, cols, tag in [('gen', 'results-gen', 'clwb', ''),
                               ('full', 'results-eval', 'clw', 'E')]:
        for p, name in PROTOS.items():
            data = load(f'{d}/{name}.csv', mode)
            for m, w in WIDTH.items():
                meas = data.get((False, m), {})
                tables[f'T{p}{tag}{w}'] = table(meas, cols)
                est = data.get((True, m), {})
                if est:
                    last = max(meas)
                    tables[f'T{p}X{tag}{w}'] = table({last: meas[last], **est}, cols)
        ours = [load(f'{d}/{name}.csv', mode) for name in OURS]
        for m, w in WIDTH.items():
            ns = set.intersection(*(set(o[(False, m)]) for o in ours))
            env = {n: [max(o[(False, m)][n][i] for o in ours) for i in range(4)] for n in ns}
            tables[f'TOenv{tag}{w}'] = table(env, cols)

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
