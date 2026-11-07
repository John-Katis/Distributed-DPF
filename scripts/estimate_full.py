#!/usr/bin/env python3
"""Appends estimated full-domain rows to a bench CSV, from its last measured
input width n0 up to a given width, one row per (in_bits, out_bits).

    scripts/estimate_full.py results-eval/NAME.csv MAX_IN_BITS

Like scripts/estimate_gen.py for Gen: a full-domain evaluation expands all
2^n - 1 nodes of the tree, so its time doubles per input bit. With k = n - n0,
from the mean of the measured rows at n0 (per output width):

  * time (comp_ms, lan_total_ms, wan_total_ms): t(n0)·2^k;
  * ns_per_point: as at n0, which is the same estimate per point;
  * communication, rounds, network time: 0, as measured (evaluation is local).

Estimated rows have the variant suffix `+est` (after the variant of the row at
n0, without a `+stream` suffix) and reps 0. Rows from an earlier
run of this script are replaced, so it can run again after more points were
measured. Only `full,` rows are read and estimated; every other line (the
`eval,` rows, headers) is kept as it is.
"""
import sys
from collections import defaultdict

DOUBLING = {"comp_ms", "lan_total_ms", "wan_total_ms"}
INTS = {"bm", "comm_p0", "comm_p1", "comm_p2", "comm_total", "rounds"}


def main(path, max_in):
    lines = open(path).read().splitlines()
    header = next((l for l in lines if l.startswith("# full: ")), None)
    if header is None:
        sys.exit(f"{path}: no '# full:' header")
    cols = header[len("# full: "):].split(",")
    keep = [l for l in lines if not l.startswith("# estimated full:") and not (l.startswith("full,") and l.split(",")[1].endswith("+est"))]
    rows = defaultdict(list)
    for l in keep:
        if l.startswith("full,"):
            r = dict(zip(cols, l.split(",")))
            rows[(int(float(r["in_bits"])), int(r["out_bits"]))].append(r)
    out = []
    for m in sorted({m for _, m in rows}):
        n0 = max(n for n, mm in rows if mm == m)
        if n0 >= max_in:
            continue
        mean = lambda c: sum(float(r[c]) for r in rows[(n0, m)]) / len(rows[(n0, m)])
        variant = rows[(n0, m)][0]["variant"].removesuffix("+stream")
        out.append(f"# estimated full: in_bits={n0 + 1}..={max_in} out_bits={m} from in_bits={n0} (time x2 per bit, ns_per_point constant)")
        for n in range(n0 + 1, max_in + 1):
            e = {c: mean(c) * 2 ** (n - n0) if c in DOUBLING else mean(c) for c in cols[5:]}
            e["reps"] = 0
            fmt = lambda c: str(round(e[c])) if c in INTS or c == "reps" else f"{e[c]:.6f}" if c.endswith("_ms") else f"{e[c]:.2f}"
            out.append(",".join(["full", variant + "+est", str(2 ** n), f"{n:.2f}", str(m)] + [fmt(c) for c in cols[5:]]))
    open(path, "w").write("\n".join(keep + out) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], int(sys.argv[2]))
