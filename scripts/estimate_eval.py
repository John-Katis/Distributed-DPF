#!/usr/bin/env python3
"""Appends estimated single-point evaluation rows to a bench CSV, from its last
measured input width n0 up to a given width, one row per (in_bits, out_bits).

    scripts/estimate_eval.py results-single-point/NAME.csv MAX_IN_BITS

Like scripts/estimate_full.py for full-domain evaluation: evaluating a key at
one point walks the n levels of its tree, one PRG call per level, so its time
grows linearly in n. From the mean of the measured rows at n0 (per output
width):

  * time (comp_ms, lan_total_ms, wan_total_ms, ns_per_eval): t(n0)·n/n0;
  * points: as at n0;
  * communication, rounds, network time: 0, as measured (evaluation is local).

Estimated rows have the variant suffix `+est` and reps 0. Rows from an earlier
run of this script are replaced, so it can run again after more points were
measured. Only `eval,` rows are read and estimated; every other line is kept as
it is.
"""
import sys
from collections import defaultdict

LINEAR = {"comp_ms", "lan_total_ms", "wan_total_ms", "ns_per_eval"}
INTS = {"bm", "comm_p0", "comm_p1", "comm_p2", "comm_total", "rounds", "points"}


def main(path, max_in):
    lines = open(path).read().splitlines()
    header = next((l for l in lines if l.startswith("# eval: ")), None)
    if header is None:
        sys.exit(f"{path}: no '# eval:' header")
    cols = header[len("# eval: "):].split(",")
    keep = [l for l in lines if not l.startswith("# estimated eval:") and not (l.startswith("eval,") and l.split(",")[1].endswith("+est"))]
    rows = defaultdict(list)
    for l in keep:
        if l.startswith("eval,"):
            r = dict(zip(cols, l.split(",")))
            rows[(int(float(r["in_bits"])), int(r["out_bits"]))].append(r)
    out = []
    for m in sorted({m for _, m in rows}):
        n0 = max(n for n, mm in rows if mm == m)
        if n0 >= max_in:
            continue
        mean = lambda c: sum(float(r[c]) for r in rows[(n0, m)]) / len(rows[(n0, m)])
        variant = rows[(n0, m)][0]["variant"].removesuffix("+stream")
        out.append(f"# estimated eval: in_bits={n0 + 1}..={max_in} out_bits={m} from in_bits={n0} (time linear in n)")
        for n in range(n0 + 1, max_in + 1):
            e = {c: mean(c) * n / n0 if c in LINEAR else mean(c) for c in cols[5:]}
            e["reps"] = 0
            fmt = lambda c: str(round(e[c])) if c in INTS or c == "reps" else f"{e[c]:.6f}" if c.endswith("_ms") else f"{e[c]:.1f}"
            out.append(",".join(["eval", variant + "+est", str(2 ** n), f"{n:.2f}", str(m)] + [fmt(c) for c in cols[5:]]))
    open(path, "w").write("\n".join(keep + out) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], int(sys.argv[2]))
