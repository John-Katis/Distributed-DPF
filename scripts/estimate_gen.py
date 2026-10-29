#!/usr/bin/env python3
"""Appends estimated Gen rows to a bench CSV, from its last measured input
width n0 up to a given width, one row per (in_bits, out_bits).

    scripts/estimate_gen.py results-gen/NAME.csv MAX_IN_BITS

The estimate continues the last two measured widths n0 - 1 and n0 (the mean
of their rows, per output width), with k = n - n0:

  * computation (comp_ms, gen_ms_p0, gen_ms_p1): c(n0)·2^k, since a tree-based
    Gen makes Theta(2^n) PRG calls;
  * setup (setup_ms, setup_bytes): as at n0, since it does not depend on n;
  * everything else that is counted (bytes, rounds, network times, COTs, key
    bytes, ...): linear in n, x(n0) + k·(x(n0) - x(n0 - 1)), as rounds and
    bytes are (at least 0, against the noise of times near 0);
  * totals: computation plus network time, for the LAN and the WAN.

Estimated rows have the variant suffix `+est` and reps 0. Rows from an earlier
run of this script are replaced, so it can run again after more points were
measured.
"""
import sys
from collections import defaultdict

DOUBLING = {"comp_ms", "gen_ms_p0", "gen_ms_p1"}
CONSTANT = {"bm", "setup_ms", "setup_bytes"}
INTS = {"bm", "comm_p0", "comm_p1", "comm_p2", "comm_total", "rounds", "setup_bytes", "pre_bytes",
        "pre_rounds", "gen_bytes", "gen_bytes_per_level", "gen_rounds", "and_gates", "cots", "key_bytes"}


def main(path, max_in):
    lines = open(path).read().splitlines()
    header = next((l for l in lines if l.startswith("# gen: ")), None)
    if header is None:
        sys.exit(f"{path}: no '# gen:' header")
    cols = header[len("# gen: "):].split(",")
    keep = [l for l in lines if not l.startswith("# estimated:") and not (l.startswith("gen,") and l.split(",")[1].endswith("+est"))]
    rows = defaultdict(list)
    for l in keep:
        if l.startswith("gen,"):
            r = dict(zip(cols, l.split(",")))
            rows[(int(float(r["in_bits"])), int(r["out_bits"]))].append(r)
    out = []
    for m in sorted({m for _, m in rows}):
        widths = sorted(n for n, mm in rows if mm == m)
        n0 = widths[-1]
        if n0 >= max_in or n0 - 1 not in widths:
            continue
        mean = lambda n, c: sum(float(r[c]) for r in rows[(n, m)]) / len(rows[(n, m)])
        variant = rows[(n0, m)][0]["variant"]
        for n in range(n0 + 1, max_in + 1):
            k = n - n0
            e = {}
            for c in cols[5:]:
                x0, x1 = mean(n0 - 1, c), mean(n0, c)
                e[c] = x1 * 2 ** k if c in DOUBLING else x1 if c in CONSTANT else max(0.0, x1 + k * (x1 - x0))
            e["reps"] = 0
            e["gen_bytes_per_level"] = e["gen_bytes"] / n
            e["lan_total_ms"] = e["comp_ms"] + e["lan_net_ms"]
            e["wan_total_ms"] = e["comp_ms"] + e["wan_net_ms"]
            fmt = lambda c: str(round(e[c])) if c in INTS or c == "reps" else f"{e[c]:.6f}" if c.endswith("_ms") and c[:3] in ("com", "lan", "wan") else f"{e[c]:.3f}"
            out.append(",".join(["gen", variant + "+est", str(2 ** n), f"{n:.2f}", str(m)] + [fmt(c) for c in cols[5:]]))
        out.insert(len(out) - (max_in - n0), f"# estimated: in_bits={n0 + 1}..={max_in} out_bits={m} from in_bits={n0 - 1},{n0} (computation x2 per bit, setup constant, the rest linear)")
    open(path, "w").write("\n".join(keep + out) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], int(sys.argv[2]))
