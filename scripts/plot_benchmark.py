#!/usr/bin/env python3
"""Draws the README's benchmark chart as a standalone SVG, from the median
table the benchmark produced (no plotting library needed).

Usage: plot_benchmark.py [--csv docs/results/m5_round3_medians.csv]
                         [--workers 9] [--before 1500000] [-o docs/benchmark.svg]

--before draws a reference line for the throughput ceiling measured before
the capture fix (rounds 1 and 2, ~1.5M packets/sec on the M5).
"""
import argparse
import csv

# Colors follow the chart palette: CPU and GPU take categorical slots 1 and
# 2, validated for color-vision deficiency in both light and dark mode.
STYLE = """
  .surface { fill: #fcfcfb; }
  .ink { fill: #0b0b0b; }
  .ink-2 { fill: #52514e; }
  .grid { stroke: #e4e3df; stroke-width: 1; }
  .axis { stroke: #b5b4ae; stroke-width: 1; }
  .ref { stroke: #52514e; stroke-width: 1.5; stroke-dasharray: 5 4; }
  .halo { stroke: #fcfcfb; stroke-width: 4; stroke-linejoin: round; paint-order: stroke; }
  .cpu { fill: #2a78d6; }
  .gpu { fill: #eb6834; }
  text { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }
  @media (prefers-color-scheme: dark) {
    .surface { fill: #1a1a19; }
    .ink { fill: #ffffff; }
    .ink-2 { fill: #c3c2b7; }
    .grid { stroke: #2e2e2c; }
    .axis { stroke: #5f5e5a; }
    .ref { stroke: #c3c2b7; }
    .halo { stroke: #1a1a19; }
    .cpu { fill: #3987e5; }
    .gpu { fill: #d95926; }
  }
"""


def bar(x, y, w, h, cls):
    """A bar with 4px rounded corners at the data end, square at the baseline."""
    r = min(4, w / 2, h)
    return (f'<path class="{cls}" d="M{x:.1f},{y + h:.1f} V{y + r:.1f} '
            f'Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f} H{x + w - r:.1f} '
            f'Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f} V{y + h:.1f} Z"/>')


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv", default="docs/results/m5_round3_medians.csv")
    parser.add_argument("--workers", default="9")
    parser.add_argument("--before", type=float, default=1_500_000)
    parser.add_argument("-o", "--output", default="docs/benchmark.svg")
    args = parser.parse_args()

    medians = {}
    with open(args.csv) as f:
        for row in csv.DictReader(f):
            if row["workers"] == args.workers:
                medians[(int(row["batch"]), row["mode"])] = float(row["pps_median"])
    batches = sorted({b for b, _ in medians})
    if not batches:
        raise SystemExit(f"no rows for {args.workers} workers in {args.csv}")

    width, height = 720, 400
    left, right, top, bottom = 64, 24, 92, 64
    plot_w, plot_h = width - left - right, height - top - bottom
    y_max = 5_000_000
    y = lambda v: top + plot_h * (1 - v / y_max)

    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
           f'width="{width}" height="{height}" role="img" '
           f'aria-labelledby="title desc">',
           f'<style>{STYLE}</style>',
           '<title id="title">NetSentinel throughput, CPU vs GPU entropy</title>',
           '<desc id="desc">Packets per second on an Apple M5 with '
           f'{args.workers} workers, by maximum batch size. '
           + "; ".join(f"batch {b}: CPU {medians[(b, 'cpu')] / 1e6:.2f}M, "
                       f"GPU {medians[(b, 'gpu')] / 1e6:.2f}M" for b in batches)
           + f'. Before the capture fix both modes were capped near '
             f'{args.before / 1e6:.1f}M.</desc>',
           f'<rect class="surface" width="{width}" height="{height}" rx="8"/>',
           f'<text class="ink" x="{left}" y="30" font-size="16" font-weight="600">'
           'Packets/sec, CPU vs GPU entropy</text>',
           f'<text class="ink-2" x="{left}" y="50" font-size="12">Apple M5, 500k-packet '
           f'capture, {args.workers} workers, median of 5 runs</text>']

    # Legend
    lx = left
    for cls, label in (("cpu", "CPU only"), ("gpu", "Entropy on GPU (-g)")):
        out.append(f'<rect class="{cls}" x="{lx}" y="64" width="12" height="12" rx="2"/>')
        out.append(f'<text class="ink" x="{lx + 18}" y="74" font-size="12">{label}</text>')
        lx += 18 + len(label) * 7 + 24

    # Grid and y axis labels
    for v in range(0, y_max + 1, 1_000_000):
        gy = y(v)
        out.append(f'<line class="{"axis" if v == 0 else "grid"}" x1="{left}" x2="{left + plot_w}" '
                   f'y1="{gy:.1f}" y2="{gy:.1f}"/>')
        out.append(f'<text class="ink-2" x="{left - 8}" y="{gy + 4:.1f}" font-size="11" '
                   f'text-anchor="end">{f"{v // 1_000_000}M" if v else "0"}</text>')

    # Bars: two per batch size, 2px apart
    group_w = plot_w / len(batches)
    bar_w = min(56, group_w * 0.3)
    gap = 2
    for i, b in enumerate(batches):
        cx = left + group_w * (i + 0.5)
        for j, mode in enumerate(("cpu", "gpu")):
            v = medians[(b, mode)]
            x = cx - bar_w - gap / 2 if j == 0 else cx + gap / 2
            out.append(bar(x, y(v), bar_w, y(0) - y(v), mode))
            out.append(f'<text class="ink" x="{x + bar_w / 2:.1f}" y="{y(v) - 6:.1f}" '
                       f'font-size="11" text-anchor="middle">{v / 1e6:.2f}M</text>')
        ratio = medians[(b, "gpu")] / medians[(b, "cpu")]
        out.append(f'<text class="ink" x="{cx:.1f}" y="{y(0) + 20:.1f}" font-size="12" '
                   f'text-anchor="middle">batch {b}</text>')
        out.append(f'<text class="ink-2" x="{cx:.1f}" y="{y(0) + 36:.1f}" font-size="11" '
                   f'text-anchor="middle">GPU {ratio:.2f}×</text>')

    # Reference line: the ceiling before the capture fix
    if args.before > 0:
        ry = y(args.before)
        out.append(f'<line class="ref" x1="{left}" x2="{left + plot_w}" y1="{ry:.1f}" y2="{ry:.1f}"/>')
        out.append(f'<text class="ink-2 halo" x="{left + plot_w}" y="{ry - 6:.1f}" font-size="11" '
                   f'text-anchor="end">before the capture fix: both capped near '
                   f'{args.before / 1e6:.1f}M</text>')

    out.append('</svg>')
    with open(args.output, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
