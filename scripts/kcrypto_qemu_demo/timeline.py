#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Static evidence timeline from sealed receipts (attempt 4, Task 5).

Reads one campaign run directory (per-cell subdirs with sealed
``cell-*.json`` receipts, ledgers, and ``console.log``) and writes
a static SVG. Every visual edge carries exactly one label from
``observed``/``reference``/``inferred``/``unknown`` plus its run
ID — validated by :func:`reconcile.timeline_edges` before the SVG
is written, so an unproved arrow refuses instead of rendering.

Honesty rules (pinned by tests):

- Guest timestamps are per-boot monotonic clocks. Cross-cell
  alignment would be fabrication: each row keeps its own span
  and the SVG states that spans are not comparable.
- ``inferred`` is never emitted: this renderer only draws what
  sealed evidence directly shows (``observed``), what the pinned
  product report corroborates (``reference``), or ``unknown``.
- A cell whose receipts are missing or unreadable renders as an
  explicit ``unknown`` row, never a gap.

Version 2 (``--v2``, repair-1) renders verdict-aware rows from the
run-log verdicts (offline re-judgment fallback), labels every edge
with its evidence layer (guest-probe / caller-ledger /
product-report / none), and marks unsealed-history rows. V1 stays
the default and is byte-stable (the sealed p10a4 SVG reproduces).
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from kcrypto_qemu_demo import reconcile  # noqa: E402

STAGES = ["requested", "selected", "entered", "queued", "returned",
          "completed", "reported"]


def _load_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _mark_span(console_text: str) -> tuple[float | None, float | None]:
    first: float | None = None
    last: float | None = None
    for line in console_text.splitlines():
        line = line.strip()
        if not line.startswith("DEMO:MARK "):
            continue
        try:
            row = json.loads(line[len("DEMO:MARK "):])
        except json.JSONDecodeError:
            continue
        ts = row.get("ts_mono")
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            continue
        if first is None or ts < first:
            first = ts
        if last is None or ts > last:
            last = ts
    return first, last


RUN_LOG_VERDICTS = frozenset({"PASS", "FAIL", "UNSUPPORTED", "NOT_RUN"})


def _log_verdict(path: Path) -> str | None:
    """Adjudicated verdict from one run-log file (None when absent)."""
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return None
    if not lines:
        return None
    try:
        obj = json.loads(lines[0])
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    verdict = obj.get("verdict")
    return verdict if verdict in RUN_LOG_VERDICTS else None


def run_log_verdict(run_dir: Path, row_name: str,
                    cell_id: str) -> str | None:
    """Adjudicated verdict for one row from its run log.

    Candidates: ``<row>.log``, ``<row>-run.log``, then the
    sorted-first ``*.log`` whose first-line JSON names this cell.
    Seal-refusal text (unsealed history) yields None: the caller
    falls back to offline re-judgment.
    """
    run_dir = Path(run_dir)
    direct = [run_dir / f"{row_name}.log",
              run_dir / f"{row_name}-run.log"]
    for path in direct:
        verdict = _log_verdict(path)
        if verdict is not None:
            return verdict
        if path.is_file():
            return None
    for path in sorted(run_dir.glob("*.log")):
        if path in direct:
            continue
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        if not lines:
            continue
        try:
            obj = json.loads(lines[0])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("cell") == cell_id:
            verdict = obj.get("verdict")
            if verdict in RUN_LOG_VERDICTS:
                return verdict
    return None


def cell_edges(cell_id: str, run_id: str, cell_dir: Path,
               v2: bool = False, log_verdict: str | None = None,
               sealed: bool = True) -> tuple[list[dict], dict]:
    """Edges + row facts for one sealed cell directory."""
    receipts = sorted(cell_dir.glob("cell-*.json"))
    receipt = _load_json(receipts[0]) if receipts else None
    try:
        console_text = (cell_dir / "console.log").read_text(
            errors="replace")
    except OSError:
        console_text = ""
    first, last = _mark_span(console_text)
    if receipt is None:
        edge = {"frm": "requested", "to": "completed", "label": "unknown",
                "run_id": run_id, "cell": cell_id,
                "note": "receipt missing or unreadable"}
        if v2:
            edge["layer"] = "none"
        return [edge], {"verdict": "UNKNOWN", "span": (first, last),
                        "sealed": sealed}
    verdict = receipt.get("verdict", "UNKNOWN")
    if verdict in ("NOT_RUN", "UNSUPPORTED"):
        edge = {"frm": "requested", "to": "completed", "label": "unknown",
                "run_id": run_id, "cell": cell_id,
                "note": receipt.get("reason", verdict)}
        if v2:
            edge["layer"] = "none"
        return [edge], {"verdict": verdict, "span": (first, last),
                        "sealed": sealed}
    checks = receipt.get("checks", {})
    if v2:
        pairs: dict[tuple[str, str], tuple[str, str]] = {}
        if receipt.get("selected_driver"):
            pairs[("requested", "selected")] = ("observed", "guest-probe")
        else:
            pairs[("requested", "selected")] = ("unknown", "none")
        ledger_ok = bool(checks.get("all_status_ok",
                                    checks.get("io_status_ok")))
        # Caller-ledger success proves neither provider-body entry
        # nor product completion: unproved edges stay unknown.
        pairs[("selected", "entered")] = ("unknown", "none")
        pairs[("entered", "queued")] = ("unknown", "none")
        pairs[("queued", "returned")] = ("unknown", "none")
        if ledger_ok:
            pairs[("returned", "completed")] = ("observed",
                                               "caller-ledger")
        else:
            pairs[("returned", "completed")] = ("unknown", "none")
        if checks.get("kryprobe_present"):
            pairs[("completed", "reported")] = ("reference",
                                               "product-report")
        else:
            pairs[("completed", "reported")] = ("unknown", "none")
        edges = [
            {"frm": frm, "to": to, "label": label, "layer": layer,
             "run_id": run_id, "cell": cell_id}
            for (frm, to), (label, layer) in pairs.items()
        ]
        row_verdict = (log_verdict
                       or reconcile.reconcile_cell(receipt)["verdict"])
        return edges, {"verdict": row_verdict, "span": (first, last),
                       "sealed": sealed}
    labels: dict[tuple[str, str], str] = {}
    if receipt.get("selected_driver"):
        labels[("requested", "selected")] = "observed"
    else:
        labels[("requested", "selected")] = "unknown"
    ledger_ok = bool(checks.get("all_status_ok", checks.get("io_status_ok")))
    labels[("selected", "entered")] = "observed" if ledger_ok else "unknown"
    labels[("entered", "queued")] = "unknown"
    labels[("queued", "returned")] = "unknown"
    labels[("returned", "completed")] = "observed" if ledger_ok else "unknown"
    if checks.get("kryprobe_present"):
        labels[("completed", "reported")] = "reference"
    else:
        labels[("completed", "reported")] = "unknown"
    edges = [
        {"frm": frm, "to": to, "label": label, "run_id": run_id,
         "cell": cell_id}
        for (frm, to), label in labels.items()
    ]
    return edges, {"verdict": verdict, "span": (first, last),
                   "sealed": sealed}


def collect_run(run_dir: Path, v2: bool = False) -> tuple[list[dict], dict[str, dict]]:
    """All edges + per-cell rows for a campaign run directory."""
    run_dir = Path(run_dir)
    edges: list[dict] = []
    rows: dict[str, dict] = {}
    for child in sorted(run_dir.iterdir()):
        if not child.is_dir():
            continue
        if (child / "probe.json").exists():
            continue  # qualification probe, not a campaign cell
        receipts = sorted(child.glob("cell-*.json"))
        if not receipts and not (child / "console.log").exists():
            continue
        receipt = _load_json(receipts[0]) if receipts else None
        cell_id = (receipt or {}).get("cell_id", child.name)
        run_id = (receipt or {}).get("run_id", child.name)
        log_verdict = (run_log_verdict(run_dir, child.name, cell_id)
                       if v2 else None)
        sealed = (child / "SHA256SUMS").is_file()
        cell_edges_list, facts = cell_edges(
            cell_id, run_id, child, v2=v2, log_verdict=log_verdict,
            sealed=sealed)
        facts["cell"] = cell_id
        for edge in cell_edges_list:
            edge["row"] = child.name
        edges.extend(cell_edges_list)
        rows[child.name] = facts
    judged = reconcile.timeline_edges(edges)
    if not judged["ok"]:
        raise ValueError(f"timeline refuses unproved arrows: {judged}")
    return edges, rows


COLORS = {
    "observed": "#1a7f37",
    "reference": "#0969da",
    "inferred": "#9a6700",
    "unknown": "#6e7781",
}

VERDICT_COLORS = {
    "RUN": "#6e7781",
    "PASS": "#1a7f37",
    "FAIL": "#cf222e",
    "UNSUPPORTED": "#9a6700",
    "NOT_RUN": "#6e7781",
    "UNKNOWN": "#6e7781",
}


def render_svg(run_id: str, edges: list[dict], rows: dict[str, dict],
               v2: bool = False) -> str:
    """Render the collected edges + rows as a static SVG string."""
    row_h, top, left = 46, 90, 150
    width = 1000
    height = top + (len(rows) + 1) * row_h + 60
    if v2:
        parts: list[str] = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}"'
            f' height="{height}" role="img">',
            f"<title>kcrypto demo timeline {html.escape(run_id)}"
            " (v2 verdict-aware replay)</title>",
            f'<text x="20" y="30">kcrypto demo timeline'
            f" {html.escape(run_id)} — v2 verdict-aware replay</text>",
            '<text x="20" y="52">spans are per-boot guest clocks;'
            " cross-cell alignment is schematic, not measured</text>",
            '<text x="20" y="74">rows: run-log verdicts; edges:'
            " label + evidence layer; unsealed-history marked;"
            " run ID on every edge</text>",
        ]
    else:
        parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}"'
            f' height="{height}" role="img">',
            f"<title>kcrypto demo timeline {html.escape(run_id)}"
            " (replay of sealed receipts)</title>",
            f'<text x="20" y="30">kcrypto demo timeline'
            f" {html.escape(run_id)} — replay of sealed receipts</text>",
            '<text x="20" y="52">spans are per-boot guest clocks;'
            " cross-cell alignment is schematic, not measured</text>",
            '<text x="20" y="74">edge labels: observed (green) /'
            " reference (blue) / unknown (grey);"
            " run ID on every edge</text>",
        ]
    for index, row_name in enumerate(sorted(rows)):
        facts = rows[row_name]
        cell_id = facts.get("cell", row_name)
        y = top + index * row_h
        verdict = facts.get("verdict", "UNKNOWN")
        color = VERDICT_COLORS.get(verdict, "#6e7781")
        span = facts.get("span", (None, None))
        span_text = (
            f"{span[0]:.1f}–{span[1]:.1f}s guest"
            if span[0] is not None and span[1] is not None
            else "span unknown"
        )
        row_label = f"{row_name} [{verdict}]"
        if v2 and not facts.get("sealed", True):
            row_label += "·unsealed-history"
        parts.append(
            f'<text x="20" y="{y + 18}">{html.escape(row_label)}</text>'
        )
        parts.append(
            f'<text x="20" y="{y + 34}" font-size="11">{span_text}</text>'
        )
        cell_edges = [edge for edge in edges if edge["row"] == row_name]
        x = left
        step = (width - left - 20) // max(len(cell_edges), 1)
        for edge in cell_edges:
            x2 = x + step - 8
            edge_color = COLORS[edge["label"]]
            title = (f"{edge['frm']}→{edge['to']} [{edge['label']}]"
                     f" run {edge['run_id']}")
            if v2 and edge.get("layer"):
                title += f" layer {edge['layer']}"
            if edge.get("note"):
                title += f": {edge['note']}"
            parts.append(
                f'<line x1="{x}" y1="{y + 20}" x2="{x2}" y2="{y + 20}"'
                f' stroke="{edge_color}" stroke-width="3">'
                f"<title>{html.escape(title)}</title></line>"
            )
            edge_text = (f"{edge['frm']}→{edge['to']}"
                         f" ({edge['label']})")
            if v2 and edge.get("layer"):
                edge_text = (f"{edge['frm']}→{edge['to']}"
                             f" ({edge['label']}, {edge['layer']})")
            parts.append(
                f'<text x="{x}" y="{y + 12}" font-size="10">'
                f"{html.escape(edge_text)}</text>"
            )
            x = x2 + 8
        parts.append(
            f'<circle cx="{left - 12}" cy="{y + 20}" r="6" fill="{color}">'
            f"<title>{html.escape(cell_id)}: {html.escape(str(verdict))}"
            "</title></circle>"
        )
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="render evidence timeline")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--v2", action="store_true",
                        help="verdict-aware rows + evidence layers"
                        " (v1 stays the byte-stable default)")
    args = parser.parse_args(argv)
    run_dir = Path(args.run_dir)
    edges, rows = collect_run(run_dir, v2=args.v2)
    svg = render_svg(run_dir.name, edges, rows, v2=args.v2)
    Path(args.out).write_text(svg)
    print(f"edges {len(edges)} cells {len(rows)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
