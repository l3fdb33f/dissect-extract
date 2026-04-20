from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, TextIO

from dissect_extract.engine import TimelineEvent, collect_events_from_path
from dissect_extract.keywords import KeywordFilter, load_keywords_from_file, merge_keywords, parse_keyword_list_arg


def _default_max_workers(num_targets: int) -> int:
    cpu = os.cpu_count() or 1
    return max(1, min(num_targets, cpu, 32))


def _dump_jsonl_filename(tpath: str) -> str:
    p = Path(tpath)
    name = p.name
    if not name or name in (".", ".."):
        name = str(p.resolve())
        for c in "/\\":
            name = name.replace(c, "_")
    for c in '<>:"/\\|?*':
        name = name.replace(c, "_")
    name = name.strip("._") or "target"
    if not name.lower().endswith(".jsonl"):
        name = f"{name}.jsonl"
    return name


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


def _events_as_dicts(events: list[TimelineEvent]) -> list[dict[str, Any]]:
    return [
        {
            "timestamp": e.timestamp,
            "category": e.category,
            "source_function": e.source_function,
            "description": e.description,
            "target": e.target_name,
            "record_type": e.record_type,
        }
        for e in events
    ]


def _write_json(events: list[TimelineEvent], fp: TextIO) -> None:
    json.dump(_events_as_dicts(events), fp, indent=2)
    fp.write("\n")


def _write_csv(events: list[TimelineEvent], fp: TextIO) -> None:
    w = csv.DictWriter(
        fp,
        fieldnames=["timestamp", "category", "source_function", "description", "target", "record_type"],
    )
    w.writeheader()
    for row in _events_as_dicts(events):
        w.writerow(row)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build labeled timelines from dissect.target using the Python API (cross-platform).",
    )
    parser.add_argument("targets", nargs="+", help="Paths to disk images, directories, or VM configs")
    parser.add_argument("-v", "--verbose", action="store_true")

    cat = parser.add_argument_group("categories (combinable)")
    cat.add_argument("--pe", "--persistence-execution", action="store_true", help="Persistence & execution")
    cat.add_argument("--lm", "--lateral-movement", action="store_true", help="Lateral movement")
    cat.add_argument("--da", "--data-access", action="store_true", help="Data access")
    cat.add_argument("--de", "--data-exfiltration", action="store_true", help="Data exfiltration")
    cat.add_argument("--ia", "--initial-access", action="store_true", help="Initial access (delivery, downloads, web logs)")

    sub = parser.add_argument_group("persistence scope by OS (optional; limits which bundle applies)")
    sub.add_argument(
        "--pel",
        "--persistence-execution-linux",
        action="store_true",
        help="Only use Linux persistence definitions (no effect unless target OS is Linux)",
    )
    sub.add_argument("--pew", "--persistence-execution-windows", action="store_true")
    sub.add_argument("--pem", "--persistence-execution-macos", action="store_true")
    sub.add_argument("--peu", "--persistence-execution-unix", action="store_true")

    parser.add_argument(
        "-f",
        "--format",
        choices=("json", "csv"),
        default="json",
        help="Output format",
    )
    parser.add_argument("-o", "--output", default="-", help="Output file (default: stdout)")
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=None,
        metavar="N",
        help="Max targets to process in parallel (default: min(CPU count, target count, 32); use 1 for sequential)",
    )
    parser.add_argument(
        "-d",
        "--dump",
        metavar="DIR",
        help="Write raw applicable plugin records as JSONL (one file per target under DIR; same filters as timeline)",
    )
    kw = parser.add_argument_group("keyword filter (optional; substring, case-insensitive)")
    kw.add_argument(
        "-kl",
        "--keyword-list",
        metavar="KWS",
        help="Comma-separated keywords to match in record fields, category, source function, and description",
    )
    kw.add_argument(
        "-kf",
        "--keyword-file",
        type=Path,
        metavar="FILE",
        help="File with one keyword per line (# comments and blank lines ignored); merged with --keyword-list",
    )

    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    categories: list[str] = []
    if args.pe or args.pel or args.pew or args.pem or args.peu:
        categories.append("persistence-execution")
    if args.lm:
        categories.append("lateral-movement")
    if args.da:
        categories.append("data-access")
    if args.de:
        categories.append("data-exfiltration")
    if args.ia:
        categories.append("initial-access")

    if not categories:
        parser.error("Select at least one category (--pe, --lm, --da, --de, --ia)")

    kw_batches: list[list[str]] = []
    if args.keyword_list:
        kw_batches.append(parse_keyword_list_arg(args.keyword_list))
    if args.keyword_file:
        p = args.keyword_file.expanduser()
        if not p.is_file():
            parser.error(f"Keyword file not found: {p}")
        kw_batches.append(load_keywords_from_file(p))
    keyword_filter: KeywordFilter | None = None
    if kw_batches:
        keyword_filter = KeywordFilter(merge_keywords(*kw_batches))
        if not keyword_filter.active:
            parser.error("No valid keywords after parsing --keyword-list / --keyword-file")

    pe_flags = (args.pel, args.pew, args.pem, args.peu)
    persistence_os_filter: frozenset[str] | None = None
    if any(pe_flags):
        persistence_os_filter = frozenset(
            k for k, on in zip(("linux", "windows", "macos", "unix"), pe_flags) if on
        )

    n = len(args.targets)
    if args.jobs is not None:
        if args.jobs < 1:
            parser.error("--jobs must be at least 1")
        max_workers = min(args.jobs, n)
    else:
        max_workers = _default_max_workers(n)

    dump_root: Path | None = Path(args.dump).resolve() if args.dump else None
    if dump_root is not None:
        dump_root.mkdir(parents=True, exist_ok=True)

    def run_one(tpath: str) -> list[TimelineEvent]:
        dpath = (dump_root / _dump_jsonl_filename(tpath)) if dump_root is not None else None
        return collect_events_from_path(
            tpath,
            categories,
            persistence_os_filter=persistence_os_filter,
            dump_jsonl_path=dpath,
            keyword_filter=keyword_filter,
        )

    if max_workers <= 1:
        all_events: list[TimelineEvent] = []
        for tpath in args.targets:
            all_events.extend(run_one(tpath))
    else:
        logging.info("Processing %d targets with up to %d parallel workers", n, max_workers)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            batches = executor.map(run_one, args.targets)
        all_events = [e for batch in batches for e in batch]

    all_events.sort(
        key=lambda e: (e.timestamp or "", e.category, e.target_name, e.source_function, e.description),
    )

    out: TextIO
    if args.output == "-":
        out = sys.stdout
    else:
        out = open(args.output, "w", encoding="utf-8", newline="")

    try:
        if args.format == "json":
            _write_json(all_events, out)
        else:
            _write_csv(all_events, out)
    finally:
        if out is not sys.stdout:
            out.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
