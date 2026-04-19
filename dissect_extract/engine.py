from __future__ import annotations

import importlib.resources
import itertools
import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from dissect.target import Target
from dissect.target.exceptions import PluginError, UnsupportedPluginError

try:
    from dissect.target.plugins.filesystem.yara import HAS_YARA as _DISSECT_HAS_YARA
except ImportError:
    _DISSECT_HAS_YARA = False

from dissect_extract.keywords import KeywordFilter
from dissect_extract.util import (
    fnmatch_path,
    format_path,
    format_record_value,
    load_toml,
    match_scenario,
    normalize_os_slug,
    pick_timestamp,
    record_mapping,
    safe_format,
    to_jsonable,
)

log = logging.getLogger(__name__)

LINUX_YARA_RULES = "linux_implant_yara.yar"
YARA_LINUX_PERSISTENCE_FN = "yara:linux-persistence"
MAX_LINUX_YARA_SCAN_SIZE = 64 * 1024 * 1024

_YARA_RULE_KIND_LABEL: dict[str, str] = {
    "golang_elf_implant_heuristic": "Golang",
    "rust_elf_implant_heuristic": "Rust",
    "php_webshell_common": "Webshell",
}


class _DictAsRecord:
    """Minimal stand-in for flow.record rows so ``record_mapping`` can use ``_asdict``."""

    __slots__ = ("_data",)

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def _asdict(self, exclude: list[str] | None = None) -> dict[str, Any]:
        return dict(self._data)


def _norm_posix_path(p: Any) -> str:
    s = format_path(p).replace("\\", "/")
    while "//" in s:
        s = s.replace("//", "/")
    if len(s) > 1:
        s = s.rstrip("/")
    return s or "/"


def _linux_walkfs_record_for_path(target: Target, want_path: str) -> Any | None:
    """Return the ``walkfs`` filesystem/entry row for *want_path*, without walking from ``/``."""

    want = _norm_posix_path(want_path)
    if want in ("", "/"):
        return None
    parent = str(PurePosixPath(want).parent)
    if parent == ".":
        parent = "/"
    if parent == "/":
        return None
    out = _call_plugin_function(target, "walkfs", {"walkfs_path": parent})
    if out is None:
        return None
    for rec in out:
        m = record_mapping(rec)
        if _norm_posix_path(m.get("path")) == want:
            return rec
    return None


def _iter_linux_yara_persistence(
    target: Target,
    categories: list[str],
    *,
    persistence_os_filter: frozenset[str] | None,
) -> Iterator[tuple[str, str, dict[str, Any], list[dict[str, Any]], str, Any]]:
    if "persistence-execution" not in categories:
        return
    try:
        target_os = target.os
    except Exception:
        return
    if normalize_os_slug(target_os) != "linux":
        return
    if persistence_os_filter is not None and "linux" not in persistence_os_filter:
        return
    if not _DISSECT_HAS_YARA:
        log.debug("yara-python not installed; skipping Linux YARA persistence scan")
        return
    ref = importlib.resources.files("dissect_extract.data") / LINUX_YARA_RULES
    meta = {
        "description": (
            "Possible Persistence: {kind_label} based on the YARA rule matching ({path}, rule {yara_rule})"
        ),
        "timestamp_field": "mtime",
    }
    scenarios: list[dict[str, Any]] = []
    with importlib.resources.as_file(ref) as rules_path:
        out = _call_plugin_function(
            target,
            "yara",
            {
                "rules": [str(rules_path)],
                "path": "/",
                "max_size": MAX_LINUX_YARA_SCAN_SIZE,
            },
        )
        if out is None:
            return
        for yrec in out:
            ym = record_mapping(yrec)
            rule = format_record_value(ym.get("rule", ""))
            kind_label = _YARA_RULE_KIND_LABEL.get(rule, rule)
            path_val = ym.get("path")
            path_s = _norm_posix_path(path_val)
            wf = _linux_walkfs_record_for_path(target, path_s)
            if wf is not None:
                merged = record_mapping(wf)
                merged["yara_rule"] = rule
                merged["kind_label"] = kind_label
                merged["_type"] = "filesystem/entry"
            else:
                merged = {
                    "path": path_val,
                    "mtime": ym.get("ts_mtime"),
                    "yara_rule": rule,
                    "kind_label": kind_label,
                    "_type": "filesystem/yara/match",
                }
            yield (
                "persistence-execution",
                YARA_LINUX_PERSISTENCE_FN,
                meta,
                scenarios,
                target_os,
                _DictAsRecord(merged),
            )


CATEGORY_FILES = {
    "persistence-execution": "persistence_execution.toml",
    "lateral-movement": "lateral_movement.toml",
    "data-access": "data_access.toml",
    "data-exfiltration": "data_exfiltration.toml",
}


@dataclass(frozen=True)
class TimelineEvent:
    timestamp: str | None
    category: str
    source_function: str
    description: str
    target_name: str
    record_type: str | None = None


def load_category_toml(category: str) -> dict[str, Any]:
    if category not in CATEGORY_FILES:
        raise ValueError(f"Unknown category: {category}")
    name = CATEGORY_FILES[category]
    with importlib.resources.as_file(importlib.resources.files("dissect_extract.data") / name) as p:
        return load_toml(p)


def _os_sections_for_target(
    data: dict[str, Any],
    target_os: str,
    only_os: frozenset[str] | None,
) -> dict[str, Any] | None:
    slug = normalize_os_slug(target_os)
    if only_os is not None and slug not in only_os:
        return None
    block = data.get(slug)
    if not isinstance(block, dict) and slug == "unix":
        block = data.get("bsd")
    return block if isinstance(block, dict) else None


def _describe_record(
    func_name: str,
    mapping: dict[str, Any],
    func_meta: dict[str, Any],
    scenarios: list[dict[str, Any]],
    target_os: str,
) -> tuple[str, str | None]:
    ts_field = func_meta.get("timestamp_field")
    for sc in scenarios:
        if normalize_os_slug(str(sc.get("os", target_os))) != normalize_os_slug(target_os):
            continue
        if match_scenario(sc, func_name, mapping):
            sc_ts = sc.get("timestamp_field")
            return safe_format(str(sc["description"]), mapping), (sc_ts if sc_ts else ts_field)
    desc_tpl = func_meta.get("description")
    if not desc_tpl:
        return f"{func_name}: {mapping}", ts_field
    return safe_format(str(desc_tpl), mapping), ts_field


def _call_plugin_function(target: Target, name: str, kwargs: dict[str, Any] | None):
    kwargs = kwargs or {}
    try:
        if not target.has_function(name):
            return None
    except PluginError:
        return None
    try:
        fn = getattr(target, name)
        return fn(**kwargs)
    except UnsupportedPluginError:
        log.debug("Unsupported plugin for %s on this target", name, exc_info=True)
    except TypeError:
        try:
            fn = getattr(target, name)
            return fn()
        except Exception:
            log.debug("Could not call %s with kwargs %s", name, kwargs, exc_info=True)
    except Exception:
        log.warning("Plugin %s failed", name, exc_info=True)
    return None


def _iter_applicable_records(
    target: Target,
    categories: list[str],
    *,
    persistence_os_filter: frozenset[str] | None = None,
) -> Iterator[tuple[str, str, dict[str, Any], list[dict[str, Any]], str, Any]]:
    """Yield (category, source_function, describe_meta, scenarios, target_os, record) for each applicable row."""

    try:
        target_os = target.os
    except Exception:
        target_os = "unknown"

    for category in categories:
        try:
            data = load_category_toml(category)
        except FileNotFoundError:
            log.warning("Missing TOML for category %s", category)
            continue

        os_filter = persistence_os_filter if category == "persistence-execution" else None
        block = _os_sections_for_target(data, target_os, os_filter)
        if block is None:
            if os_filter is not None:
                log.info("Skipping category %s: OS %s not in %s", category, target_os, os_filter)
            continue

        raw_sc = data.get("scenario") or data.get("scenarios") or []
        scenarios = [s for s in raw_sc if isinstance(s, dict)]

        functions_block = block.get("functions")
        if isinstance(functions_block, dict):
            for func_name, meta in functions_block.items():
                if not isinstance(meta, dict):
                    continue
                out = _call_plugin_function(target, func_name, meta.get("call_kwargs"))
                if out is None:
                    continue
                try:
                    iterator = iter(out)
                except TypeError:
                    continue
                for rec in iterator:
                    yield category, func_name, meta, scenarios, target_os, rec

        for walk in block.get("walkfs", []) or []:
            if not isinstance(walk, dict):
                continue
            root = walk.get("walkfs_path", "/")
            meta = {
                "description": walk.get("description", "Filesystem entry: {path}"),
                "timestamp_field": walk.get("timestamp_field", "mtime"),
            }
            out = _call_plugin_function(target, "walkfs", {"walkfs_path": root})
            if out is None:
                continue
            glob_pat = walk.get("path_glob")
            sub = walk.get("path_substring")
            walk_fn = f"walkfs:{root}"
            for rec in out:
                mapping = record_mapping(rec)
                path_str = format_path(mapping.get("path"))
                if glob_pat and not fnmatch_path(path_str, glob_pat):
                    continue
                if sub and sub.lower() not in path_str.lower():
                    continue
                yield category, walk_fn, meta, scenarios, target_os, rec


def collect_events(
    target: Target,
    categories: list[str],
    *,
    persistence_os_filter: frozenset[str] | None = None,
    dump_jsonl_path: Path | None = None,
    keyword_filter: KeywordFilter | None = None,
) -> list[TimelineEvent]:
    tname = getattr(target, "name", None) or str(target.path or "target")
    events: list[TimelineEvent] = []
    dump_f = None
    try:
        if dump_jsonl_path is not None:
            dump_jsonl_path = Path(dump_jsonl_path)
            dump_jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            dump_f = dump_jsonl_path.open("w", encoding="utf-8", newline="\n")

        combined = itertools.chain(
            _iter_applicable_records(
                target,
                categories,
                persistence_os_filter=persistence_os_filter,
            ),
            _iter_linux_yara_persistence(
                target,
                categories,
                persistence_os_filter=persistence_os_filter,
            ),
        )
        for category, func_name, meta, scenarios, target_os, rec in combined:
            mapping = record_mapping(rec)
            desc, ts_f = _describe_record(func_name, mapping, meta, scenarios, target_os)
            if keyword_filter is not None and keyword_filter.active:
                if not keyword_filter.matches(
                    mapping,
                    category=category,
                    source_function=func_name,
                    description=desc,
                ):
                    continue
            ts = pick_timestamp(mapping, ts_f)
            rt = getattr(rec, "_desc", None)
            rtype = getattr(rt, "name", None) if rt is not None else mapping.get("_type")
            rtype_s = str(rtype) if rtype else None
            if func_name.startswith("walkfs:"):
                rtype_s = rtype_s or "filesystem/entry"
            elif func_name == YARA_LINUX_PERSISTENCE_FN:
                rtype_s = format_record_value(mapping.get("_type")) or "filesystem/yara/match"
            events.append(
                TimelineEvent(
                    timestamp=ts.isoformat() if ts else None,
                    category=category,
                    source_function=func_name,
                    description=desc,
                    target_name=tname,
                    record_type=rtype_s,
                ),
            )
            if dump_f is not None:
                payload = {
                    "target_path": str(getattr(target, "path", "") or ""),
                    "target_name": tname,
                    "category": category,
                    "source_function": func_name,
                    "record_type": rtype_s,
                    "record": to_jsonable(mapping),
                }
                dump_f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    finally:
        if dump_f is not None:
            dump_f.close()

    events.sort(key=lambda e: (e.timestamp or "", e.category, e.source_function))
    return events


def open_target(path: str | Path) -> Target:
    return Target.open(str(path))


def close_target(target: Target) -> None:
    """Best-effort cleanup of underlying resources.

    Note: dissect.target's Target object (3.25.1) does not expose a public ``close()``
    nor context manager protocol, but its underlying containers/filesystems often do.
    """

    def _try_close(obj: Any) -> None:
        close = getattr(obj, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                log.debug("Failed closing %r", obj, exc_info=True)

    # Close filesystems first (may depend on volumes/containers).
    for fs in getattr(getattr(target, "filesystems", None), "entries", []) or []:
        _try_close(fs)

    for vol in getattr(getattr(target, "volumes", None), "entries", []) or []:
        _try_close(vol)
        _try_close(getattr(vol, "vs", None))

    for disk in getattr(getattr(target, "disks", None), "entries", []) or []:
        _try_close(getattr(disk, "vs", None))
        _try_close(disk)


def collect_events_from_path(
    path: str | Path,
    categories: list[str],
    *,
    persistence_os_filter: frozenset[str] | None = None,
    dump_jsonl_path: Path | str | None = None,
    keyword_filter: KeywordFilter | None = None,
) -> list[TimelineEvent]:
    """Open *path* as a target, collect timeline events, and return (empty list on failure).

    Safe for use from worker threads: each call creates its own :class:`~dissect.target.Target`.
    When *dump_jsonl_path* is set, writes one JSON object per applicable record to that file.
    When *keyword_filter* is active, only records matching at least one keyword are included (timeline and dump).
    """
    try:
        target = open_target(path)
    except Exception:
        log.exception("Failed to open target %s", path)
        return []
    try:
        dump_path = Path(dump_jsonl_path) if dump_jsonl_path is not None else None
        return collect_events(
            target,
            categories,
            persistence_os_filter=persistence_os_filter,
            dump_jsonl_path=dump_path,
            keyword_filter=keyword_filter,
        )
    except Exception:
        log.exception("Failed to collect events from target %s", path)
        return []
    finally:
        close_target(target)
