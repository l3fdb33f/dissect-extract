from __future__ import annotations

import base64
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as f:
        return tomllib.load(f)


def format_record_value(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, date):
        return v.isoformat()
    if isinstance(v, Path):
        return str(v)
    return str(v)


def record_mapping(rec: Any) -> dict[str, Any]:
    if hasattr(rec, "_asdict"):
        # flow.record.Record._asdict supports `exclude` in current versions, but keep this robust
        # for older/newer implementations.
        try:
            return rec._asdict(exclude=["_target", "_key", "_user", "_resource"])
        except TypeError:
            return rec._asdict()
    return {k: getattr(rec, k) for k in dir(rec) if not k.startswith("_")}


def pick_timestamp(mapping: dict[str, Any], preferred: str | None) -> date | None:
    """Return a calendar date or datetime from *mapping* (``datetime`` subclasses ``date``)."""

    if preferred and mapping.get(preferred):
        v = mapping[preferred]
        return v if isinstance(v, date) else None
    for key in (
        "ts",
        "mtime",
        "btime",
        "ctime",
        "atime",
        "target_mtime",
        "lnk_mtime",
        "regf_mtime",
        "ts_mtime",
        "last_modified",
        "time",
    ):
        v = mapping.get(key)
        if isinstance(v, date):
            return v
    return None


def normalize_os_slug(slug: str) -> str:
    s = (slug or "").lower()
    if s in ("osx",):
        return "macos"
    if s in ("android", "esxi", "citrix-netscaler", "fortios", "ios", "proxmox", "vyos"):
        return "unix"
    return s


def safe_format(template: str, mapping: dict[str, Any]) -> str:
    flat = {k: format_record_value(v) for k, v in mapping.items()}
    try:
        return template.format(**flat)
    except (KeyError, ValueError):
        return template


def any_field_nonzero(mapping: dict[str, Any], field_names: list[Any]) -> bool:
    """True if at least one named field is present and numerically non-zero (or truthy for non-numeric)."""

    if not field_names:
        return True
    for raw in field_names:
        name = str(raw)
        v = mapping.get(name)
        if v is None:
            continue
        try:
            if int(v) != 0:
                return True
        except (TypeError, ValueError):
            if v:
                return True
    return False


def match_scenario(
    rules: dict[str, Any],
    func_name: str,
    mapping: dict[str, Any],
) -> bool:
    if rules.get("function") != func_name:
        return False
    fc = rules.get("field_contains") or {}
    for field, needle in fc.items():
        hay = format_record_value(mapping.get(field, ""))
        if needle.lower() not in hay.lower():
            return False
    frx = rules.get("field_regex") or {}
    for field, pattern in frx.items():
        if not re.search(pattern, format_record_value(mapping.get(field, ""))):
            return False
    psub = rules.get("path_contains")
    if psub:
        p = format_record_value(mapping.get("path", ""))
        if psub.lower() not in p.lower():
            return False
    return True


def fnmatch_path(path_str: str, pattern: str) -> bool:
    from fnmatch import fnmatch

    return fnmatch(path_str.replace("\\", "/"), pattern.replace("\\", "/"))


def format_path(p: Any) -> str:
    if p is None:
        return ""
    if isinstance(p, Path):
        return str(p)
    return str(p)


def to_jsonable(value: Any) -> Any:
    """Convert dissect / flow.record values to JSON-serializable structures."""

    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return {"__bytes_base64__": base64.b64encode(value).decode("ascii")}
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(v) for v in value]
    if isinstance(value, memoryview):
        return {"__bytes_base64__": base64.b64encode(value.tobytes()).decode("ascii")}
    return str(value)
