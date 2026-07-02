from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any

from dissect.target import Target

from dissect_extract.util import format_record_value, to_jsonable

log = logging.getLogger(__name__)

_SID_RE = re.compile(r"^S-1-\d+(-\d+)+$", re.IGNORECASE)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
)

_RAW_RECORD_SKIP = frozenset({"_generated", "_version", "_source", "_classification"})

USER_FIELDS: tuple[str, ...] = (
    "username",
    "user",
    "name",
    "ut_user",
    "authenticated_user",
    "SubjectUserName",
    "TargetUserName",
    "TargetUser",
    "AccountName",
    "Account_Name",
    "User",
    "UserName",
    "run_as",
    "user_id",
)

SID_FIELDS: tuple[str, ...] = (
    "sid",
    "user_sid",
    "SubjectUserSid",
    "TargetUserSid",
    "SubjectLogonId",
)

ACTION_FIELDS: tuple[str, ...] = (
    "command",
    "action",
    "EventID",
    "message",
    "comm",
    "role_name",
    "task_name",
    "Provider_Name",
    "ut_type",
    "behavior_type",
    "call_type",
    "setting",
    "yara_rule",
    "link_name",
    "product_name",
    "executable",
)

SRC_IP_FIELDS: tuple[str, ...] = (
    "IpAddress",
    "SourceNetworkAddress",
    "SourceIp",
    "SourceAddress",
    "ClientAddress",
    "ClientIpAddress",
    "WorkstationName",
    "Workstation",
    "ut_host",
    "ut_addr",
    "address",
    "remote_host",
    "InitiatingHost",
    "initiating_ip",
    "SourceIpAddress",
)

DST_IP_FIELDS: tuple[str, ...] = (
    "DestinationIp",
    "DestAddress",
    "DestinationAddress",
    "TargetIpAddress",
    "host",
)


@dataclass(frozen=True)
class EventContext:
    user: str | None = None
    action: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None


class SidUsernameMap:
    """Maps Windows SIDs (and Unix UIDs) to account names from ``target.users()``."""

    __slots__ = ("_sid_to_name", "_uid_to_name")

    def __init__(self, target: Target) -> None:
        self._sid_to_name: dict[str, str] = {}
        self._uid_to_name: dict[int, str] = {}
        try:
            for user in target.users():
                name = getattr(user, "name", None)
                if not name:
                    continue
                sid = getattr(user, "sid", None)
                if sid:
                    self._sid_to_name[str(sid).upper()] = str(name)
                uid = getattr(user, "uid", None)
                if uid is not None:
                    try:
                        self._uid_to_name[int(uid)] = str(name)
                    except (TypeError, ValueError):
                        pass
        except Exception:
            log.debug("Could not build SID/username map from target.users()", exc_info=True)

    def resolve(self, value: Any) -> str | None:
        if value is None:
            return None
        s = format_record_value(value).strip()
        if not s:
            return None
        if _SID_RE.match(s):
            return self._sid_to_name.get(s.upper(), s)
        if s.isdigit():
            try:
                return self._uid_to_name.get(int(s), s)
            except ValueError:
                pass
        return s

    def lookup_sid(self, sid: str) -> str | None:
        return self._sid_to_name.get(sid.upper())


def _first_ipv4(value: Any) -> str | None:
    if value is None:
        return None
    text = format_record_value(value)
    if not text:
        return None
    m = _IPV4_RE.search(text)
    return m.group(0) if m else None


def _collect_ipv4s(mapping: dict[str, Any]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for val in mapping.values():
        text = format_record_value(val)
        for ip in _IPV4_RE.findall(text):
            if ip not in seen:
                seen.add(ip)
                found.append(ip)
    return found


def extract_event_context(
    mapping: dict[str, Any],
    *,
    category: str,
    source_function: str,
    sid_map: SidUsernameMap,
    record: Any | None = None,
) -> EventContext:
    user: str | None = None
    for key in USER_FIELDS:
        if key not in mapping:
            continue
        resolved = sid_map.resolve(mapping.get(key))
        if resolved and not _looks_like_empty(resolved):
            user = resolved
            break

    if user is None:
        for key in SID_FIELDS:
            if key not in mapping:
                continue
            resolved = sid_map.resolve(mapping.get(key))
            if resolved:
                user = resolved
                break

    if user is None and record is not None:
        attached = getattr(record, "_user", None)
        if attached is not None:
            user = getattr(attached, "name", None) or sid_map.resolve(getattr(attached, "sid", None))

    action: str | None = None
    for key in ACTION_FIELDS:
        val = mapping.get(key)
        if _looks_like_empty(val):
            continue
        text = format_record_value(val).strip()
        if text:
            action = text[:240]
            break

    source_ip: str | None = None
    dest_ip: str | None = None
    for key in SRC_IP_FIELDS:
        ip = _first_ipv4(mapping.get(key))
        if ip:
            source_ip = ip
            break
    for key in DST_IP_FIELDS:
        ip = _first_ipv4(mapping.get(key))
        if ip and ip != source_ip:
            dest_ip = ip
            break

    extra_ips = _collect_ipv4s(mapping)
    if source_ip is None and extra_ips:
        source_ip = extra_ips[0]
    if dest_ip is None and len(extra_ips) > 1:
        for ip in extra_ips[1:]:
            if ip != source_ip:
                dest_ip = ip
                break

    if _wants_network_detail(category, source_function) and source_ip is None and dest_ip is None:
        # Last resort for LM / network plugins: any IPv4 in the record blob.
        if extra_ips:
            source_ip = extra_ips[0]
            if len(extra_ips) > 1:
                dest_ip = extra_ips[1]

    return EventContext(user=user, action=action, source_ip=source_ip, dest_ip=dest_ip)


def _wants_network_detail(category: str, source_function: str) -> bool:
    if category == "lateral-movement":
        return True
    fn = source_function.lower()
    if "network" in fn or "netstat" in fn or "sru.network" in fn:
        return True
    return False


def _looks_like_empty(val: Any) -> bool:
    if val is None:
        return True
    if isinstance(val, str) and not val.strip():
        return True
    return False


def enrich_description(base: str, ctx: EventContext) -> str:
    """Append user / action / src / dst when any are known."""

    tags: list[str] = []
    if ctx.user:
        tags.append(f"user: {ctx.user}")
    if ctx.action:
        tags.append(f"action: {ctx.action}")
    if ctx.source_ip:
        tags.append(f"src: {ctx.source_ip}")
    if ctx.dest_ip:
        tags.append(f"dst: {ctx.dest_ip}")
    if not tags:
        return base
    return f"{base} [{'; '.join(tags)}]"


def format_raw_record(mapping: dict[str, Any]) -> str:
    """Compact JSON of record fields (no flow.record reserved / internal keys)."""

    cleaned = {
        str(k): v
        for k, v in mapping.items()
        if str(k) not in _RAW_RECORD_SKIP and not str(k).startswith("_")
    }
    return json.dumps(to_jsonable(cleaned), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
