from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any

from dissect.target import Target

from dissect_extract.util import format_record_value, safe_format, to_jsonable

log = logging.getLogger(__name__)

_SID_RE = re.compile(r"^S-1-\d+(-\d+)+$", re.IGNORECASE)
_GUID_RE = re.compile(
    r"^[{\[]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[}\]]?$",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
)
_DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$", re.IGNORECASE)

_RAW_RECORD_SKIP = frozenset({"_generated", "_version", "_source", "_classification"})

USER_FIELDS: tuple[str, ...] = (
    "username",
    "user",
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
    "sam_name",
    "cn",
    "upn",
    "EventXML_User",
)

SID_FIELDS: tuple[str, ...] = (
    "sid",
    "user_sid",
    "SubjectUserSid",
    "TargetUserSid",
    "Security_UserID",
    "SubjectLogonId",
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
    "EventXML_Param3",
    "ClientIP",
    "clientIP",
)

DST_IP_FIELDS: tuple[str, ...] = (
    "DestinationIp",
    "DestAddress",
    "DestinationAddress",
    "TargetIpAddress",
    "host",
)

# Terminal Services / RDP: Param1 is typically the username on these events.
_EVENTXML_USER_FIRST_IDS = frozenset({1149, 21, 22, 24, 25, 41, 131, 1024, 1102})

# WinRM outbound session create: connection string is <host>/wsman?PSVersion=...
_WINRM_CONNECTION_EVENT_IDS = frozenset({6})
# WinRM inbound shell create: client address in ClientIP field or message text.
_WINRM_INBOUND_EVENT_IDS = frozenset({91})
_CLIENTIP_MESSAGE_RE = re.compile(r"clientIP:\s*([^\s)]+)", re.IGNORECASE)
_LOCALHOST_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_LOW_PRIORITY_USER_SIDS = frozenset({"S-1-5-18", "S-1-5-19", "S-1-5-20"})
_LOW_PRIORITY_USER_NAMES = frozenset(
    {
        "local service",
        "localservice",
        "local system",
        "localsystem",
        "network service",
        "networkservice",
        "system",
        "systemprofile",
    }
)


@dataclass(frozen=True)
class EventContext:
    user: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None


class UserAccountMap:
    """SID/UID map plus known account names from profile list, SAM, and NTDS."""

    __slots__ = ("_sid_to_name", "_uid_to_name", "_name_lookup")

    def __init__(self, target: Target) -> None:
        self._sid_to_name: dict[str, str] = {}
        self._uid_to_name: dict[int, str] = {}
        self._name_lookup: dict[str, str] = {}
        self._load_target_users(target)
        self._load_sam(target)
        self._load_ntds(target)

    def _register_name(self, name: str | None) -> None:
        if not name:
            return
        text = str(name).strip()
        if not text or not _looks_like_username(text):
            return
        display = text
        if "\\" in display:
            display = display.split("\\", 1)[-1]
        if "@" in display:
            display = display.split("@", 1)[0]
        key = display.lower()
        if key and key not in self._name_lookup:
            self._name_lookup[key] = display

    def _register_sid(self, sid: str | None, name: str | None) -> None:
        if sid and name:
            self._sid_to_name[str(sid).upper()] = str(name)
        if name:
            self._register_name(name)

    def _load_target_users(self, target: Target) -> None:
        try:
            for user in target.users():
                name = getattr(user, "name", None)
                sid = getattr(user, "sid", None)
                self._register_sid(str(sid) if sid else None, str(name) if name else None)
                uid = getattr(user, "uid", None)
                if name is not None and uid is not None:
                    try:
                        self._uid_to_name[int(uid)] = str(name)
                    except (TypeError, ValueError):
                        pass
        except Exception:
            log.debug("Could not enumerate target.users()", exc_info=True)

    def _load_sam(self, target: Target) -> None:
        try:
            if not target.has_function("sam"):
                return
            machine_sid = None
            if target.has_function("machine_sid"):
                machine_sid = next(target.machine_sid(), None)
            domain_sid = getattr(machine_sid, "sid", None) if machine_sid else None
            for rec in target.sam():
                username = getattr(rec, "username", None)
                rid = getattr(rec, "rid", None)
                if domain_sid and rid is not None:
                    self._register_sid(f"{domain_sid}-{rid}", str(username) if username else None)
                elif username:
                    self._register_name(str(username))
        except Exception:
            log.debug("Could not enumerate SAM accounts", exc_info=True)

    def _load_ntds(self, target: Target) -> None:
        try:
            if not target.has_function("ad"):
                return
            ad = getattr(target, "ad", None)
            if ad is None or not hasattr(ad, "users"):
                return
            for rec in ad.users():
                sid = getattr(rec, "sid", None)
                for candidate in (
                    getattr(rec, "sam_name", None),
                    getattr(rec, "cn", None),
                    getattr(rec, "upn", None),
                ):
                    self._register_sid(str(sid) if sid else None, str(candidate) if candidate else None)
        except Exception:
            log.debug("Could not enumerate NTDS accounts", exc_info=True)

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
        return self.match_known_name(s)

    def match_known_name(self, value: Any) -> str | None:
        s = format_record_value(value).strip()
        if not s or not _looks_like_username(s):
            return None
        if _SID_RE.match(s):
            return self._sid_to_name.get(s.upper())
        if "\\" in s:
            s = s.split("\\", 1)[-1]
        if "@" in s:
            s = s.split("@", 1)[0]
        return self._name_lookup.get(s.lower())

    def lookup_sid(self, sid: str) -> str | None:
        return self._sid_to_name.get(sid.upper())


# Backward-compatible alias used by engine.py
SidUsernameMap = UserAccountMap


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


def _event_id(mapping: dict[str, Any]) -> int | None:
    raw = mapping.get("EventID")
    if raw is None:
        return None
    try:
        return int(format_record_value(raw).strip())
    except ValueError:
        return None


def _is_winrm_provider(mapping: dict[str, Any]) -> bool:
    name = format_record_value(mapping.get("Provider_Name", "")).strip().lower()
    return "winrm" in name or name.endswith("windows remote management")


def _parse_winrm_connection_dest(value: Any) -> str | None:
    """Extract remote host from WinRM connection strings like host/wsman?PSVersion=5.1."""

    text = format_record_value(value).strip()
    if not text:
        return None

    target = text
    if "://" in target:
        target = target.split("://", 1)[1]

    host_port = target.split("/", 1)[0].split("?", 1)[0].strip()
    if not host_port:
        return None

    if host_port.startswith("[") and "]" in host_port:
        host = host_port[1 : host_port.index("]")].strip()
    elif ":" in host_port and not _IPV4_RE.fullmatch(host_port):
        host_part, port_part = host_port.rsplit(":", 1)
        host = host_part.strip() if port_part.isdigit() else host_port
    else:
        host = host_port

    if not host or host.lower() in _LOCALHOST_HOSTS:
        return None

    ip_match = _IPV4_RE.search(host)
    if ip_match:
        return ip_match.group(0)
    return host


def _extract_winrm_dest(mapping: dict[str, Any]) -> str | None:
    if not _is_winrm_provider(mapping):
        return None
    eid = _event_id(mapping)
    if eid not in _WINRM_CONNECTION_EVENT_IDS:
        return None
    for key in ("connection", "Connection"):
        if key in mapping:
            dest = _parse_winrm_connection_dest(mapping.get(key))
            if dest:
                return dest
    return None


def _normalize_winrm_client(value: str) -> str | None:
    text = value.strip().rstrip(")")
    if not text:
        return None
    lower = text.lower()
    if lower in _LOCALHOST_HOSTS:
        return None
    ip_match = _IPV4_RE.search(text)
    if ip_match:
        return ip_match.group(0)
    return text


def _extract_winrm_source(mapping: dict[str, Any]) -> str | None:
    """Inbound WinRM (e.g. event 91): client IP from field or rendered message."""

    if not _is_winrm_provider(mapping):
        return None
    eid = _event_id(mapping)
    if eid not in _WINRM_INBOUND_EVENT_IDS:
        return None

    for key in ("ClientIP", "clientIP", "ClientIp"):
        if key in mapping:
            client = _normalize_winrm_client(format_record_value(mapping.get(key)))
            if client:
                return client

    for key in ("Message", "message"):
        if key not in mapping:
            continue
        text = format_record_value(mapping.get(key))
        match = _CLIENTIP_MESSAGE_RE.search(text)
        if match:
            client = _normalize_winrm_client(match.group(1))
            if client:
                return client

    return None


def _is_low_priority_user(candidate: str, original: Any = None) -> bool:
    original_text = format_record_value(original).strip().upper() if original is not None else ""
    if original_text in _LOW_PRIORITY_USER_SIDS:
        return True
    candidate_text = candidate.strip().lower()
    if "\\" in candidate_text:
        candidate_text = candidate_text.split("\\", 1)[-1]
    if "@" in candidate_text:
        candidate_text = candidate_text.split("@", 1)[0]
    return candidate_text in _LOW_PRIORITY_USER_NAMES


def _user_candidate(value: Any, *, sid_map: UserAccountMap, allow_raw: bool = False) -> str | None:
    resolved = sid_map.resolve(value)
    if resolved and _looks_like_username(resolved):
        return resolved

    if not allow_raw:
        return None
    text = format_record_value(value).strip()
    if text and _looks_like_username(text) and not _DOMAIN_RE.match(text):
        return text
    return None


def _extract_user(
    mapping: dict[str, Any],
    *,
    sid_map: UserAccountMap,
    record: Any | None,
) -> str | None:
    fallback_user: str | None = None

    def keep_or_return(candidate: str | None, original: Any = None) -> str | None:
        nonlocal fallback_user
        if not candidate:
            return None
        if _is_low_priority_user(candidate, original):
            fallback_user = fallback_user or candidate
            return None
        return candidate

    for key in USER_FIELDS:
        if key not in mapping:
            continue
        val = mapping.get(key)
        resolved = _user_candidate(val, sid_map=sid_map, allow_raw=True)
        chosen = keep_or_return(resolved, val)
        if chosen:
            return chosen

    eid = _event_id(mapping)
    if eid in _EVENTXML_USER_FIRST_IDS:
        p1 = mapping.get("EventXML_Param1")
        if p1 is not None:
            resolved = _user_candidate(p1, sid_map=sid_map, allow_raw=True)
            chosen = keep_or_return(resolved, p1)
            if chosen:
                return str(chosen)

    for key in sorted(k for k in mapping if str(k).startswith("EventXML_Param")):
        val = mapping.get(key)
        resolved = sid_map.match_known_name(val)
        chosen = keep_or_return(resolved, val)
        if chosen:
            return chosen
        text = format_record_value(val).strip()
        if text and _looks_like_username(text) and not _DOMAIN_RE.match(text):
            if eid in _EVENTXML_USER_FIRST_IDS and key.endswith("Param1"):
                chosen = keep_or_return(text, val)
                if chosen:
                    return chosen
            known = sid_map.match_known_name(text)
            chosen = keep_or_return(known, val)
            if chosen:
                return chosen

    for key in SID_FIELDS:
        if key not in mapping:
            continue
        val = mapping.get(key)
        resolved = sid_map.resolve(val)
        chosen = keep_or_return(resolved, val)
        if chosen:
            return chosen

    for val in mapping.values():
        hit = sid_map.match_known_name(val)
        chosen = keep_or_return(hit, val)
        if chosen:
            return chosen

    if record is not None:
        attached = getattr(record, "_user", None)
        if attached is not None:
            name = getattr(attached, "name", None)
            if name:
                chosen = keep_or_return(str(name), name)
                if chosen:
                    return chosen
            sid = getattr(attached, "sid", None)
            if sid:
                resolved = sid_map.resolve(str(sid))
                chosen = keep_or_return(resolved, str(sid))
                if chosen:
                    return chosen

    return fallback_user


def extract_event_context(
    mapping: dict[str, Any],
    *,
    category: str = "",
    source_function: str = "",
    sid_map: UserAccountMap,
    record: Any | None = None,
) -> EventContext:
    user = _extract_user(mapping, sid_map=sid_map, record=record)

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

    if _wants_network_detail(category, source_function) and source_ip is None and extra_ips:
        source_ip = extra_ips[0]
        if len(extra_ips) > 1 and dest_ip is None:
            dest_ip = extra_ips[1]

    winrm_dest = _extract_winrm_dest(mapping)
    if winrm_dest:
        if source_ip == winrm_dest:
            source_ip = None
        dest_ip = winrm_dest

    winrm_source = _extract_winrm_source(mapping)
    if winrm_source:
        if dest_ip == winrm_source:
            dest_ip = None
        source_ip = winrm_source

    return EventContext(user=user, source_ip=source_ip, dest_ip=dest_ip)


def _wants_network_detail(category: str, source_function: str) -> bool:
    if category == "lateral-movement":
        return True
    fn = source_function.lower()
    return "network" in fn or "netstat" in fn or "sru.network" in fn


def _looks_like_username(value: str) -> bool:
    s = value.strip()
    if not s or len(s) < 2:
        return False
    lower = s.lower()
    if lower in {
        "-",
        "n/a",
        "local system",
        "localsystem",
        "system",
        "anonymous",
        "defaultaccount",
        "wdagutilityaccount",
    }:
        return False
    if _SID_RE.match(s) or _GUID_RE.match(s) or _IPV4_RE.fullmatch(s) or _DOMAIN_RE.match(s):
        return False
    if s.isdigit():
        return False
    if not any(c.isalpha() for c in s):
        return False
    return True


_DEFAULT_NARRATIVE_META = {
    "narrative_user_action": "User {user} {action}",
    "narrative_user_only": "User {user}",
    "narrative_action_only": "{action}",
}


def format_narrative(
    action: str | None,
    ctx: EventContext,
    *,
    meta: dict[str, Any] | None = None,
    fallback: str = "",
) -> str:
    """Apply category TOML narrative templates to a resolved action and extracted context."""

    templates = {**_DEFAULT_NARRATIVE_META, **(meta or {})}
    act = (action or "").strip()
    act_cap = act[0].upper() + act[1:] if act and act[0].islower() else act

    if ctx.user and act:
        text = safe_format(
            str(templates["narrative_user_action"]),
            {"user": ctx.user, "action": act},
        )
    elif ctx.user:
        text = safe_format(str(templates["narrative_user_only"]), {"user": ctx.user})
    elif act:
        text = safe_format(str(templates["narrative_action_only"]), {"action": act_cap})
    else:
        text = fallback.strip()

    if ctx.source_ip:
        text = f"{text} from {ctx.source_ip}"
    if ctx.dest_ip and ctx.dest_ip != ctx.source_ip:
        text = f"{text} to {ctx.dest_ip}"
    return text


def format_raw_record(mapping: dict[str, Any]) -> str:
    """Compact JSON of record fields (no flow.record reserved / internal keys)."""

    cleaned = {
        str(k): v
        for k, v in mapping.items()
        if str(k) not in _RAW_RECORD_SKIP and not str(k).startswith("_")
    }
    return json.dumps(to_jsonable(cleaned), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
