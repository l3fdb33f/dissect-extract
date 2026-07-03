#!/usr/bin/env python3
"""Fetch event titles/descriptions from detection.wiki provider pages.

Provider pages list events with anchors (#6, #41, etc.). Per-event URLs like
/provider/4624 are HTML and do not expose the markdown headers this parser expects.
Use WebFetch or curl with a browser User-Agent if urllib gets HTTP 403.
"""

from __future__ import annotations

import re
import urllib.request

# provider slug on detection.wiki -> event ids used in category TOML evtx scenarios
PROVIDER_EVENTS: dict[str, list[int]] = {
    "microsoft-windows-security-auditing": [4624, 4625, 4648, 4672, 4688, 4697, 4698, 4699, 4700, 4701, 4702, 4768, 4769, 4776, 5140, 4778, 4779],
    "service-control-manager": [7036, 7045],
    "microsoft-windows-wmi-activity": [5860, 5861],
    "microsoft-windows-winrm": [6, 91],
    "microsoft-windows-powershell": [4103, 4104],
    "powershell": [400, 800],
    "microsoft-windows-terminalservices-localsessionmanager": [21, 22, 24, 25, 41],
    "microsoft-windows-terminalservices-remoteconnectionmanager": [1149],
    "microsoft-windows-remotedesktopservices-rdpcorets": [131],
    "microsoft-windows-terminalservices-rdpclient": [1024, 1102],
    "microsoft-windows-taskscheduler": [106, 140, 141, 142],
}

HEADER_RE = re.compile(r"^## Event ID (\d+): (.+)$", re.M)
DESC_RE = re.compile(r"^## Event ID (\d+):[^\n]*\n(?:.*\n)*?^## Description\s*\n\n(.+?)(?:\n\n## |\Z)", re.M | re.S)


def fetch_provider_markdown(slug: str) -> str:
    url = f"https://detection.wiki/{slug}/"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; dissect-extract/1.0)"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse_provider(text: str) -> dict[int, tuple[str, str]]:
    out: dict[int, tuple[str, str]] = {}
    for m in HEADER_RE.finditer(text):
        eid = int(m.group(1))
        title = m.group(2).strip().rstrip(".")
        out[eid] = (title, "")
    for m in DESC_RE.finditer(text):
        eid = int(m.group(1))
        desc = m.group(2).strip().split("\n\n")[0]
        if eid in out:
            title, _ = out[eid]
            out[eid] = (title, desc)
    return out


def suggest_action(eid: int, title: str, desc: str) -> str:
    if desc and desc.lower() != title.lower():
        if len(desc) > 160:
            desc = desc[:157].rsplit(" ", 1)[0] + "..."
        return f"Event {eid}: {title}. {desc}"
    return f"Event {eid}: {title}"


def main() -> None:
    for slug, eids in PROVIDER_EVENTS.items():
        try:
            text = fetch_provider_markdown(slug)
            parsed = parse_provider(text)
        except Exception as exc:
            print(f"# {slug}: fetch failed: {exc}")
            continue
        for eid in eids:
            title, desc = parsed.get(eid, ("?", ""))
            print(f"{slug}\t{eid}\t{suggest_action(eid, title, desc)!r}")


if __name__ == "__main__":
    main()
