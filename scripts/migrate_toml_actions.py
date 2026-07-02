#!/usr/bin/env python3
"""One-off: add [meta], rename description->action, shorten LM/persistence scenario verbs."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "dissect_extract" / "data"

META = """[meta]
narrative_user_action = "User {user} {action}"
narrative_user_only = "User {user}"
narrative_action_only = "{action}"

"""

LM_SCENARIO_ACTIONS: list[tuple[str, str, str]] = [
    ("remoteaccess", "message", "used remote access (RDP)"),
    ("evtx", "4624", "logged on"),
    ("evtx", "4625", "failed logon"),
    ("evtx", "4648", "logged on with explicit credentials"),
    ("evtx", "4672", "logged on with elevated privileges"),
    ("evtx", "4768", "requested Kerberos TGT"),
    ("evtx", "4769", "requested Kerberos service ticket"),
    ("evtx", "4776", "authenticated via NTLM"),
    ("evtx", "5140", "accessed a network share"),
    ("evtx", "4778", "reconnected RDP session"),
    ("evtx", "4779", "disconnected RDP session"),
    ("evtx", "7045", "installed a remote service"),
    ("evtx", "7036", "changed service state"),
    ("evtx", "4697", "installed a service"),
    ("evtx", "5860", "used WMI"),
    ("evtx", "5861", "used WMI"),
    ("evtx", '"^6$"', "connected via WinRM"),
    ("evtx", '"^91$"', "received WinRM connection"),
    ("evtx", "4103", "ran PowerShell"),
    ("evtx", "4104", "ran PowerShell"),
    ("evtx", '"^400$"', "started PowerShell"),
    ("evtx", '"^800$"', "ran PowerShell pipeline"),
    ("evtx", "1149", "connected via RDP"),
    ("evtx", '"^131$"', "connected via RDP"),
    ("evtx", "1024|1102", "initiated outbound RDP"),
]

PE_SCENARIO_ACTIONS: list[tuple[str, str, str]] = [
    ("runkeys", "powershell", "ran PowerShell from a Run key"),
    ("services", ".timer", "configured a systemd timer"),
]

RDP_LSM_OLD = re.compile(
    r"\[\[scenario\]\]\r?\n"
    r'os = "windows"\r?\n'
    r'function = "evtx"\r?\n'
    r'field_regex = \{ Provider_Name = "\(\?i\)\^Microsoft-Windows-TerminalServices-LocalSessionManager\$", '
    r'EventID = "\^\(21\|22\|25\|24\|41\)\$" \}\r?\n'
    r"^action = .+$\r?\n"
    r'timestamp_field = "ts"\r?\n',
    re.M,
)

RDP_LSM_NEW = """[[scenario]]
os = "windows"
function = "evtx"
field_regex = { Provider_Name = "(?i)^Microsoft-Windows-TerminalServices-LocalSessionManager$", EventID = "^21$" }
action = "connected via RDP"
timestamp_field = "ts"

[[scenario]]
os = "windows"
function = "evtx"
field_regex = { Provider_Name = "(?i)^Microsoft-Windows-TerminalServices-LocalSessionManager$", EventID = "^22$" }
action = "disconnected RDP session"
timestamp_field = "ts"

[[scenario]]
os = "windows"
function = "evtx"
field_regex = { Provider_Name = "(?i)^Microsoft-Windows-TerminalServices-LocalSessionManager$", EventID = "^24$" }
action = "disconnected RDP session"
timestamp_field = "ts"

[[scenario]]
os = "windows"
function = "evtx"
field_regex = { Provider_Name = "(?i)^Microsoft-Windows-TerminalServices-LocalSessionManager$", EventID = "^25$" }
action = "reconnected RDP session"
timestamp_field = "ts"

[[scenario]]
os = "windows"
function = "evtx"
field_regex = { Provider_Name = "(?i)^Microsoft-Windows-TerminalServices-LocalSessionManager$", EventID = "^41$" }
action = "disconnected RDP session"
timestamp_field = "ts"

"""


def prepend_meta(text: str) -> str:
    if text.startswith("[meta]"):
        return text
    lines = text.splitlines(keepends=True)
    i = 0
    while i < len(lines) and (lines[i].startswith("#") or lines[i].strip() == ""):
        i += 1
    return "".join(lines[:i]) + META + "".join(lines[i:])


def _shorten_scenario_action(block: str, rules: list[tuple[str, str, str]]) -> str:
    fn_m = re.search(r'^function = "([^"]+)"', block, re.M)
    if not fn_m:
        return block
    fn = fn_m.group(1)
    for rule_fn, needle, action in rules:
        if fn != rule_fn or needle not in block:
            continue
        block = re.sub(
            r"^description = .+$",
            f'action = "{action}"',
            block,
            count=1,
            flags=re.M,
        )
        break
    return block


def migrate_file(path: Path, scenario_rules: list[tuple[str, str, str]] | None) -> None:
    text = path.read_text(encoding="utf-8")
    text = prepend_meta(text)

    if scenario_rules:
        parts = re.split(r"(?=^\[\[scenario\]\])", text, flags=re.M)
        head = parts[0]
        blocks = []
        for block in parts[1:]:
            if block.startswith("[[scenario]]"):
                blocks.append(_shorten_scenario_action(block, scenario_rules))
            else:
                blocks.append(block)
        text = head + "".join(blocks)

    text = re.sub(r"^description = ", "action = ", text, flags=re.M)

    if path.name == "lateral_movement.toml":
        text, n = RDP_LSM_OLD.subn(RDP_LSM_NEW, text)
        if n:
            print(f"  split RDP LSM scenario into {n} block(s)")

    path.write_text(text, encoding="utf-8", newline="\n")
    print(f"updated {path.name}")


def main() -> None:
    migrate_file(ROOT / "lateral_movement.toml", LM_SCENARIO_ACTIONS)
    migrate_file(ROOT / "persistence_execution.toml", PE_SCENARIO_ACTIONS)
    for name in ("data_access.toml", "data_exfiltration.toml", "initial_access.toml"):
        migrate_file(ROOT / name, None)


if __name__ == "__main__":
    main()
