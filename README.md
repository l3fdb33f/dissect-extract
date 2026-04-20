# dissect-extract

This project builds on the [Dissect](https://docs.dissect.tools) framework (`dissect.target`) to pull triage-oriented records from disk images or mounted targets, merge them into a **sorted super-timeline**, and attach **human-readable descriptions** (with timestamps where available). Definitions live in TOML bundles under `dissect_extract/data/` and map to [target-query](https://docs.dissect.tools/en/latest/tools/target-query.html)–style plugin functions (for example `runkeys`, `walkfs`, `defender.quarantine`).

## What you get

- **Categories** you can mix and match: persistence and execution, lateral movement, data access, data exfiltration, and initial access.
- **Per-OS behavior**: only the section that matches the target’s detected OS is used (with limited fallbacks, for example `unix` for some non-Linux Unix targets).
- **Scenario overrides**: a few high-signal patterns (for example “Run key + PowerShell”, “systemd timer”) can replace the default description for matching rows.
- **Optional keyword filter**: keep only events whose fields, category, source function, or description match your terms.
- **Parallel targets**: process multiple images at once with a configurable worker cap.
- **Optional raw dump**: write the same records that fed the timeline to JSONL (one file per target) for deeper review.
- **Linux-only YARA add-on** (persistence category): bundled rules for Go/Rust ELF heuristics and PHP webshell patterns, run through Dissect’s `yara` plugin when `yara-python` is installed (see below).

## Requirements

| Requirement | Notes |
|-------------|--------|
| **Python** | 3.10 or newer (`requires-python` in `pyproject.toml`). |
| **dissect.target** | Core dependency (≥ 3.20). Install the usual Dissect filesystem/registry stack so your target type opens cleanly. Some plugins need optional Dissect extras (for example browser parsers); if a function is missing on a given image, that source is skipped. |
| **tomli** | Pulled in automatically on Python 3.10 only (for TOML loading); 3.11+ uses the stdlib. |
| **yara-python** (optional) | Install with `pip install dissect-extract[yara]` or `pip install yara-python` to enable the **Linux** bundled YARA persistence scan. Without it, the rest of the tool works; the YARA pass is skipped. |

Development tooling (optional): `pip install dissect-extract[dev]` for Ruff.

## Installation

From a clone of this repository:

```bash
pip install .
```

Editable install while developing:

```bash
pip install -e ".[dev]"
```

With YARA support for Linux heuristic persistence:

```bash
pip install ".[yara]"
```

This installs the `dissect-timeline` console script (see below).

## How to run

The CLI entry point is **`dissect-timeline`** (defined in `pyproject.toml`). You can also run the package as a module:

```bash
python -m dissect_extract.cli [OPTIONS] TARGET [TARGET ...]
```

### Basics

- **Targets**: one or more paths Dissect can open (disk images, folders, VM configs, etc.—same idea as `target-query`).
- **Pick at least one category** (flags are combinable):

  | Flag | Category |
  |------|----------|
  | `--pe` / `--persistence-execution` | Persistence and execution |
  | `--lm` / `--lateral-movement` | Lateral movement |
  | `--da` / `--data-access` | Data access |
  | `--de` / `--data-exfiltration` | Data exfiltration |
  | `--ia` / `--initial-access` | Initial access (delivery, downloads, web logs) |

- **Output**: JSON (default) or CSV (`-f csv`). Default output is stdout (`-o` to write a file).

Example: persistence and lateral movement from one image to `timeline.json`:

```bash
dissect-timeline --pe --lm C:/cases/host01.e01 -o timeline.json
```

Example: all five categories, verbose logging:

```bash
dissect-timeline --pe --lm --da --de --ia /mnt/evidence/disk.raw -v -o all.json
```

### Persistence scope by OS (optional)

When you use **`--pe`**, you can narrow **which OS bundle** is consulted for persistence (useful when you only care about one playbook). If you set any of these, **only** the listed OS sections are loaded for persistence; the target must still match that OS or persistence will be empty for that target.

| Flag | Effect |
|------|--------|
| `--pel` / `--persistence-execution-linux` | Linux persistence definitions only |
| `--pew` / `--persistence-execution-windows` | Windows persistence definitions only |
| `--pem` / `--persistence-execution-macos` | macOS persistence definitions only |
| `--peu` / `--persistence-execution-unix` | Generic Unix/BSD persistence definitions only |

Example: Linux-only persistence plus lateral movement (for any OS the target reports):

```bash
dissect-timeline --pe --pel --lm /data/linux.dd -o out.json
```

### Other useful options

| Option | Purpose |
|--------|---------|
| `-f csv` | CSV instead of JSON. |
| `-j N` / `--jobs N` | Process up to `N` targets in parallel (default scales with CPU and target count, capped at 32). Use `-j 1` for strictly sequential runs. |
| `-d DIR` / `--dump DIR` | Write one JSONL file per target under `DIR` with raw `record` payloads (same filters as the timeline). |
| `-kl KWS` / `--keyword-list` | Comma-separated keywords (substring, case-insensitive) across record fields, category, source function, and description. |
| `-kf FILE` / `--keyword-file` | One keyword per line (`#` comments and blank lines ignored); merged with `-kl`. |
| `-v` / `--verbose` | DEBUG logging; default is WARNING. |

## Artifacts by category and OS

Below is what the **shipped TOML** wires up. Exact availability depends on the image (plugins that do not apply or fail are skipped). **Walkfs** entries enumerate files under a root on the target filesystem. **Functions** are Dissect plugin methods. **Scenarios** (see `persistence_execution.toml` and others) swap in alternate descriptions when their filters match. Some function blocks use **`any_field_nonzero`** or **`field_contains`** (see `data_exfiltration.toml`): records are skipped unless those filters match (e.g. SRUM byte counters non-zero, or USN `reason` containing `ARCHIVE`).

### Persistence and execution (`--pe`)

**Windows** — functions include: `runkeys`, `services`, `tasks`, `userassist`, `appinit`, `bootshell`, `alternateshell`, `winlogon`, `startupinfo`, `shimcache`, `amcache`, `muicache`, `prefetch`, `powershell_history`, `usnjrnl`, `defender.quarantine`, `msoffice.startup`, `msoffice.native`, `msoffice.web`. Walkfs: `C:/Windows/System32/Tasks`, All Users Startup, `C:/Windows/Prefetch` (`*.pf`). Scenario: Run key commands containing PowerShell.

**Linux** — functions: `cronjobs`, `services`, `journal`, `bashhistory`, `commandhistory`, `openssh.authorized_keys`. Walkfs: `/etc/cron.d`, `/etc/cron.daily`, `/etc/systemd/system`, `/lib/systemd/system`, `/etc/init.d`, `/etc/rc.local`, `/etc/profile.d`, user `/home/**/.ssh/**`, `/root/**.ssh**`. Scenario: systemd unit name contains `.timer`.

**Additional Linux (code path, not TOML)**: full-filesystem YARA scan using bundled rules (`linux_implant_yara.yar`) via the `yara` plugin when `yara-python` is installed; matches are labeled in the timeline and enriched with `walkfs` metadata when practical.

**macOS** — functions: `commandhistory`, `bashhistory`, `openssh.authorized_keys`. Walkfs: `/Library/LaunchAgents`, `/Library/LaunchDaemons`, `/Library/StartupItems`, per-user LaunchAgents under `/Users`.

**Unix / BSD** — functions: `commandhistory`, `bashhistory`, `cronjobs`, `openssh.authorized_keys` (BSD block mirrors Unix-style keys where applicable). Walkfs: `/etc/periodic`, `/usr/local/etc/rc.d`.

### Lateral movement (`--lm`)

**Windows** — `remoteaccess`, `rdpcache.paths`, `mru.mstsc`, `openssh.authorized_keys`, `ual.client_access` (User Access Logging / incoming client usage); walkfs: `C:/Windows/System32/config/systemprofile/.ssh`. Scenario: remote access message mentions RDP.

**Linux** — `openssh.authorized_keys`, `openssh.known_hosts`, `remoteaccess`, `lastlog`, `wtmp`, `btmp`, `utmp`, `journal`; walkfs: `/etc/ssh`, `/home/**/.ssh/**`.

**macOS** — `openssh.authorized_keys`; walkfs: `/etc/ssh`.

**Unix** — `openssh.authorized_keys`, `openssh.known_hosts`; walkfs: `/etc/ssh`.

**BSD** — `openssh.authorized_keys`.

### Data access (`--da`)

**Windows** — `shellbags`, `mru.recentdocs`, `mru.msoffice`, `recentfilecache`, `recyclebin`, `sru.application_timeline`, `jumplist.automatic_destination`; walkfs: `C:/Users/**/Recent/**`, `C:/Windows/System32/winevt/Logs/*.evtx`.

**Linux** — `recently_used`, `commandhistory`; walkfs: `/var/log/auth.log*`, `/var/log/secure*`.

**macOS** — `recently_used`, `commandhistory`; walkfs: `/Users/**/Recent/**`.

**Unix** — `commandhistory`; walkfs: `/var/log/auth.log*`.

**BSD** — `commandhistory`.

### Data exfiltration (`--de`)

**Windows** — `browser.passwords`, `powershell_history`, `usnjrnl` (only if `reason` contains `ARCHIVE`), `sru.network_data` (only if `bytes_sent` or `bytes_recvd` ≠ 0), `sru.application_timeline` (only if `network_bytes_raw` ≠ 0). Walkfs: `C:/Users/**/Downloads/**`.

**Linux** — `commandhistory`; walkfs: `/tmp/**`.

**macOS** — `commandhistory`.

### Initial access (`--ia`)

**Windows** — `browser.history`, `browser.downloads`, `activitiescache` (Timeline / multi-app activity), `mru.opensave` (Open/Save dialog MRU for non-browser apps), `mru.run` (RunMRU / Win+R history; clickfix-relevant), `ual.client_access` (UAL inbound client / server-role access), `wget.hsts` (wget HSTS cache when present), unified web access logs: `iis.access`, `nginx.access`, `apache.access` (each only yields when that stack exists). Walkfs: per-user **`Downloads`**, and **`%LocalAppData%\Microsoft\Windows\INetCache\Content.Outlook`** under `C:/Users`.

**Linux** — `nginx.access`, `apache.access`, `caddy.access` (when those servers/logs are present), `wget.hsts`. Walkfs: **`/home/**/Downloads/**`**.

**macOS** — `browser.history`, `browser.downloads`, `wget.hsts`. Walkfs: **`/Users/**/Downloads/**`**.

## Output shape

Each timeline row includes: `timestamp`, `category`, `source_function`, `description`, `target` (target label), and `record_type` when known. Events are sorted by timestamp, then category and source.

## Roadmap

- Credential access  
- Defense evasion  

## License and upstream docs

Dissect is documented at [docs.dissect.tools](https://docs.dissect.tools). For available plugins and record layouts, use `target-query --list` and the per-plugin help on a machine with `dissect.target` installed.
