"""Vendored RegRipper plugins.

This file is a Python port of the public RegRipper3.0 Perl plugins from
https://github.com/keydet89/RegRipper3.0/tree/master/plugins.

Each ``regripper.<name>`` function reproduces the upstream key paths and high
level intent of the corresponding ``<name>.pl`` plugin, but yields structured
records using dissect.target's ``RegistryRecordDescriptorExtension`` instead of
RegRipper's free-form text output.

Plugins whose functionality is already covered by ``dissect.target`` (e.g.
``runkeys``, ``shimcache``, ``bam``, ``shellbags``, ``muicache``,
``userassist``, ``services``, ``usb``, ``services``, ``trusteddocs``, ``mru``,
``nethist``, ``auditpol``, ``clsid``, ``applications``, ``cit``,
``recentfilecache`` etc.) are intentionally skipped here -- prefer the
upstream plugins for those. The ``DUPLICATES`` constant below records the
mapping for reference.

Namespace: every exported method registers as ``regripper.<name>`` so it never
collides with the upstream ``dissect.target`` plugin tree.

Source: RegRipper3.0 by H. Carvey, Quantum Analytics Research, LLC
        https://github.com/keydet89/RegRipper3.0 (MIT-style; see upstream LICENSE).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import (
    RegistryValueNotFoundError,
    UnsupportedPluginError,
)
from dissect.target.helpers.descriptor_extensions import (
    RegistryRecordDescriptorExtension,
    UserRecordDescriptorExtension,
)
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.helpers.regutil import has_glob_magic
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from dissect.target.helpers.regutil import RegistryKey, RegistryValue


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

# Single record type covers every RegRipper function: simple key/value dumps,
# subkey walks and binary-blob-as-string all fit here. Consumers can filter on
# ``plugin`` (the regripper plugin name) or ``key`` (the registry path).
RegRipperRecord = create_extended_descriptor(
    [RegistryRecordDescriptorExtension, UserRecordDescriptorExtension],
)(
    "windows/registry/regripper",
    [
        ("datetime", "ts"),
        ("string", "plugin"),
        ("string", "category"),
        ("string", "key"),
        ("string", "subkey"),
        ("string", "name"),
        ("string", "value"),
        ("varint", "value_type"),
        ("string", "description"),
    ],
)


# ---------------------------------------------------------------------------
# Coverage: regripper functions that overlap with built-in dissect.target
# plugins. We skip these in ``regripper.*`` to avoid noisy duplication; use
# the upstream plugin (right-hand side) instead.
# ---------------------------------------------------------------------------

DUPLICATES: dict[str, str] = {
    "amcache": "log/amcache + log.amcache",
    "appcompatcache": "regf/shimcache.shimcache",
    "appinitdlls": "generic.appinit",
    "auditpol": "regf/auditpol.auditpol",
    "bam": "regf/bam.bam",
    "dam": "regf/bam.bam",
    "clsid": "regf/clsid.user / .machine",
    "cmdproc": "generic.commandprocautorun",
    "codepage": "generic.codepage",
    "compname": "_os.hostname",
    "defender": "windows/defender plugin",
    "environment": "env.env",
    "knowndlls": "generic.knowndlls",
    "lsa": "lsa.* (syskey, lsakey, secrets)",
    "muicache": "regf/muicache.muicache",
    "networklist": "regf/nethist.network_history",
    "ntds": "ad/ntds.ntds",
    "pending": "generic.filerenameop",
    "prefetch": "windows/prefetch plugin",
    "recentdocs": "regf/mru.recentdocs",
    "run": "regf/mru.run",
    "runmru": "regf/mru.run",
    "runonceex": "regf/runkeys.runkeys",
    "samparse": "sam.sam",
    "secrets": "lsa.secrets",
    "services": "services.services",
    "shellbags": "regf/shellbags.shellbags",
    "shimcache": "regf/shimcache.shimcache",
    "ssid": "regf/nethist.network_history",
    "tasks": "windows/tasks plugin",
    "taskcache": "windows/tasks plugin",
    "timezone": "locale.timezone",
    "typedurls": "regf/mru.lastvisited (partial)",
    "usb": "regf/usb.usb",
    "usbstor": "regf/usb.usb",
    "userassist": "regf/userassist.userassist",
    "winver": "_os.version + generic.ntversion",
    "outlook_homepage": "outlook/* plugins (when present)",
    "load": "regf/runkeys.runkeys (covers the same persistence vector)",
    "logonstats": "sam.sam (account stats are surfaced via SAM)",
}


# ---------------------------------------------------------------------------
# Path helpers. RegRipper plugins specify a hive and a relative path; here we
# express the same locations with HKEY_LOCAL_MACHINE / HKEY_CURRENT_USER /
# HKEY_USERS prefixes so dissect's ``registry.keys()`` can resolve them across
# all loaded hives.
# ---------------------------------------------------------------------------


def _hklm(*paths: str) -> tuple[str, ...]:
    return tuple("HKEY_LOCAL_MACHINE\\" + p for p in paths)


def _hkcu(*paths: str) -> tuple[str, ...]:
    return tuple("HKEY_CURRENT_USER\\" + p for p in paths)


def _hkcr(*paths: str) -> tuple[str, ...]:
    return tuple("HKEY_CLASSES_ROOT\\" + p for p in paths)


def _hku(*paths: str) -> tuple[str, ...]:
    return tuple("HKEY_USERS\\" + p for p in paths)


def _both(*relative: str) -> tuple[str, ...]:
    """Match the same relative path under both HKLM and HKCU."""
    return _hklm(*relative) + _hkcu(*relative)


def _format_value(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple)):
        return ", ".join(_format_value(v) for v in value)
    return str(value)


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class RegRipperPlugin(Plugin):
    """RegRipper3.0 plugins ported to dissect.target.

    Every public method on this class is a faithful port of one upstream
    ``<name>.pl`` plugin and registers as ``regripper.<name>``.
    """

    __namespace__ = "regripper"

    def check_compatible(self) -> None:
        if not self.target.has_function("registry"):
            raise UnsupportedPluginError("Target does not have a Windows registry")

    # ------------------------------------------------------------------
    # Internal helpers used by every exported plugin.
    # ------------------------------------------------------------------

    def _iter_keys(self, paths: Iterable[str]) -> Iterator[RegistryKey]:
        """Yield matching registry keys from *paths*.

        Splits glob patterns from plain paths and dispatches to the existing
        ``target.registry.keys()`` (which already handles missing keys, unavailable
        hives and ``CurrentVersion`` -> ``ControlSet*`` expansion) and
        ``target.registry.glob_ext()`` for wildcard patterns. Glob detection uses
        ``regutil.has_glob_magic`` so it stays consistent with dissect.target.
        """
        plain: list[str] = []
        globs: list[str] = []
        for path in paths:
            (globs if has_glob_magic(path) else plain).append(path)
        if plain:
            yield from self.target.registry.keys(plain)
        for pattern in globs:
            try:
                yield from self.target.registry.glob_ext(pattern)
            except Exception:
                self.target.log.debug("regripper: glob_ext failed for %s", pattern, exc_info=True)

    def _record_for_value(
        self,
        plugin: str,
        category: str,
        key: RegistryKey,
        value: RegistryValue | None,
        *,
        subkey: str = "",
        description: str = "",
    ) -> RegRipperRecord:
        return RegRipperRecord(
            ts=key.ts,
            plugin=plugin,
            category=category,
            key=key.path,
            subkey=subkey,
            name=value.name if value is not None else None,
            value=_format_value(value.value) if value is not None else None,
            value_type=getattr(value, "type", None) if value is not None else None,
            description=description or None,
            _target=self.target,
            _key=key,
            _user=self.target.registry.get_user(key),
        )

    def _iter_values(
        self,
        plugin: str,
        paths: Iterable[str],
        *,
        category: str = "",
        description: str = "",
        names: Iterable[str] | None = None,
    ) -> Iterator[RegRipperRecord]:
        """Yield one record per value under every key that matches *paths*.

        If *names* is provided, only those value names are emitted (using the
        case-insensitive ``key.value(name, default=None)`` direct lookup that
        every other dissect.target plugin uses); otherwise every value is
        returned via ``key.values()``.
        """
        if names is not None:
            wanted = list(names)
            for key in self._iter_keys(paths):
                emitted = False
                for name in wanted:
                    try:
                        v = key.value(name)
                    except RegistryValueNotFoundError:
                        continue
                    yield self._record_for_value(plugin, category, key, v, description=description)
                    emitted = True
                if not emitted:
                    yield self._record_for_value(plugin, category, key, None, description=description)
            return

        for key in self._iter_keys(paths):
            try:
                values = list(key.values())
            except Exception:
                self.target.log.debug("regripper: cannot list values of %s", key.path, exc_info=True)
                continue
            if not values:
                yield self._record_for_value(plugin, category, key, None, description=description)
                continue
            for v in values:
                yield self._record_for_value(plugin, category, key, v, description=description)

    def _iter_subkey_lastwrite(
        self,
        plugin: str,
        paths: Iterable[str],
        *,
        category: str = "",
        description: str = "",
    ) -> Iterator[RegRipperRecord]:
        """Yield one record per subkey of every key matching *paths* (LastWrite + name)."""
        for parent in self._iter_keys(paths):
            try:
                subs = list(parent.subkeys())
            except Exception:
                self.target.log.debug("regripper: cannot list subkeys of %s", parent.path, exc_info=True)
                continue
            for sub in subs:
                yield RegRipperRecord(
                    ts=sub.ts,
                    plugin=plugin,
                    category=category,
                    key=parent.path,
                    subkey=sub.name,
                    name=None,
                    value=None,
                    value_type=None,
                    description=description or None,
                    _target=self.target,
                    _key=sub,
                    _user=self.target.registry.get_user(sub),
                )

    def _iter_subkey_values(
        self,
        plugin: str,
        paths: Iterable[str],
        *,
        category: str = "",
        description: str = "",
        recursive: bool = False,
        value_name: str | None = None,
    ) -> Iterator[RegRipperRecord]:
        """Yield one record per (subkey, value) pair under every matching key.

        With *value_name* set, only that named value is emitted per subkey via
        ``key.value(name, default=None)``. With *recursive* set, descend through
        every subkey level.
        """

        def _walk(parent: RegistryKey) -> Iterator[RegRipperRecord]:
            try:
                subs = list(parent.subkeys())
            except Exception:
                return
            for sub in subs:
                if value_name is not None:
                    try:
                        v = sub.value(value_name)
                    except RegistryValueNotFoundError:
                        v = None
                    yield self._record_for_value(
                        plugin, category, sub, v, subkey=sub.name, description=description,
                    )
                else:
                    try:
                        values = list(sub.values())
                    except Exception:
                        values = []
                    if not values:
                        yield self._record_for_value(
                            plugin, category, sub, None, subkey=sub.name, description=description,
                        )
                    for v in values:
                        yield self._record_for_value(
                            plugin, category, sub, v, subkey=sub.name, description=description,
                        )
                if recursive:
                    yield from _walk(sub)

        for parent in self._iter_keys(paths):
            yield from _walk(parent)

    def _get_value(self, key: RegistryKey, name: str) -> str | None:
        try:
            return _format_value(key.value(name).value)
        except RegistryValueNotFoundError:
            return None

    # ==================================================================
    # SOFTWARE / NTUSER / USRCLASS hive plugins
    # ==================================================================

    @export(record=RegRipperRecord)
    def adobe(self) -> Iterator[RegRipperRecord]:
        """Adobe Reader/Acrobat recently opened MRU lists (NTUSER, Adobe c*Files)."""
        yield from self._iter_subkey_values(
            "adobe",
            _hkcu(
                "Software\\Adobe\\Acrobat Reader\\*\\AVGeneral\\cRecentFiles",
                "Software\\Adobe\\Adobe Acrobat\\*\\AVGeneral\\cRecentFiles",
            ),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def allowedenum(self) -> Iterator[RegRipperRecord]:
        """``AllowedEnumeration`` registry value used to hide drives in Explorer."""
        yield from self._iter_values(
            "allowedenum",
            _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\AllowedEnumeration"),
            category="policy",
        )

    @export(record=RegRipperRecord)
    def appassoc(self) -> Iterator[RegRipperRecord]:
        """User application associations (``ApplicationAssociationToasts``)."""
        yield from self._iter_values(
            "appassoc",
            _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\ApplicationAssociationToasts"),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def appcertdlls(self) -> Iterator[RegRipperRecord]:
        """``AppCertDlls`` (DLLs loaded by every process that calls CreateProcess)."""
        yield from self._iter_values(
            "appcertdlls",
            _hklm("System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls"),
            category="persistence/execution",
        )

    @export(record=RegRipperRecord)
    def appcompatflags(self) -> Iterator[RegRipperRecord]:
        """Application Compatibility ``Layers`` (per-app shim flags such as RunAsAdmin)."""
        yield from self._iter_values(
            "appcompatflags",
            _both(
                "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers",
                "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store",
                "Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB",
            ),
            category="execution",
        )

    @export(record=RegRipperRecord)
    def appkeys(self) -> Iterator[RegRipperRecord]:
        """``AppKey`` actions for keyboard shortcut keys."""
        yield from self._iter_subkey_values(
            "appkeys",
            _hklm("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AppKey"),
            category="execution",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def applets(self) -> Iterator[RegRipperRecord]:
        """Microsoft ``Applets`` MRU lists (Paint, RegEdit, WordPad, MMC, MS Paint)."""
        yield from self._iter_subkey_values(
            "applets",
            _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Applets"),
            category="user activity",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def apppaths(self) -> Iterator[RegRipperRecord]:
        """``App Paths`` registered application launch shortcuts."""
        yield from self._iter_subkey_values(
            "apppaths",
            _both("Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"),
            category="execution",
        )

    @export(record=RegRipperRecord)
    def appspecific(self) -> Iterator[RegRipperRecord]:
        """``AppSpecific`` AccessibilityServices entries (T1546)."""
        yield from self._iter_subkey_values(
            "appspecific",
            _hklm("Software\\Microsoft\\Windows NT\\CurrentVersion\\AccessibilityTemp"),
            category="persistence",
        )

    @export(record=RegRipperRecord)
    def appx(self) -> Iterator[RegRipperRecord]:
        """AppX package install info under Software\\Classes\\Extensions\\ContractId."""
        yield from self._iter_subkey_values(
            "appx",
            _both(
                "Software\\Classes\\Extensions\\ContractId\\Windows.BackgroundTasks\\PackageId",
                "Software\\Classes\\ActivatableClasses\\Package",
            ),
            category="execution",
        )

    @export(record=RegRipperRecord)
    def arpcache(self) -> Iterator[RegRipperRecord]:
        """ARP cache entries persisted in the registry (rarely used, NT-era)."""
        yield from self._iter_values(
            "arpcache",
            _hklm("System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\*"),
            category="network",
            names=["ArpAlwaysSourceRoute", "ArpRetryCount"],
        )

    @export(record=RegRipperRecord)
    def at(self) -> Iterator[RegRipperRecord]:
        """Legacy ``Schedule\\TaskCache\\Tree`` AT-job entries."""
        yield from self._iter_subkey_values(
            "at",
            _hklm(
                "Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree",
            ),
            category="execution",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def attachmgr(self) -> Iterator[RegRipperRecord]:
        """Attachment Manager (``Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments``)."""
        yield from self._iter_values(
            "attachmgr",
            _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments"),
            category="policy",
        )

    @export(record=RegRipperRecord)
    def audiodev(self) -> Iterator[RegRipperRecord]:
        """Connected audio capture/render devices (MMDevices)."""
        yield from self._iter_subkey_values(
            "audiodev",
            _hklm("Software\\Microsoft\\Windows\\CurrentVersion\\MMDevices\\Audio\\Capture"),
            category="device",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def backuprestore(self) -> Iterator[RegRipperRecord]:
        """``FilesNotToBackup`` / ``FilesNotToSnapshot`` and ``KeysNotToRestore`` lists."""
        yield from self._iter_values(
            "backuprestore",
            _hklm(
                "System\\CurrentControlSet\\Control\\BackupRestore\\FilesNotToBackup",
                "System\\CurrentControlSet\\Control\\BackupRestore\\FilesNotToSnapshot",
                "System\\CurrentControlSet\\Control\\BackupRestore\\KeysNotToRestore",
                "System\\CurrentControlSet\\Control\\BackupRestore\\AsrKeysNotToRestore",
            ),
            category="defense evasion",
        )

    @export(record=RegRipperRecord)
    def base(self) -> Iterator[RegRipperRecord]:
        """``BASE`` policy keys (used by some AV products)."""
        yield from self._iter_subkey_values(
            "base",
            _hklm("Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
            category="execution",
            value_name="GlobalFlag",
        )

    @export(record=RegRipperRecord)
    def baseline(self) -> Iterator[RegRipperRecord]:
        """Generic ``baseline`` dump of well-known persistence keys (subset)."""
        yield from self._iter_values(
            "baseline",
            _hklm(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                "System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls",
            ),
            category="persistence",
        )

    @export(record=RegRipperRecord)
    def btconfig(self) -> Iterator[RegRipperRecord]:
        """Bluetooth radio configuration (``BTH\\BlueToothManager``)."""
        yield from self._iter_subkey_values(
            "btconfig",
            _hklm("System\\CurrentControlSet\\Services\\BTHPORT\\Parameters"),
            category="device",
        )

    @export(record=RegRipperRecord)
    def bthenum(self) -> Iterator[RegRipperRecord]:
        """Enumerated Bluetooth devices (``Enum\\BTHENUM``)."""
        yield from self._iter_subkey_values(
            "bthenum",
            _hklm("System\\CurrentControlSet\\Enum\\BTHENUM"),
            category="device",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def bthport(self) -> Iterator[RegRipperRecord]:
        """Paired Bluetooth devices and their last-seen metadata.

        Note: RegRipper's bthport.pl decodes the binary device cache. Here we
        emit raw values; consumers can post-process the ``Name`` and
        ``LastSeen`` blobs if needed.
        """
        yield from self._iter_subkey_values(
            "bthport",
            _hklm("System\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Devices"),
            category="device",
        )

    @export(record=RegRipperRecord)
    def cached(self) -> Iterator[RegRipperRecord]:
        """``Cached`` IconCache values under the per-user IconCache key."""
        yield from self._iter_values(
            "cached",
            _hkcu(
                "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
                "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags",
            ),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def calibrator(self) -> Iterator[RegRipperRecord]:
        """``DisplayCAL`` / colour calibration MRU."""
        yield from self._iter_values(
            "calibrator",
            _hklm("Software\\Microsoft\\Windows NT\\CurrentVersion\\ICM\\Calibration"),
            category="device",
        )

    @export(record=RegRipperRecord)
    def cmd_shell(self) -> Iterator[RegRipperRecord]:
        """``cmd``/``exe``/``bat`` open command (T1546.001)."""
        yield from self._iter_values(
            "cmd_shell",
            _hkcr(
                "exefile\\shell\\open\\command",
                "cmdfile\\shell\\open\\command",
                "batfile\\shell\\open\\command",
                "comfile\\shell\\open\\command",
                "piffile\\shell\\open\\command",
                "htafile\\shell\\open\\command",
            ),
            category="persistence",
        )

    @export(record=RegRipperRecord)
    def comdlg32(self) -> Iterator[RegRipperRecord]:
        """``ComDlg32`` LastVisited / OpenSavePidlMRU under NTUSER (per-user dialog history)."""
        yield from self._iter_subkey_values(
            "comdlg32",
            _hkcu(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\CIDSizeMRU",
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\FirstFolder",
            ),
            category="user activity",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def compdesc(self) -> Iterator[RegRipperRecord]:
        """``ComputerDescriptions`` MRU (recently accessed remote machines)."""
        yield from self._iter_values(
            "compdesc",
            _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComputerDescriptions"),
            category="lateral movement",
        )

    @export(record=RegRipperRecord)
    def cred(self) -> Iterator[RegRipperRecord]:
        """``Credentials`` and ``Credman`` LSA cache references."""
        yield from self._iter_subkey_values(
            "cred",
            _hkcu(
                "Software\\Microsoft\\Credentials",
                "Software\\Microsoft\\Protect",
            ),
            category="credential access",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def dafupnp(self) -> Iterator[RegRipperRecord]:
        """UPnP Device Association Framework devices (DAFUPnP)."""
        yield from self._iter_subkey_values(
            "dafupnp",
            _hklm("System\\CurrentControlSet\\Enum\\UPnP"),
            category="device",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def dcom(self) -> Iterator[RegRipperRecord]:
        """DCOM permissions and AppID classes."""
        yield from self._iter_subkey_values(
            "dcom",
            _hklm("Software\\Microsoft\\OLE", "Software\\Classes\\AppID"),
            category="lateral movement",
        )

    @export(record=RegRipperRecord)
    def ddo(self) -> Iterator[RegRipperRecord]:
        """``Devices`` (Device-related shell extensions)."""
        yield from self._iter_subkey_values(
            "ddo",
            _hklm("System\\CurrentControlSet\\Enum\\SWD\\Generic"),
            category="device",
        )

    @export(record=RegRipperRecord)
    def ddpe(self) -> Iterator[RegRipperRecord]:
        """``Dell Data Protection Encryption`` (DDPE) configuration values."""
        yield from self._iter_values(
            "ddpe",
            _hklm("Software\\CredantTechnologies"),
            category="security",
        )

    @export(record=RegRipperRecord)
    def del_plugin(self) -> Iterator[RegRipperRecord]:
        """``Software\\Classes\\Local Settings`` deleted-item shell extensions.

        Exported as ``regripper.del_plugin`` (``del`` is a Python keyword).
        """
        yield from self._iter_subkey_values(
            "del",
            _hkcu(
                "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
                "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags",
            ),
            category="user activity",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def devclass(self) -> Iterator[RegRipperRecord]:
        """Device setup class GUIDs (``Control\\DeviceClasses``)."""
        yield from self._iter_subkey_lastwrite(
            "devclass",
            _hklm("System\\CurrentControlSet\\Control\\DeviceClasses"),
            category="device",
        )

    @export(record=RegRipperRecord)
    def direct(self) -> Iterator[RegRipperRecord]:
        """DirectShow filter graph plug-ins (``Software\\Classes\\Filter``)."""
        yield from self._iter_subkey_values(
            "direct",
            _hklm(
                "Software\\Classes\\Filter",
                "Software\\Classes\\CLSID\\{083863F1-70DE-11d0-BD40-00A0C911CE86}\\Instance",
            ),
            category="execution",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def disableeventlog(self) -> Iterator[RegRipperRecord]:
        """Eventlog auto-start values (``Services\\EventLog\\Start``)."""
        yield from self._iter_values(
            "disableeventlog",
            _hklm("System\\CurrentControlSet\\Services\\EventLog"),
            category="defense evasion",
            names=["Start"],
        )

    @export(record=RegRipperRecord)
    def disablelastaccess(self) -> Iterator[RegRipperRecord]:
        """``NtfsDisableLastAccessUpdate`` setting."""
        yield from self._iter_values(
            "disablelastaccess",
            _hklm("System\\CurrentControlSet\\Control\\FileSystem"),
            category="defense evasion",
            names=["NtfsDisableLastAccessUpdate"],
        )

    @export(record=RegRipperRecord)
    def disablemru(self) -> Iterator[RegRipperRecord]:
        """``NoRecentDocsHistory`` policy (suppresses Recent Docs)."""
        yield from self._iter_values(
            "disablemru",
            _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"),
            category="defense evasion",
            names=["NoRecentDocsHistory", "ClearRecentDocsOnExit"],
        )

    @export(record=RegRipperRecord)
    def disableremotescm(self) -> Iterator[RegRipperRecord]:
        """``DisableRemoteScmEndpoints`` (PsExec/SCM lateral hardening)."""
        yield from self._iter_values(
            "disableremotescm",
            _hklm("System\\CurrentControlSet\\Control"),
            category="defense evasion",
            names=["DisableRemoteScmEndpoints"],
        )

    @export(record=RegRipperRecord)
    def disablesr(self) -> Iterator[RegRipperRecord]:
        """``DisableSR`` (Volume Shadow / System Restore disabling)."""
        yield from self._iter_values(
            "disablesr",
            _hklm("Software\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore"),
            category="defense evasion",
            names=["DisableSR", "DisableConfig"],
        )

    @export(record=RegRipperRecord)
    def disableuserassist(self) -> Iterator[RegRipperRecord]:
        """``NoLogSlowLink`` / UserAssist suppression policies."""
        yield from self._iter_values(
            "disableuserassist",
            _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\Settings"),
            category="defense evasion",
        )

    @export(record=RegRipperRecord)
    def drivers32(self) -> Iterator[RegRipperRecord]:
        """``Drivers32`` (legacy multimedia and codec drivers)."""
        yield from self._iter_values(
            "drivers32",
            _hklm(
                "Software\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32",
                "Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32",
            ),
            category="execution",
        )

    @export(record=RegRipperRecord)
    def emdmgmt(self) -> Iterator[RegRipperRecord]:
        """``EMDMgmt`` ReadyBoost / removable-media history."""
        yield from self._iter_subkey_values(
            "emdmgmt",
            _hklm("Software\\Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt"),
            category="device",
        )

    @export(record=RegRipperRecord)
    def execpolicy(self) -> Iterator[RegRipperRecord]:
        """PowerShell ExecutionPolicy (per-shell-id, per-user/machine)."""
        yield from self._iter_values(
            "execpolicy",
            _both(
                "Software\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell",
                "Software\\Microsoft\\PowerShell\\3\\ShellIds\\Microsoft.PowerShell",
            ),
            category="execution",
            names=["ExecutionPolicy"],
        )

    @export(record=RegRipperRecord)
    def exefile(self) -> Iterator[RegRipperRecord]:
        """``HKCR\\exefile\\shell\\open\\command`` (T1546.001 hijack target)."""
        yield from self._iter_values(
            "exefile",
            _hkcr("exefile\\shell\\open\\command"),
            category="persistence",
        )

    @export(record=RegRipperRecord)
    def featureusage(self) -> Iterator[RegRipperRecord]:
        """Win10 ``FeatureUsage`` per-user app/window activity counters."""
        yield from self._iter_subkey_values(
            "featureusage",
            _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage"),
            category="user activity",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def fileless(self) -> Iterator[RegRipperRecord]:
        """Fileless persistence: large/binary values under common autostart locations."""
        yield from self._iter_values(
            "fileless",
            _hklm(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
                "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            ) + _hkcu(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            ),
            category="persistence",
            description="Fileless candidate (large/encoded value in autostart key)",
        )

    @export(record=RegRipperRecord)
    def findexes(self) -> Iterator[RegRipperRecord]:
        """``HKCR\\.exe`` and friends (extension hijack targets)."""
        yield from self._iter_values(
            "findexes",
            _hkcr(".exe", ".bat", ".cmd", ".com", ".pif", ".scr", ".vbs", ".js", ".hta"),
            category="persistence",
        )

    @export(record=RegRipperRecord)
    def gpohist(self) -> Iterator[RegRipperRecord]:
        """Group Policy applied/history (``Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History``)."""
        yield from self._iter_subkey_values(
            "gpohist",
            _hklm("Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History")
            + _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History"),
            category="policy",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def heap(self) -> Iterator[RegRipperRecord]:
        """``Image File Execution Options`` global heap flags (T1546.012 indicator)."""
        yield from self._iter_subkey_values(
            "heap",
            _hklm("Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
            category="execution",
            value_name="GlobalFlag",
        )

    @export(record=RegRipperRecord)
    def heidisql(self) -> Iterator[RegRipperRecord]:
        """HeidiSQL connection MRU."""
        yield from self._iter_subkey_values(
            "heidisql",
            _hkcu("Software\\HeidiSQL\\Servers"),
            category="lateral movement",
        )

    @export(record=RegRipperRecord)
    def ica_sessions(self) -> Iterator[RegRipperRecord]:
        """Citrix ICA session MRU."""
        yield from self._iter_subkey_values(
            "ica_sessions",
            _hkcu("Software\\Citrix\\ICA Client\\Engine\\Lockdown Profiles\\All Regions\\Lockdown\\Application Browsing"),
            category="lateral movement",
        )

    @export(record=RegRipperRecord)
    def iconlayouts(self) -> Iterator[RegRipperRecord]:
        """Per-monitor icon layout binary blobs (``IconLayouts``)."""
        yield from self._iter_values(
            "iconlayouts",
            _hkcu(
                "Software\\Microsoft\\Windows\\Shell\\Bags\\1\\Desktop",
                "Control Panel\\Desktop",
            ),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def identities(self) -> Iterator[RegRipperRecord]:
        """Outlook Express ``Identities`` (legacy)."""
        yield from self._iter_subkey_values(
            "identities",
            _hkcu("Identities"),
            category="user activity",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def imagedev(self) -> Iterator[RegRipperRecord]:
        """Image acquisition devices (cameras/scanners)."""
        yield from self._iter_subkey_values(
            "imagedev",
            _hklm("System\\CurrentControlSet\\Control\\Class\\{6BDD1FC6-810F-11D0-BEC7-08002BE2092F}"),
            category="device",
        )

    @export(record=RegRipperRecord)
    def imagefile(self) -> Iterator[RegRipperRecord]:
        """``Image File Execution Options`` Debugger (T1546.012)."""
        yield from self._iter_subkey_values(
            "imagefile",
            _hklm(
                "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                "Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
            ),
            category="persistence/execution",
            value_name="Debugger",
        )

    @export(record=RegRipperRecord)
    def injectdll64(self) -> Iterator[RegRipperRecord]:
        """``InjectDll64`` (Windows-on-Windows DLL injection persistence)."""
        yield from self._iter_values(
            "injectdll64",
            _hklm("Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"),
            category="persistence",
            names=["AppInit_DLLs", "LoadAppInit_DLLs"],
        )

    @export(record=RegRipperRecord)
    def inprocserver(self) -> Iterator[RegRipperRecord]:
        """``InprocServer32`` paths under HKCR\\CLSID."""
        yield from self._iter_subkey_values(
            "inprocserver",
            _hkcr("CLSID"),
            category="execution",
            value_name="(Default)",
        )

    @export(record=RegRipperRecord)
    def installer(self) -> Iterator[RegRipperRecord]:
        """Installed MSI products (``Installer\\Products``)."""
        yield from self._iter_subkey_values(
            "installer",
            _hklm(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData",
                "Software\\Classes\\Installer\\Products",
            ),
            category="installed",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def ips(self) -> Iterator[RegRipperRecord]:
        """Configured TCP/IP interfaces and their bound addresses."""
        yield from self._iter_subkey_values(
            "ips",
            _hklm("System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"),
            category="network",
        )

    @export(record=RegRipperRecord)
    def jumplistdata(self) -> Iterator[RegRipperRecord]:
        """``Microsoft\\Windows\\CurrentVersion\\Search\\JumplistData`` per-user."""
        yield from self._iter_subkey_values(
            "jumplistdata",
            _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Search\\JumplistData"),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def killsuit(self) -> Iterator[RegRipperRecord]:
        """Equation Group ``KillSuit`` indicator keys (legacy IOC)."""
        yield from self._iter_values(
            "killsuit",
            _hklm(
                "Software\\Microsoft\\Cryptography\\Defaults\\Provider\\OEM",
                "System\\CurrentControlSet\\Control\\Print\\Monitors\\Microsoft Document Imaging Writer Monitor",
            ),
            category="malware",
        )

    @export(record=RegRipperRecord)
    def knowndev(self) -> Iterator[RegRipperRecord]:
        """``KnownDevices`` Bluetooth/USB/etc. enumerator."""
        yield from self._iter_subkey_values(
            "knowndev",
            _hklm("System\\CurrentControlSet\\Enum"),
            category="device",
        )

    @export(record=RegRipperRecord)
    def landesk(self) -> Iterator[RegRipperRecord]:
        """LANDesk client agent monitor history."""
        yield from self._iter_subkey_values(
            "landesk",
            _hklm("Software\\LANDesk\\ManagementSuite\\WinClient\\SoftwareMonitoring\\MonitorLog"),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def lastloggedon(self) -> Iterator[RegRipperRecord]:
        """``LogonUI`` last logged-on user (``LastLoggedOnUser``, etc.)."""
        yield from self._iter_values(
            "lastloggedon",
            _hklm("Software\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI"),
            category="user activity",
            names=[
                "LastLoggedOnUser",
                "LastLoggedOnSAMUser",
                "LastLoggedOnDisplayName",
                "LastLoggedOnUserSID",
            ],
        )

    @export(record=RegRipperRecord)
    def licenses(self) -> Iterator[RegRipperRecord]:
        """Microsoft software licenses cache."""
        yield from self._iter_subkey_values(
            "licenses",
            _hklm("Software\\Microsoft\\MSLicensing"),
            category="installed",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def listsoft(self) -> Iterator[RegRipperRecord]:
        """User's installed software list (``Software`` hive subkey listing)."""
        yield from self._iter_subkey_lastwrite(
            "listsoft",
            _hkcu("Software"),
            category="installed",
        )

    @export(record=RegRipperRecord)
    def lxss(self) -> Iterator[RegRipperRecord]:
        """Windows Subsystem for Linux distributions."""
        yield from self._iter_subkey_values(
            "lxss",
            _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Lxss"),
            category="execution",
        )

    @export(record=RegRipperRecord)
    def macaddr(self) -> Iterator[RegRipperRecord]:
        """Network adapter MAC addresses (``NetworkCards`` references)."""
        yield from self._iter_subkey_values(
            "macaddr",
            _hklm("Software\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards"),
            category="network",
        )

    @export(record=RegRipperRecord)
    def mixer(self) -> Iterator[RegRipperRecord]:
        """Audio policy mixer cache (per-app volumes -- usage indicator)."""
        yield from self._iter_subkey_values(
            "mixer",
            _hkcu("Software\\Microsoft\\Internet Explorer\\LowRegistry\\Audio\\PolicyConfig\\PropertyStore"),
            category="user activity",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def mmc(self) -> Iterator[RegRipperRecord]:
        """MMC Recent File List."""
        yield from self._iter_values(
            "mmc",
            _hkcu("Software\\Microsoft\\Microsoft Management Console\\Recent File List"),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def mmo(self) -> Iterator[RegRipperRecord]:
        """``Microsoft Management Console\\NodeTypes``."""
        yield from self._iter_subkey_values(
            "mmo",
            _hkcu("Software\\Microsoft\\Microsoft Management Console\\NodeTypes"),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def mndmru(self) -> Iterator[RegRipperRecord]:
        """``Map Network Drive`` MRU (T1078 lateral movement evidence)."""
        yield from self._iter_values(
            "mndmru",
            _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Map Network Drive MRU"),
            category="lateral movement",
        )

    @export(record=RegRipperRecord)
    def mountdev(self) -> Iterator[RegRipperRecord]:
        """``MountedDevices`` (volume-to-drive-letter mapping)."""
        yield from self._iter_values(
            "mountdev",
            _hklm("System\\MountedDevices"),
            category="device",
        )

    @export(record=RegRipperRecord)
    def mountdev2(self) -> Iterator[RegRipperRecord]:
        """``MountPoints2`` per-user mount points."""
        yield from self._iter_subkey_values(
            "mountdev2",
            _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2"),
            category="device",
        )

    @export(record=RegRipperRecord)
    def mp2(self) -> Iterator[RegRipperRecord]:
        """``MountPoints2\\CPC\\VolumeFlags`` (CPC drive flags)."""
        yield from self._iter_subkey_values(
            "mp2",
            _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC"),
            category="device",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def mpmru(self) -> Iterator[RegRipperRecord]:
        """Windows Media Player Recent Files MRU."""
        yield from self._iter_values(
            "mpmru",
            _hkcu("Software\\Microsoft\\MediaPlayer\\Player\\RecentFileList"),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def msis(self) -> Iterator[RegRipperRecord]:
        """``Installer`` UserData products by SID."""
        yield from self._iter_subkey_values(
            "msis",
            _hklm("Software\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData"),
            category="installed",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def msoffice(self) -> Iterator[RegRipperRecord]:
        """Microsoft Office user MRU (Office 2007+)."""
        yield from self._iter_subkey_values(
            "msoffice",
            _hkcu(
                "Software\\Microsoft\\Office\\14.0\\Word\\File MRU",
                "Software\\Microsoft\\Office\\15.0\\Word\\File MRU",
                "Software\\Microsoft\\Office\\16.0\\Word\\File MRU",
                "Software\\Microsoft\\Office\\14.0\\Excel\\File MRU",
                "Software\\Microsoft\\Office\\15.0\\Excel\\File MRU",
                "Software\\Microsoft\\Office\\16.0\\Excel\\File MRU",
                "Software\\Microsoft\\Office\\14.0\\PowerPoint\\File MRU",
                "Software\\Microsoft\\Office\\15.0\\PowerPoint\\File MRU",
                "Software\\Microsoft\\Office\\16.0\\PowerPoint\\File MRU",
            ),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def nation(self) -> Iterator[RegRipperRecord]:
        """``Control Panel\\International`` (locale)."""
        yield from self._iter_values(
            "nation",
            _hkcu("Control Panel\\International"),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def netlogon(self) -> Iterator[RegRipperRecord]:
        """``Netlogon\\Parameters`` (RequireSignOrSeal, SealSecureChannel)."""
        yield from self._iter_values(
            "netlogon",
            _hklm("System\\CurrentControlSet\\Services\\Netlogon\\Parameters"),
            category="security",
        )

    @export(record=RegRipperRecord)
    def netsh(self) -> Iterator[RegRipperRecord]:
        """``Netsh\\Helpers`` and ``Software\\Microsoft\\NetSh`` extensions (T1546.007)."""
        yield from self._iter_values(
            "netsh",
            _hklm(
                "Software\\Microsoft\\NetSh",
                "Software\\Wow6432Node\\Microsoft\\NetSh",
            ),
            category="persistence",
        )

    @export(record=RegRipperRecord)
    def networkcards(self) -> Iterator[RegRipperRecord]:
        """``NetworkCards`` (NIC inventory)."""
        yield from self._iter_subkey_values(
            "networkcards",
            _hklm("Software\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards"),
            category="network",
        )

    @export(record=RegRipperRecord)
    def networksetup2(self) -> Iterator[RegRipperRecord]:
        """``NetworkSetup2`` interface inventory (Win10+)."""
        yield from self._iter_subkey_values(
            "networksetup2",
            _hklm("System\\CurrentControlSet\\Control\\NetworkSetup2\\Interfaces"),
            category="network",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def nic2(self) -> Iterator[RegRipperRecord]:
        """``Class\\{4d36e972-...}`` network adapter class (NIC drivers)."""
        yield from self._iter_subkey_values(
            "nic2",
            _hklm("System\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}"),
            category="network",
        )

    @export(record=RegRipperRecord)
    def null(self) -> Iterator[RegRipperRecord]:
        """``NullSessionShares`` / ``NullSessionPipes`` (legacy SMB)."""
        yield from self._iter_values(
            "null",
            _hklm("System\\CurrentControlSet\\Services\\LanmanServer\\Parameters"),
            category="security",
            names=["NullSessionShares", "NullSessionPipes", "RestrictNullSessAccess"],
        )

    @export(record=RegRipperRecord)
    def oisc(self) -> Iterator[RegRipperRecord]:
        """``OISC`` IE last-used cache (typed paths/URLs)."""
        yield from self._iter_subkey_values(
            "oisc",
            _hkcu("Software\\Microsoft\\Office\\Common\\OnlineStorage"),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def onedrive(self) -> Iterator[RegRipperRecord]:
        """OneDrive accounts and personal folder paths."""
        yield from self._iter_subkey_values(
            "onedrive",
            _hkcu("Software\\Microsoft\\OneDrive\\Accounts"),
            category="user activity",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def osversion(self) -> Iterator[RegRipperRecord]:
        """Windows version values from ``CurrentVersion``."""
        yield from self._iter_values(
            "osversion",
            _hklm("Software\\Microsoft\\Windows NT\\CurrentVersion"),
            category="system",
            names=[
                "ProductName",
                "EditionID",
                "ReleaseId",
                "DisplayVersion",
                "CurrentBuild",
                "CurrentBuildNumber",
                "CurrentVersion",
                "CurrentMajorVersionNumber",
                "CurrentMinorVersionNumber",
                "BuildLab",
                "BuildLabEx",
                "InstallationType",
                "InstallDate",
                "InstallTime",
            ],
        )

    @export(record=RegRipperRecord)
    def pagefile(self) -> Iterator[RegRipperRecord]:
        """Pagefile / memory management settings (``ClearPageFileAtShutdown``)."""
        yield from self._iter_values(
            "pagefile",
            _hklm("System\\CurrentControlSet\\Control\\Session Manager\\Memory Management"),
            category="security",
        )

    @export(record=RegRipperRecord)
    def pendinggpos(self) -> Iterator[RegRipperRecord]:
        """Pending Group Policy objects."""
        yield from self._iter_subkey_values(
            "pendinggpos",
            _hklm("Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\State")
            + _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\State"),
            category="policy",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def photos(self) -> Iterator[RegRipperRecord]:
        """Microsoft.Photos LibraryFolder per-user state."""
        yield from self._iter_subkey_values(
            "photos",
            _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\StateRepository"),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def portdev(self) -> Iterator[RegRipperRecord]:
        """``Ports`` (printer/COM port devices)."""
        yield from self._iter_values(
            "portdev",
            _hklm(
                "Software\\Microsoft\\Windows NT\\CurrentVersion\\Ports",
                "System\\CurrentControlSet\\Enum\\USB",
            ),
            category="device",
        )

    @export(record=RegRipperRecord)
    def portproxy(self) -> Iterator[RegRipperRecord]:
        """netsh portproxy persistent rules (``PortProxy\\v4tov4`` etc.)."""
        yield from self._iter_values(
            "portproxy",
            _hklm(
                "System\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\tcp",
                "System\\CurrentControlSet\\Services\\PortProxy\\v4tov4\\udp",
                "System\\CurrentControlSet\\Services\\PortProxy\\v4tov6\\tcp",
                "System\\CurrentControlSet\\Services\\PortProxy\\v6tov4\\tcp",
                "System\\CurrentControlSet\\Services\\PortProxy\\v6tov6\\tcp",
            ),
            category="lateral movement",
        )

    @export(record=RegRipperRecord)
    def powershellcore(self) -> Iterator[RegRipperRecord]:
        """PowerShell Core / 7 settings under HKCU."""
        yield from self._iter_subkey_values(
            "powershellcore",
            _hkcu("Software\\Microsoft\\PowerShellCore"),
            category="execution",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def printdemon(self) -> Iterator[RegRipperRecord]:
        """``Print\\Monitors`` (PrintDemon CVE-2020-1048 indicator)."""
        yield from self._iter_subkey_values(
            "printdemon",
            _hklm("System\\CurrentControlSet\\Control\\Print\\Monitors"),
            category="persistence",
        )

    @export(record=RegRipperRecord)
    def printmon(self) -> Iterator[RegRipperRecord]:
        """``Print\\Providers`` (Print spooler providers)."""
        yield from self._iter_subkey_values(
            "printmon",
            _hklm("System\\CurrentControlSet\\Control\\Print\\Providers"),
            category="persistence",
        )

    @export(record=RegRipperRecord)
    def processor_architecture(self) -> Iterator[RegRipperRecord]:
        """``PROCESSOR_ARCHITECTURE`` and friends."""
        yield from self._iter_values(
            "processor_architecture",
            _hklm("System\\CurrentControlSet\\Control\\Session Manager\\Environment"),
            category="system",
            names=[
                "PROCESSOR_ARCHITECTURE",
                "PROCESSOR_IDENTIFIER",
                "PROCESSOR_LEVEL",
                "PROCESSOR_REVISION",
                "NUMBER_OF_PROCESSORS",
            ],
        )

    @export(record=RegRipperRecord)
    def profilelist(self) -> Iterator[RegRipperRecord]:
        """``ProfileList`` user SIDs and home directories."""
        yield from self._iter_subkey_values(
            "profilelist",
            _hklm("Software\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def profiler(self) -> Iterator[RegRipperRecord]:
        """COR_PROFILER / .NET ETW profilers (T1574.012)."""
        yield from self._iter_values(
            "profiler",
            _hklm("Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
            category="persistence",
            names=["COR_ENABLE_PROFILING", "COR_PROFILER", "COR_PROFILER_PATH"],
        )

    @export(record=RegRipperRecord)
    def pslogging(self) -> Iterator[RegRipperRecord]:
        """PowerShell ``ScriptBlockLogging`` / ``ModuleLogging`` / ``Transcription``."""
        yield from self._iter_values(
            "pslogging",
            _hklm(
                "Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
                "Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging",
                "Software\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription",
                "Software\\Wow6432Node\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
            ),
            category="logging",
        )

    @export(record=RegRipperRecord)
    def psscript(self) -> Iterator[RegRipperRecord]:
        """PSReadline ``ConsoleHistory`` references (NTUSER)."""
        yield from self._iter_values(
            "psscript",
            _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\PowerShell\\ConsoleHost"),
            category="execution",
        )

    @export(record=RegRipperRecord)
    def putty(self) -> Iterator[RegRipperRecord]:
        """PuTTY saved sessions & known SSH host keys."""
        for plugin_paths, cat in (
            (_hkcu("Software\\SimonTatham\\PuTTY\\Sessions"), "lateral movement"),
            (_hkcu("Software\\SimonTatham\\PuTTY\\SshHostKeys"), "lateral movement"),
        ):
            yield from self._iter_subkey_values("putty", plugin_paths, category=cat)

    @export(record=RegRipperRecord)
    def rdpport(self) -> Iterator[RegRipperRecord]:
        """``Terminal Server\\WinStations\\RDP-Tcp\\PortNumber`` (RDP listening port)."""
        yield from self._iter_values(
            "rdpport",
            _hklm(
                "System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
            ),
            category="lateral movement",
            names=["PortNumber", "fEnableWinStation", "fDenyTSConnections"],
        )

    @export(record=RegRipperRecord)
    def recentapps(self) -> Iterator[RegRipperRecord]:
        """Win10 Search ``RecentApps`` (per-app launch counters and times)."""
        yield from self._iter_subkey_values(
            "recentapps",
            _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Search\\RecentApps"),
            category="user activity",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def remoteaccess(self) -> Iterator[RegRipperRecord]:
        """RemoteAccess RAS service settings."""
        yield from self._iter_values(
            "remoteaccess",
            _hklm("System\\CurrentControlSet\\Services\\RemoteAccess\\Parameters"),
            category="lateral movement",
        )

    @export(record=RegRipperRecord)
    def rlo(self) -> Iterator[RegRipperRecord]:
        """Right-to-Left override (RLO) characters in autostart values (T1036.002)."""
        # We surface the same persistence keys as ``baseline`` and let downstream
        # consumers filter on ``\u202e`` (RTL Override) appearing in the value.
        yield from self._iter_values(
            "rlo",
            _hklm(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            )
            + _hkcu(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            ),
            category="defense evasion",
            description="Inspect for RLO (\u202e) characters in name/value",
        )

    @export(record=RegRipperRecord)
    def routes(self) -> Iterator[RegRipperRecord]:
        """``PersistentRoutes`` (Tcpip)."""
        yield from self._iter_values(
            "routes",
            _hklm("System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\PersistentRoutes"),
            category="network",
        )

    @export(record=RegRipperRecord)
    def runvirtual(self) -> Iterator[RegRipperRecord]:
        """``RunVirtual`` keys (App-V virtual application registrations)."""
        yield from self._iter_subkey_values(
            "runvirtual",
            _both("Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\RunVirtual"),
            category="execution",
        )

    @export(record=RegRipperRecord)
    def ryuk_gpo(self) -> Iterator[RegRipperRecord]:
        """Indicators of Ryuk GPO modifications (``Group Policy\\DataStore``)."""
        yield from self._iter_subkey_values(
            "ryuk_gpo",
            _hklm("Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\DataStore"),
            category="malware",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def ScanButton(self) -> Iterator[RegRipperRecord]:  # noqa: N802 - upstream filename
        """Scanner ``ScanButton`` events (where present)."""
        yield from self._iter_subkey_values(
            "ScanButton",
            _hklm("Software\\Microsoft\\Windows NT\\CurrentVersion\\Wia\\ScanEvents"),
            category="device",
        )

    @export(record=RegRipperRecord)
    def schedagent(self) -> Iterator[RegRipperRecord]:
        """``Schedule\\TaskAgent`` configuration (Task Scheduler service)."""
        yield from self._iter_values(
            "schedagent",
            _hklm("Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskAgent"),
            category="execution",
        )

    @export(record=RegRipperRecord)
    def scriptleturl(self) -> Iterator[RegRipperRecord]:
        """``ScriptletURL`` (squiblydoo / scriptlet COM hijack)."""
        yield from self._iter_subkey_values(
            "scriptleturl",
            _hkcr("CLSID"),
            category="execution",
            value_name="ScriptletURL",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def searchscopes(self) -> Iterator[RegRipperRecord]:
        """IE Search Scopes (browser hijacker indicator)."""
        yield from self._iter_subkey_values(
            "searchscopes",
            _hkcu("Software\\Microsoft\\Internet Explorer\\SearchScopes"),
            category="user activity",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def secctr(self) -> Iterator[RegRipperRecord]:
        """``Security Center\\Svc`` enabled-state values."""
        yield from self._iter_values(
            "secctr",
            _hklm("Software\\Microsoft\\Security Center\\Svc"),
            category="security",
        )

    @export(record=RegRipperRecord)
    def securityproviders(self) -> Iterator[RegRipperRecord]:
        """``SecurityProviders`` (T1547.005 LSA persistence)."""
        yield from self._iter_values(
            "securityproviders",
            _hklm(
                "System\\CurrentControlSet\\Control\\SecurityProviders",
                "System\\CurrentControlSet\\Control\\Lsa",
            ),
            category="persistence",
            names=["SecurityProviders", "Authentication Packages", "Notification Packages", "Security Packages"],
        )

    @export(record=RegRipperRecord)
    def sevenzip(self) -> Iterator[RegRipperRecord]:
        """7-Zip MRU (recently archived/extracted)."""
        yield from self._iter_subkey_values(
            "sevenzip",
            _hkcu(
                "Software\\7-Zip\\Compression",
                "Software\\7-Zip\\Extraction",
                "Software\\7-Zip\\FM",
            ),
            category="user activity",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def sfc(self) -> Iterator[RegRipperRecord]:
        """``SFCDisable``-related System File Checker policy values."""
        yield from self._iter_values(
            "sfc",
            _hklm(
                "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                "Software\\Policies\\Microsoft\\Windows\\WindowsUpdate",
            ),
            category="defense evasion",
            names=["SFCDisable", "SFCQuota", "SFCScan", "SFCShowProgress"],
        )

    @export(record=RegRipperRecord)
    def shares(self) -> Iterator[RegRipperRecord]:
        """``LanmanServer\\Shares`` and ``Shares\\Security``."""
        yield from self._iter_values(
            "shares",
            _hklm(
                "System\\CurrentControlSet\\Services\\LanmanServer\\Shares",
                "System\\CurrentControlSet\\Services\\LanmanServer\\Shares\\Security",
            ),
            category="lateral movement",
        )

    @export(record=RegRipperRecord)
    def shc(self) -> Iterator[RegRipperRecord]:
        """``CurrentVersion\\Explorer\\SessionInfo`` shell handler cache."""
        yield from self._iter_subkey_values(
            "shc",
            _hkcu(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SessionInfo",
                "Software\\Microsoft\\Windows\\Shell\\Associations",
            ),
            category="user activity",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def shellfolders(self) -> Iterator[RegRipperRecord]:
        """User shell folder paths (Documents/Desktop/Startup/etc.)."""
        yield from self._iter_values(
            "shellfolders",
            _hkcu(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
            ),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def shelloverlay(self) -> Iterator[RegRipperRecord]:
        """ShellIconOverlayIdentifiers (T1546.005)."""
        yield from self._iter_subkey_values(
            "shelloverlay",
            _hklm(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers",
                "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers",
            ),
            category="persistence",
        )

    @export(record=RegRipperRecord)
    def shutdown(self) -> Iterator[RegRipperRecord]:
        """``ShutdownTime`` (last shutdown timestamp)."""
        yield from self._iter_values(
            "shutdown",
            _hklm("System\\CurrentControlSet\\Control\\Windows"),
            category="system",
            names=["ShutdownTime", "ShutdownReasonCode", "ShutdownReasonComment"],
        )

    @export(record=RegRipperRecord)
    def sizes(self) -> Iterator[RegRipperRecord]:
        """``Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BagMRU\\NodeSlots`` sizes."""
        yield from self._iter_values(
            "sizes",
            _hkcu("Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell"),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def slack(self) -> Iterator[RegRipperRecord]:
        """Slack desktop preferences and login state."""
        yield from self._iter_subkey_values(
            "slack",
            _hkcu("Software\\Slack"),
            category="user activity",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def source_os(self) -> Iterator[RegRipperRecord]:
        """``Source OS`` upgrade history."""
        yield from self._iter_subkey_values(
            "source_os",
            _hklm("System\\Setup\\Source OS"),
            category="system",
        )

    @export(record=RegRipperRecord)
    def speech(self) -> Iterator[RegRipperRecord]:
        """Speech recognition configuration and accent."""
        yield from self._iter_values(
            "speech",
            _hkcu(
                "Software\\Microsoft\\Speech",
                "Software\\Microsoft\\Speech_OneCore",
            ),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def spp_clients(self) -> Iterator[RegRipperRecord]:
        """``SPP\\Clients`` software protection client GUIDs."""
        yield from self._iter_values(
            "spp_clients",
            _hklm("Software\\Microsoft\\Windows NT\\CurrentVersion\\SPP\\Clients"),
            category="installed",
        )

    @export(record=RegRipperRecord)
    def srum(self) -> Iterator[RegRipperRecord]:
        """``SRUM`` extension keys (System Resource Usage Monitor)."""
        yield from self._iter_subkey_values(
            "srum",
            _hklm("Software\\Microsoft\\Windows NT\\CurrentVersion\\SRUM\\Extensions"),
            category="user activity",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def susclient(self) -> Iterator[RegRipperRecord]:
        """``SusClientId`` and Windows Update unique client ID."""
        yield from self._iter_values(
            "susclient",
            _hklm("Software\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate"),
            category="system",
            names=["SusClientId", "SusClientIDValidation", "AccountDomainSid"],
        )

    @export(record=RegRipperRecord)
    def svc(self) -> Iterator[RegRipperRecord]:
        """Single-key dump of ``Services`` LastWrite (rough counterpart of services)."""
        yield from self._iter_subkey_lastwrite(
            "svc",
            _hklm("System\\CurrentControlSet\\Services"),
            category="execution",
        )

    @export(record=RegRipperRecord)
    def svcdll(self) -> Iterator[RegRipperRecord]:
        """``Services\\<Name>\\Parameters\\ServiceDll`` paths."""
        yield from self._iter_subkey_values(
            "svcdll",
            _hklm("System\\CurrentControlSet\\Services"),
            category="persistence",
            value_name="ServiceDll",
        )

    @export(record=RegRipperRecord)
    def syscache(self) -> Iterator[RegRipperRecord]:
        """``Syscache`` artifact (legacy AppLocker cache, COMPONENTS hive)."""
        yield from self._iter_subkey_values(
            "syscache",
            _hklm("DefaultObjectStore\\ObjectTable"),
            category="execution",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def syscache_csv(self) -> Iterator[RegRipperRecord]:
        """Same artifact as :py:meth:`syscache` (kept for parity with upstream)."""
        yield from self.syscache()

    @export(record=RegRipperRecord)
    def sysinternals(self) -> Iterator[RegRipperRecord]:
        """Sysinternals EULA-accepted markers (per-tool ``EulaAccepted`` value)."""
        yield from self._iter_subkey_values(
            "sysinternals",
            _hkcu("Software\\Sysinternals"),
            category="user activity",
            value_name="EulaAccepted",
        )

    @export(record=RegRipperRecord)
    def systemindex(self) -> Iterator[RegRipperRecord]:
        """Windows Search ``SystemIndex`` excluded paths and crawl scopes."""
        yield from self._iter_subkey_values(
            "systemindex",
            _hklm(
                "Software\\Microsoft\\Windows Search\\CrawlScopeManager\\Windows\\SystemIndex\\WorkingSetRules",
                "Software\\Microsoft\\Windows Search\\CrawlScopeManager\\Windows\\SystemIndex\\DefaultRules",
            ),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def termcert(self) -> Iterator[RegRipperRecord]:
        """RDP self-signed certificate hash + listener."""
        yield from self._iter_values(
            "termcert",
            _hklm(
                "System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                "System\\CurrentControlSet\\Services\\TermService\\Parameters",
            ),
            category="lateral movement",
            names=["SSLCertificateSHA1Hash", "Certificate"],
        )

    @export(record=RegRipperRecord)
    def termserv(self) -> Iterator[RegRipperRecord]:
        """Terminal Server / Remote Desktop core configuration."""
        yield from self._iter_values(
            "termserv",
            _hklm(
                "System\\CurrentControlSet\\Control\\Terminal Server",
                "System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
            ),
            category="lateral movement",
        )

    @export(record=RegRipperRecord)
    def thispcpolicy(self) -> Iterator[RegRipperRecord]:
        """``ThisPCPolicy`` (Win10 Explorer ``This PC`` shell policy values)."""
        yield from self._iter_subkey_values(
            "thispcpolicy",
            _hklm(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FolderDescriptions",
                "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FolderDescriptions",
            ),
            category="policy",
            value_name="ThisPCPolicy",
        )

    @export(record=RegRipperRecord)
    def tracing(self) -> Iterator[RegRipperRecord]:
        """``Tracing`` registry providers."""
        yield from self._iter_subkey_lastwrite(
            "tracing",
            _hklm("Software\\Microsoft\\Tracing"),
            category="logging",
        )

    @export(record=RegRipperRecord)
    def tsclient(self) -> Iterator[RegRipperRecord]:
        """``Terminal Server Client`` MRU and Default."""
        yield from self._iter_subkey_values(
            "tsclient",
            _hkcu(
                "Software\\Microsoft\\Terminal Server Client\\Default",
                "Software\\Microsoft\\Terminal Server Client\\Servers",
            ),
            category="lateral movement",
        )

    @export(record=RegRipperRecord)
    def typedpaths(self) -> Iterator[RegRipperRecord]:
        """Explorer address-bar typed paths (NTUSER)."""
        yield from self._iter_values(
            "typedpaths",
            _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths"),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def typedurlstime(self) -> Iterator[RegRipperRecord]:
        """``TypedURLsTime`` IE typed URL timestamps."""
        yield from self._iter_values(
            "typedurlstime",
            _hkcu(
                "Software\\Microsoft\\Internet Explorer\\TypedURLsTime",
                "Software\\Microsoft\\Internet Explorer\\TypedURLs",
            ),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def uac(self) -> Iterator[RegRipperRecord]:
        """User Account Control settings under ``Policies\\System``."""
        yield from self._iter_values(
            "uac",
            _hklm("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
            category="security",
            names=[
                "EnableLUA",
                "ConsentPromptBehaviorAdmin",
                "ConsentPromptBehaviorUser",
                "FilterAdministratorToken",
                "PromptOnSecureDesktop",
                "EnableInstallerDetection",
                "EnableSecureUIAPaths",
                "EnableUIADesktopToggle",
                "EnableVirtualization",
            ],
        )

    @export(record=RegRipperRecord)
    def uacbypass(self) -> Iterator[RegRipperRecord]:
        """Known UAC bypass keys (sdclt/eventvwr/fodhelper handlers)."""
        yield from self._iter_subkey_values(
            "uacbypass",
            _hkcu(
                "Software\\Classes\\ms-settings\\shell\\open\\command",
                "Software\\Classes\\Folder\\shell\\open\\command",
                "Software\\Classes\\mscfile\\shell\\open\\command",
                "Software\\Classes\\exefile\\shell\\open\\command",
            ),
            category="defense evasion",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def uninstall(self) -> Iterator[RegRipperRecord]:
        """``CurrentVersion\\Uninstall`` installed software list."""
        yield from self._iter_subkey_values(
            "uninstall",
            _hklm(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            )
            + _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            category="installed",
        )

    @export(record=RegRipperRecord)
    def usbdevices(self) -> Iterator[RegRipperRecord]:
        """``Enum\\USB`` & ``Enum\\USBSTOR`` summary (rough)."""
        yield from self._iter_subkey_values(
            "usbdevices",
            _hklm(
                "System\\CurrentControlSet\\Enum\\USB",
                "System\\CurrentControlSet\\Enum\\USBSTOR",
            ),
            category="device",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def volinfocache(self) -> Iterator[RegRipperRecord]:
        """``VolumeInfoCache`` (Win10 mounted volume label cache)."""
        yield from self._iter_subkey_values(
            "volinfocache",
            _hklm("Software\\Microsoft\\Windows Search\\VolumeInfoCache"),
            category="device",
        )

    @export(record=RegRipperRecord)
    def wab(self) -> Iterator[RegRipperRecord]:
        """Windows Address Book (Outlook contact ``WAB``) MRU/preferences."""
        yield from self._iter_subkey_values(
            "wab",
            _hkcu("Software\\Microsoft\\WAB"),
            category="user activity",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def watp(self) -> Iterator[RegRipperRecord]:
        """Windows Advanced Threat Protection (Defender ATP) onboarding."""
        yield from self._iter_values(
            "watp",
            _hklm("Software\\Microsoft\\Windows Advanced Threat Protection"),
            category="security",
        )

    @export(record=RegRipperRecord)
    def wbem(self) -> Iterator[RegRipperRecord]:
        """``WBEM`` (WMI) configuration values."""
        yield from self._iter_subkey_values(
            "wbem",
            _hklm("Software\\Microsoft\\Wbem"),
            category="execution",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def wc_shares(self) -> Iterator[RegRipperRecord]:
        """``WorkstationCache\\Shares`` (resolved network shares)."""
        yield from self._iter_subkey_values(
            "wc_shares",
            _hkcu("Network"),
            category="lateral movement",
        )

    @export(record=RegRipperRecord)
    def winrar(self) -> Iterator[RegRipperRecord]:
        """WinRAR ArcHistory and DialogEditHistory."""
        yield from self._iter_subkey_values(
            "winrar",
            _hkcu(
                "Software\\WinRAR\\ArcHistory",
                "Software\\WinRAR\\DialogEditHistory\\ExtrPath",
                "Software\\WinRAR\\DialogEditHistory\\ArcName",
            ),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def winscp(self) -> Iterator[RegRipperRecord]:
        """WinSCP saved sessions (lateral SCP/SFTP usage)."""
        yield from self._iter_subkey_values(
            "winscp",
            _hkcu("Software\\Martin Prikryl\\WinSCP 2\\Sessions"),
            category="lateral movement",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def winzip(self) -> Iterator[RegRipperRecord]:
        """WinZip extract MRU."""
        yield from self._iter_subkey_values(
            "winzip",
            _hkcu("Software\\Nico Mak Computing\\WinZip"),
            category="user activity",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def wordwheelquery(self) -> Iterator[RegRipperRecord]:
        """Windows Explorer Search ``WordWheelQuery`` history."""
        yield from self._iter_values(
            "wordwheelquery",
            _hkcu("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery"),
            category="user activity",
        )

    @export(record=RegRipperRecord)
    def wow64(self) -> Iterator[RegRipperRecord]:
        """``Wow64`` redirection / disable flag(s)."""
        yield from self._iter_values(
            "wow64",
            _hklm("System\\CurrentControlSet\\Control\\Wow64"),
            category="system",
        )

    @export(record=RegRipperRecord)
    def wpdbusenum(self) -> Iterator[RegRipperRecord]:
        """``Enum\\WPDBUSENUM`` portable devices (USB MTP/PTP)."""
        yield from self._iter_subkey_values(
            "wpdbusenum",
            _hklm("System\\CurrentControlSet\\Enum\\WPDBUSENUM"),
            category="device",
            recursive=True,
        )

    @export(record=RegRipperRecord)
    def wsh_settings(self) -> Iterator[RegRipperRecord]:
        """Windows Script Host (``WSH``) settings (Enabled / Remote / Trust)."""
        yield from self._iter_values(
            "wsh_settings",
            _both("Software\\Microsoft\\Windows Script Host\\Settings"),
            category="execution",
        )
