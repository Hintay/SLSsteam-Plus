#!/usr/bin/env python3
"""
extract_funchashes.py -- Extract IPC funcHash constants from steamclient.so (32-bit ELF).

Algorithm (Steam-specific vtable layout via InterfaceMap markers):
  For each (interface, method, interface_id, vtable_index):
  1. Locate the InterfaceMap mangled-name string "<N><Name>Map\0" in rodata.
  2. Find the matching triplet [flags=0x8][str_ptr][data_ptr] in .data.rel.ro.
  3. typeinfo_slot_va = data_ptr + 12  (stable 3-slot offset into the InterfaceMap object).
  4. Search .data.rel.ro for a slot whose value == typeinfo_slot_va and
     whose predecessor (offset_to_top) == 0 -- that's the real vtable header.
  5. method[vtable_index] = read_u32(typeinfo_slot_va + 4 + vtable_index * 4).
  6. Scan the wrapper function body for the byte pattern:
       C7 45 ?? <imm32:funcHash> 6A 04 50 57 E8
     The first two hits are (funcHash, fencepost).

Ground-truth anchors (verified against Ghidra):
  IClientUser::GetSteamID         funcHash = 0xD6FC3200
  IClientAppManager::IsAppDlcInstalled  funcHash = 0xCDBD8C0F, fencepost = 0xCFE45F3C
"""

import argparse
import re
import struct
import sys
from pathlib import Path
from typing import Optional

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    print("ERROR: pyelftools not installed. Run: pip3 install pyelftools", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Methods to extract: (interface_name, method_name, interface_id, vtable_index)
# ---------------------------------------------------------------------------
METHODS = [
    ("IClientUser",         "GetSteamID",             1, 10),

    # --- Inbound: methods intercepted via funcHash IPC dispatch ---
    ("IClientAppManager",   "IsAppDlcInstalled",      8,  9),
    ("IClientAppManager",   "LaunchApp",              8,  2),
    ("IClientAppManager",   "BIsDlcEnabled",          8, 11),
    ("IClientAppManager",   "GetUpdateInfo",          8, 20),
    ("IClientApps",         "GetDLCCount",            7,  8),
    ("IClientApps",         "GetDLCDataByIndex",      7,  9),
    ("IClientRemoteStorage","IsCloudEnabledForApp",  19, 24),
    ("IClientUtils",        "GetAppId",               4, 19),
    ("IClientUtils",        "GetOfflineMode",         4, 17),

    # --- Outbound: methods SLSsteam calls into Steam (callVFuncByHash phase) ---
    ("IClientApps",         "GetAppData",             7,  0),
    ("IClientApps",         "GetAppDataSection",      7,  5),
    ("IClientApps",         "RequestAppInfoUpdate",   7,  7),
    ("IClientApps",         "GetAppType",             7, 10),
    ("IClientAppManager",   "InstallApp",             8,  0),
    ("IClientAppManager",   "GetAppInstallState",     8,  4),
    ("IClientRemoteStorage","SetCloudEnabledForApp", 19, 25),
]

# Byte pattern for funcHash in wrapper body:
#   mov [ebp+disp8], imm32  ;  push 4 ; push eax ; push edi ; call serialize
_FUNCHASH_PATTERN = re.compile(
    b'\xC7\x45.(....)\x6A\x04\x50\x57\xE8',
    re.DOTALL,
)

# Scan window (bytes from function VA start)
_SCAN_WINDOW = 0x400


class ElfReader:
    """Thin wrapper around a loaded ELF binary providing vaddr <-> file-offset mapping."""

    def __init__(self, path: str) -> None:
        self._data = Path(path).read_bytes()
        with open(path, "rb") as f:
            elf = ELFFile(f)
            self._segs = [
                (seg.header.p_vaddr,
                 seg.header.p_vaddr + seg.header.p_filesz,
                 seg.header.p_offset)
                for seg in elf.iter_segments()
                if seg.header.p_type == "PT_LOAD"
            ]

    # -- address helpers ------------------------------------------------

    def va2off(self, va: int) -> Optional[int]:
        """Return file offset for a virtual address, or None if unmapped."""
        for vstart, vend, foff in self._segs:
            if vstart <= va < vend:
                return int(foff + (va - vstart))
        return None

    def off2va(self, off: int) -> Optional[int]:
        """Return virtual address for a file offset, or None if unmapped."""
        for vstart, vend, foff in self._segs:
            fend = foff + (vend - vstart)
            if foff <= off < fend:
                return int(vstart + (off - foff))
        return None

    def read_u32_va(self, va: int) -> Optional[int]:
        off = self.va2off(va)
        if off is None:
            return None
        return struct.unpack_from("<I", self._data, off)[0]

    # -- raw search helpers ---------------------------------------------

    def find_bytes(self, pattern: bytes, start: int = 0) -> int:
        """Return file offset of first match, or -1."""
        return self._data.find(pattern, start)

    def find_all_bytes(self, pattern: bytes, lo: int, hi: int):
        """Yield all file offsets in [lo, hi) where pattern occurs."""
        pos = lo
        while True:
            pos = self._data.find(pattern, pos, hi)
            if pos < 0:
                break
            yield pos
            pos += 1

    @property
    def raw(self) -> bytes:
        return self._data


def _get_dro_range(reader: ElfReader):
    """
    Return (file_start, file_end) for .data.rel.ro by scanning PT_LOAD segments.
    We use a simple heuristic: the second-to-last RW segment (flags=6) contains it.
    In practice we just scan the whole RW region; correctness is guaranteed because
    the typeinfo_slot values are unique enough.
    """
    # Return the union of all RW (flags=6) segments as a single range
    rw_segs = [s for s in reader._segs]  # search all loaded segments
    if not rw_segs:
        raise RuntimeError("No PT_LOAD segments found")
    lo = min(s[2] for s in rw_segs)
    hi = max(s[2] + (s[1] - s[0]) for s in rw_segs)
    return lo, hi


def _find_interface_map_data_ptr(reader: ElfReader, iface_name: str, dro_lo: int, dro_hi: int) -> int:
    """
    Locate the InterfaceMap triplet for <iface_name> and return its data_ptr field.

    The mangled name is "<N><Name>Map" (e.g. "14IClientUserMap").
    The triplet layout is: [flags=0x00000008][str_ptr→mangled_name][data_ptr].
    We find the mangled-name string in the binary, then find the triplet that
    references it (str_ptr == name_va) with flags == 0x8.
    """
    map_name = f"{iface_name}Map"
    mangled  = f"{len(map_name)}{map_name}".encode() + b"\x00"

    name_off = reader.find_bytes(mangled)
    if name_off < 0:
        raise RuntimeError(f"Mangled name {mangled!r} not found in binary")
    name_va = reader.off2va(name_off)
    if name_va is None:
        raise RuntimeError(f"Mangled name found at file offset 0x{name_off:x} but not in any VA mapping")

    name_va_bytes = struct.pack("<I", name_va)
    for pos in reader.find_all_bytes(name_va_bytes, dro_lo, dro_hi):
        # str_ptr is at `pos`; flags is 4 bytes before; data_ptr is 4 bytes after
        if pos < 4:
            continue
        flags = struct.unpack_from("<I", reader.raw, pos - 4)[0]
        if flags == 0x8:
            data_ptr = struct.unpack_from("<I", reader.raw, pos + 4)[0]
            return data_ptr

    raise RuntimeError(f"No triplet with flags=0x8 references mangled name {mangled!r}")


def _find_impl_vtable_method0(reader: ElfReader, map_data_ptr: int, dro_lo: int, dro_hi: int) -> int:
    """
    Given an InterfaceMap data_ptr, compute typeinfo_slot_va = data_ptr + 12,
    then locate the implementation vtable entry where:
      - slot value  == typeinfo_slot_va
      - predecessor == 0 (offset_to_top)
    Return the VA of method[0] (= typeinfo_slot_va + 4).
    """
    ti_marker    = map_data_ptr + 12  # stable 3-slot offset
    ti_marker_b  = struct.pack("<I", ti_marker)

    for pos in reader.find_all_bytes(ti_marker_b, dro_lo, dro_hi):
        if pos < 4:
            continue
        offset_to_top = struct.unpack_from("<I", reader.raw, pos - 4)[0]
        if offset_to_top == 0:
            slot_va  = reader.off2va(pos)
            if slot_va is None:
                continue
            return slot_va + 4  # method[0] VA

    raise RuntimeError(
        f"Implementation vtable for typeinfo_slot=0x{ti_marker:08x} not found"
    )


def _scan_funchash(reader: ElfReader, func_va: int):
    """
    Scan the first _SCAN_WINDOW bytes of the wrapper at func_va for the
    funcHash byte pattern.  Return (funcHash, fencepost_or_None).
    """
    func_off = reader.va2off(func_va)
    if func_off is None:
        raise RuntimeError(f"func_va 0x{func_va:08x} not mapped to a file offset")

    window = reader.raw[func_off: func_off + _SCAN_WINDOW]
    hits   = list(_FUNCHASH_PATTERN.finditer(window))
    if not hits:
        raise RuntimeError(
            f"funcHash pattern not found in first 0x{_SCAN_WINDOW:x} bytes of "
            f"function at 0x{func_va:08x}"
        )

    funchash  = struct.unpack("<I", hits[0].group(1))[0]
    fencepost = struct.unpack("<I", hits[1].group(1))[0] if len(hits) > 1 else None
    return funchash, fencepost


def extract(so_path: str):
    """
    Extract funcHash and fencepost for every entry in METHODS.
    Return a list of dicts with keys:
      interface, method, interface_id, vtable_index, funchash, fencepost
    """
    reader = ElfReader(so_path)
    dro_lo, dro_hi = _get_dro_range(reader)

    results = []
    for iface, method, iface_id, vidx in METHODS:
        try:
            map_data_ptr  = _find_interface_map_data_ptr(reader, iface, dro_lo, dro_hi)
            method0_va    = _find_impl_vtable_method0(reader, map_data_ptr, dro_lo, dro_hi)
            func_va       = reader.read_u32_va(method0_va + vidx * 4)
            if func_va is None:
                raise RuntimeError(f"Could not read method[{vidx}] VA from 0x{method0_va + vidx*4:08x}")
            funchash, fencepost = _scan_funchash(reader, func_va)
        except RuntimeError as exc:
            print(f"WARNING: {iface}::{method} -- {exc}", file=sys.stderr)
            continue

        results.append(dict(
            interface    = iface,
            method       = method,
            interface_id = iface_id,
            vtable_index = vidx,
            funchash     = funchash,
            fencepost    = fencepost,
        ))

    return results


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _print_results(results):
    for r in results:
        fence_str = (f", fencepost=0x{r['fencepost']:08X}" if r["fencepost"] is not None else "")
        print(
            f"{r['interface']}::{r['method']} = 0x{r['funchash']:08X}"
            f"  (iface={r['interface_id']}{fence_str})"
        )


def _merge_hash(old_val, new_hash: int, version: int):
    """Merge a new hash into an existing TOML entry, preserving old values with max_version.

    Returns the merged value: a scalar (if unchanged or first entry) or a list
    of versioned candidates.
    """
    if old_val is None:
        return new_hash

    # Normalize old_val to a list of {hash, max_version} dicts.
    if isinstance(old_val, list):
        entries = []
        for item in old_val:
            if isinstance(item, dict):
                entries.append(dict(item))
            else:
                entries.append({"hash": item})
    else:
        entries = [{"hash": old_val}]

    # Check if new_hash is already present.
    for e in entries:
        if e["hash"] == new_hash:
            # Already present — ensure it's the current (no max_version).
            e.pop("max_version", None)
            return entries if len(entries) > 1 else new_hash

    # New hash differs. Demote the current latest entry (the one without
    # max_version) by stamping it with the outgoing version.
    for e in entries:
        if "max_version" not in e:
            e["max_version"] = version
            break

    # Prepend the new hash as the current latest (no max_version).
    entries.insert(0, {"hash": new_hash})
    return entries


def _update_toml(results, toml_path: Path, version: int):
    """Update the IpcHashes section in patterns.toml, preserving old hashes as versioned candidates."""
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib

    text = toml_path.read_text()
    doc = tomllib.loads(text)
    if not isinstance(doc, dict):
        raise RuntimeError(f"{toml_path} root is not a mapping")

    by_iface: dict = {}
    for r in results:
        by_iface.setdefault(r["interface"], {})[r["method"]] = r["funchash"]

    old = doc.get("IpcHashes") or {}
    merged: dict = {}
    for iface in sorted(old.keys() | by_iface.keys()):
        old_methods = old.get(iface) or {}
        new_methods = by_iface.get(iface) or {}
        methods: dict = {}
        for m in sorted(old_methods.keys() | new_methods.keys()):
            old_v = old_methods.get(m)
            new_h = new_methods.get(m)
            if new_h is not None:
                methods[m] = _merge_hash(old_v, new_h, version)
            else:
                methods[m] = old_v
        merged[iface] = methods

    lines = []
    for iface, methods in merged.items():
        lines.append(f"[IpcHashes.{iface}]")
        for m, val in methods.items():
            if isinstance(val, int):
                lines.append(f"{m} = 0x{val:08X}")
            else:
                items = []
                for entry in val:
                    h = entry["hash"]
                    mv = entry.get("max_version")
                    s = f"{{ hash = 0x{h:08X}"
                    if mv:
                        s += f", max_version = {mv}"
                    s += " }"
                    items.append(s)
                lines.append(f"{m} = [{', '.join(items)}]")
        lines.append("")
    new_section = "\n".join(lines) + "\n"

    import re as _re
    # Match all [IpcHashes.*] sections until the next non-IpcHashes section or EOF.
    # Without DOTALL so '.' does not cross newlines; the trailing (?:...|\Z) handles
    # both "next section starts" and "end of file" cases.
    pattern = _re.compile(
        r'^\[IpcHashes\.\w+\].*?(?=^\[[^I]|\Z)',
        _re.MULTILINE | _re.DOTALL,
    )
    if pattern.search(text):
        text = pattern.sub(new_section, text)
    else:
        text = text.rstrip() + "\n\n" + new_section

    toml_path.write_text(text)
    changed = sum(1 for iface in merged.values()
                  for v in iface.values() if isinstance(v, list))
    print(f"Updated IpcHashes in {toml_path} ({changed} versioned entries)", file=sys.stderr)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Extract IPC funcHash constants from steamclient.so and "
                    "update the IpcHashes section in res/patterns.toml."
    )
    parser.add_argument("so_path", help="Path to steamclient.so (32-bit ELF)")
    parser.add_argument(
        "--print", action="store_true", dest="print_only",
        help="Print results to stdout instead of updating patterns.toml",
    )
    parser.add_argument(
        "--version", type=int, default=None,
        help="nSteamVersion of the binary being extracted (required for versioned updates). "
             "Old hashes that differ from the extraction get max_version set to this value.",
    )
    parser.add_argument(
        "--toml", default=None,
        help="Path to patterns.toml (default: res/patterns.toml relative to repo root)",
    )
    args = parser.parse_args()

    results = extract(args.so_path)
    if not results:
        print("ERROR: No methods extracted.", file=sys.stderr)
        sys.exit(1)

    if args.print_only:
        _print_results(results)
    else:
        if args.version is None:
            print("ERROR: --version is required when updating TOML. "
                  "Pass the nSteamVersion of the binary (e.g. --version 1781041600).",
                  file=sys.stderr)
            sys.exit(1)
        if args.toml:
            toml_path = Path(args.toml)
        else:
            repo_root = Path(__file__).parent.parent
            toml_path = repo_root / "res" / "patterns.toml"
        _update_toml(results, toml_path, args.version)


if __name__ == "__main__":
    main()
