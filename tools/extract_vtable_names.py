#!/usr/bin/env python3
"""
extract_vtable_names.py -- Extract (vtable index -> internal IPC name) per IClient*
interface from steamclient.so (32-bit ELF).

Steam method wrappers open with a `TraceIPC(iface, method)` call whose two arguments
are loaded via `lea reg, [picBase + disp32]` immediately before the call. We:

  1. Reuse the InterfaceMap -> typeinfo -> vtable navigation from extract_funchashes.py
     to locate each interface's *real* C++ vtable.
  2. Read every vtable slot's function pointer until we walk off the table.
  3. For each wrapper, decode the iface/method strings statically from its prologue.

Output: JSON `{ "IClientFoo": [{"index": 0, "internal_name": "IClientFoo::Bar",
"func_va": "0x..."}, ...], ... }` — directly usable for spotting vtable drift and
re-deriving `vft_index` values in res/patterns.toml.

Build-time, offline, deterministic — no runtime disassembly, no live process needed.
"""

import argparse
import json
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
# Shared with extract_funchashes.py — ELF helpers
# ---------------------------------------------------------------------------

class ElfReader:
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

    def va2off(self, va: int) -> Optional[int]:
        for vstart, vend, foff in self._segs:
            if vstart <= va < vend:
                return int(foff + (va - vstart))
        return None

    def off2va(self, off: int) -> Optional[int]:
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

    def find_bytes(self, pattern: bytes, start: int = 0) -> int:
        return self._data.find(pattern, start)

    def find_all_bytes(self, pattern: bytes, lo: int, hi: int):
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


def _get_load_range(reader: ElfReader):
    if not reader._segs:
        raise RuntimeError("No PT_LOAD segments found")
    lo = min(s[2] for s in reader._segs)
    hi = max(s[2] + (s[1] - s[0]) for s in reader._segs)
    return lo, hi


# ---------------------------------------------------------------------------
# InterfaceMap -> vtable navigation (lifted from extract_funchashes.py)
# ---------------------------------------------------------------------------

def find_interface_map_data_ptr(reader, iface_name: str, dro_lo: int, dro_hi: int) -> int:
    map_name = f"{iface_name}Map"
    mangled = f"{len(map_name)}{map_name}".encode() + b"\x00"

    name_off = reader.find_bytes(mangled)
    if name_off < 0:
        raise RuntimeError(f"Mangled name {mangled!r} not found in binary")
    name_va = reader.off2va(name_off)
    if name_va is None:
        raise RuntimeError(f"Mangled name found at off=0x{name_off:x} but no VA mapping")

    name_va_bytes = struct.pack("<I", name_va)
    for pos in reader.find_all_bytes(name_va_bytes, dro_lo, dro_hi):
        if pos < 4:
            continue
        flags = struct.unpack_from("<I", reader.raw, pos - 4)[0]
        if flags == 0x8:
            return struct.unpack_from("<I", reader.raw, pos + 4)[0]
    raise RuntimeError(f"No InterfaceMap triplet for {iface_name}")


def find_impl_vtable_method0(reader, map_data_ptr: int, dro_lo: int, dro_hi: int) -> int:
    ti_marker = map_data_ptr + 12
    ti_marker_b = struct.pack("<I", ti_marker)
    for pos in reader.find_all_bytes(ti_marker_b, dro_lo, dro_hi):
        if pos < 4:
            continue
        offset_to_top = struct.unpack_from("<I", reader.raw, pos - 4)[0]
        if offset_to_top == 0:
            slot_va = reader.off2va(pos)
            if slot_va is None:
                continue
            return slot_va + 4
    raise RuntimeError(f"Impl vtable for typeinfo=0x{ti_marker:08x} not found")


def get_text_ranges(reader):
    """Return list of (vstart, vend) for executable segments."""
    # Re-open to inspect segment flags (pyelftools doesn't expose them via ElfReader's tuple).
    ranges = []
    with open_elf(reader) as elf:
        for seg in elf.iter_segments():
            if seg.header.p_type == "PT_LOAD" and (seg.header.p_flags & 0x1):  # PF_X
                vstart = seg.header.p_vaddr
                vend = vstart + seg.header.p_filesz
                ranges.append((vstart, vend))
    return ranges


def open_elf(reader):
    """Reopen ELFFile from the same underlying path. ElfReader stores bytes not the ELFFile."""
    import io
    return ELFFile(io.BytesIO(reader.raw))


def read_vtable_slots(reader, method0_va: int, text_ranges, max_slots: int = 200):
    """Walk vtable from method0_va, returning function-pointer VAs until we hit a
    non-text pointer or reach max_slots."""
    slots = []
    for i in range(max_slots):
        slot_va = method0_va + i * 4
        ptr = reader.read_u32_va(slot_va)
        if ptr is None or ptr == 0:
            break
        if not any(vs <= ptr < ve for vs, ve in text_ranges):
            break
        slots.append(ptr)
    return slots


# ---------------------------------------------------------------------------
# Wrapper internal-name decoder
# ---------------------------------------------------------------------------

_INTERFACE_NAME_RE = re.compile(rb"^IClient[A-Za-z0-9_]+$")
_METHOD_NAME_RE = re.compile(rb"^[A-Za-z_][A-Za-z0-9_]+$")


def is_interface_name(s: bytes) -> bool:
    return bool(_INTERFACE_NAME_RE.match(s))


def is_method_shape(s: bytes) -> bool:
    # Reject empty, format strings, paths, multi-word labels, interface names.
    if not s or len(s) < 2 or len(s) > 96:
        return False
    if is_interface_name(s):
        return False
    if any(c in s for c in b"/% "):
        return False
    return bool(_METHOD_NAME_RE.match(s))


def read_cstr_at_va(reader: ElfReader, va: int, max_len: int = 96) -> Optional[bytes]:
    off = reader.va2off(va)
    if off is None:
        return None
    end = reader.raw.find(b"\x00", off, off + max_len)
    if end < 0:
        return None
    return reader.raw[off:end]


def find_pic_anchor(reader: ElfReader, func_va: int, scan_len: int = 0x40):
    """Decode `E8 imm32; [pop reg;] add reg, imm32`. Return picBase (afterCall + imm)
    or None on failure."""
    func_off = reader.va2off(func_va)
    if func_off is None:
        return None
    data = reader.raw[func_off:func_off + scan_len]

    for i in range(len(data) - 11):
        if data[i] != 0xE8:
            continue
        after_call_off = i + 5
        after_call_va = func_va + after_call_off
        # Look for `add r32, imm32` within next 16 bytes (skipping optional pop)
        for j in range(after_call_off, min(after_call_off + 16, len(data) - 5)):
            if data[j] == 0x81 and 0xC0 <= data[j + 1] <= 0xC7:
                imm = struct.unpack_from("<i", data, j + 2)[0]
                return (after_call_va + imm) & 0xFFFFFFFF
    return None


def extract_internal_name(reader: ElfReader, func_va: int, scan_len: int = 0x400):
    """Statically decode TraceIPC(iface, method) by:
       - finding the PIC anchor,
       - byte-scanning for lea r,[reg+disp32] (mod=10, rm!=4) and resolving disp32 against picBase,
       - on each E8 call, checking if the last collected (iface, method) pair makes sense.
       Returns dict {iface, method, func_va} on success, None otherwise.
    """
    pic_base = find_pic_anchor(reader, func_va)
    if pic_base is None:
        return None

    func_off = reader.va2off(func_va)
    if func_off is None:
        return None
    data = reader.raw[func_off:func_off + scan_len]

    recent = []   # ring of (string, byte_offset_within_func)
    i = 0
    while i < len(data) - 5:
        # Direct call: E8 imm32. We treat the FIRST E8 we've already used as the PIC
        # thunk (no args of interest); subsequent ones are candidates for TraceIPC.
        if data[i] == 0xE8:
            # Look in the recent window for a (iface, method) pair
            iface = None
            method = None
            for s, _ in reversed(recent[-8:]):
                if is_interface_name(s) and iface is None:
                    iface = s.decode()
                elif is_method_shape(s) and method is None:
                    method = s.decode()
                if iface and method:
                    break
            if iface and method:
                return {
                    "iface": iface,
                    "method": method,
                    "internal_name": f"{iface}::{method}",
                    "func_va": f"0x{func_va:08x}",
                }
            i += 5
            continue

        # lea r32, [reg + disp32]: 8D modrm disp32 (size 6)
        if data[i] == 0x8D:
            modrm = data[i + 1]
            mod = modrm >> 6
            rm = modrm & 7
            if mod == 2 and rm != 4:
                disp = struct.unpack_from("<i", data, i + 2)[0]
                target_va = (pic_base + disp) & 0xFFFFFFFF
                s = read_cstr_at_va(reader, target_va)
                if s is not None and 2 <= len(s) <= 96 and all(0x20 <= b <= 0x7e for b in s):
                    recent.append((s, i))
                i += 6
                continue

        i += 1

    return None


# ---------------------------------------------------------------------------
# Interface discovery
# ---------------------------------------------------------------------------

def discover_interfaces(reader: ElfReader, filter_set=None):
    """Find all <N>IClient*Map mangled strings in the binary; return sorted list of
    interface names (without the 'Map' suffix)."""
    out = []
    # Mangled form: digit(s) "IClient" name "Map" NUL
    rx = re.compile(rb"(?<!\w)(\d+)IClient([A-Za-z0-9_]+)Map\x00")
    for m in rx.finditer(reader.raw):
        length = int(m.group(1))
        body = m.group(2)
        # Validate length-prefix matches "IClient<body>Map" length
        full_name = b"IClient" + body + b"Map"
        if len(full_name) != length:
            continue
        iface = "IClient" + body.decode()
        if filter_set and iface not in filter_set:
            continue
        if iface not in out:
            out.append(iface)
    return sorted(out)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def find_all_vtables(reader, dro_lo: int, dro_hi: int, text_ranges):
    """Scan .data.rel.ro for vtable headers. A header is a 3-slot pattern:
       [offset_to_top=0][typeinfo_ptr][method0_ptr -> .text]
    Returns list of method0_va.
    Heuristic: any 32-bit word in .data.rel.ro whose value is a .text pointer,
    whose predecessor is a non-text pointer (typeinfo), whose predecessor-of-predecessor
    is zero (offset_to_top), is the start of a vtable's method array.
    """
    results = []
    i = dro_lo + 8
    while i + 4 <= dro_hi:
        word = struct.unpack_from("<I", reader.raw, i)[0]
        ti = struct.unpack_from("<I", reader.raw, i - 4)[0]
        ot = struct.unpack_from("<I", reader.raw, i - 8)[0]
        # method0 must be in .text; typeinfo is data (or text); offset_to_top is 0
        if ot == 0 and ti != 0 and any(vs <= word < ve for vs, ve in text_ranges):
            method0_va = reader.off2va(i)
            if method0_va is not None:
                # Walk until non-text to determine length
                slots = read_vtable_slots(reader, method0_va, text_ranges, 200)
                if len(slots) >= 3:  # at least 3 slots to be a real vtable
                    results.append((method0_va, slots))
        i += 4
    return results


def find_run_ipc_frames(reader: ElfReader, text_ranges, iface_funchashes: dict):
    """For each interface, scan .text for `cmp eax, IMM32` (3D imm32) whose IMM32 is
    one of the interface's known funcHashes. Group by the function ENTRY closest
    below each cmp (via 55 89 E5 PIC prologue scan). Returns:
        {iface_name: {"func_va": "0x...", "cmp_count": N, "head_bytes": "55 89 e5 ..."}}
    """
    out = {}
    # Build inverse: funcHash -> iface_name
    hash_to_iface = {}
    for iface, hashes in iface_funchashes.items():
        for h in hashes:
            if h:
                hash_to_iface[h] = iface

    # Collect all cmp eax, imm32 in .text whose imm32 matches a known funcHash.
    # tally per iface, with the (cmp_va) list.
    iface_cmps = {iface: [] for iface in iface_funchashes}

    for vs, ve in text_ranges:
        # Get the file bytes for this range
        # We don't have a direct VA -> bytes range method, so iterate.
        # The raw buffer indexing via va2off would be slow per cmp; do via slice.
        off_start = reader.va2off(vs)
        if off_start is None:
            continue
        off_end = off_start + (ve - vs)
        data = reader.raw[off_start:off_end]
        # Scan for 3D IMM32 (cmp eax, imm32). 5 bytes total.
        i = 0
        n = len(data) - 5
        while i < n:
            if data[i] == 0x3D:
                imm = struct.unpack_from("<I", data, i + 1)[0]
                if imm in hash_to_iface:
                    cmp_va = vs + i
                    iface_cmps[hash_to_iface[imm]].append(cmp_va)
            i += 1

    # For each iface, attribute cmps to their containing functions and pick the
    # function with the most cmps.
    for iface, cmps in iface_cmps.items():
        if not cmps:
            continue

        # Group cmps by containing function entry. Walk back from each cmp to find
        # the nearest `55 89 E5` prologue (push ebp; mov ebp, esp).
        func_counts = {}  # func_va -> cmp count
        for cmp_va in cmps:
            # Walk back up to 0x4000 bytes looking for 55 89 e5
            scan = 0x4000
            off = reader.va2off(cmp_va)
            if off is None:
                continue
            lo = max(0, off - scan)
            window = reader.raw[lo:off + 1]
            # Find the LAST occurrence of `55 89 e5` in the window
            best = window.rfind(b"\x55\x89\xe5")
            if best < 0:
                continue
            func_off = lo + best
            func_va = reader.off2va(func_off)
            if func_va is None:
                continue
            func_counts[func_va] = func_counts.get(func_va, 0) + 1

        if not func_counts:
            continue
        # Pick the function with the highest count
        func_va, count = max(func_counts.items(), key=lambda kv: kv[1])

        off = reader.va2off(func_va)
        head = reader.raw[off:off + 24] if off is not None else b""
        out[iface] = {
            "func_va": f"0x{func_va:08x}",
            "cmp_count": count,
            "total_iface_cmps": len(cmps),
            "head_bytes": " ".join(f"{b:02X}" for b in head),
        }
    return out


def main():
    parser = argparse.ArgumentParser(
        description="Extract (vtable_index -> internal IPC name) per IClient*, "
                    "by scanning ALL vtables in .data.rel.ro and grouping wrappers by "
                    "the iface label they pass to TraceIPC (InterfaceMap-independent)."
    )
    parser.add_argument("so_path", help="Path to steamclient.so (32-bit ELF)")
    parser.add_argument("--interfaces", "-i", nargs="+",
                        help="Restrict OUTPUT to these interfaces (extraction is global)")
    parser.add_argument("--output", "-o", help="Output JSON file (default: stdout)")
    parser.add_argument("--find-runipcframe", action="store_true",
                        help="Also locate each interface's RunIPCFrame by scanning .text "
                             "for cmp eax,funcHash against the interface's method hashes")
    args = parser.parse_args()

    reader = ElfReader(args.so_path)
    dro_lo, dro_hi = _get_load_range(reader)
    text_ranges = get_text_ranges(reader)

    print(f"scanning .data.rel.ro for vtables...", file=sys.stderr)
    all_vtables = find_all_vtables(reader, dro_lo, dro_hi, text_ranges)
    print(f"  found {len(all_vtables)} candidate vtables", file=sys.stderr)

    # For each vtable, decode each slot's wrapper TraceIPC strings.
    # Tally how many slots in this vtable carry each iface label — the dominant iface
    # is the vtable's "real" interface. We attribute the vtable to that iface.
    filter_set = set(args.interfaces) if args.interfaces else None

    iface_to_vtable = {}  # iface -> [(method0_va, [methods])]
    for method0_va, slots in all_vtables:
        # Decode wrapper names; tally iface labels.
        from collections import Counter
        iface_tally = Counter()
        decoded_slots = []
        for idx, func_va in enumerate(slots):
            info = extract_internal_name(reader, func_va)
            if info:
                iface_tally[info["iface"]] += 1
                decoded_slots.append({"index": idx, **info})
            else:
                decoded_slots.append({
                    "index": idx, "iface": None, "method": None,
                    "internal_name": None, "func_va": f"0x{func_va:08x}",
                })

        if not iface_tally:
            continue
        # Dominant iface (>50% of decoded slots OR best of equals).
        dominant_iface, dom_count = iface_tally.most_common(1)[0]
        total_decoded = sum(iface_tally.values())
        if total_decoded < 3 or dom_count * 2 < total_decoded:
            continue  # too fragmented; likely not a real iface vtable

        if filter_set and dominant_iface not in filter_set:
            continue

        iface_to_vtable.setdefault(dominant_iface, []).append({
            "method0_va": f"0x{method0_va:08x}",
            "slot_count": len(slots),
            "decoded_dominant_iface_count": dom_count,
            "decoded_total": total_decoded,
            "methods": decoded_slots,
        })

    # Sort & emit
    result = {}
    for iface in sorted(iface_to_vtable):
        # If multiple vtables map to same iface, sort by method0_va; usually one is the
        # canonical client-side wrapper vtable (the largest one with most decoded methods).
        entries = sorted(iface_to_vtable[iface],
                         key=lambda e: -e["decoded_dominant_iface_count"])
        result[iface] = entries
        print(f"{iface}: {len(entries)} candidate vtable(s)", file=sys.stderr)
        for e in entries[:3]:
            print(f"  method0=0x{int(e['method0_va'],16):08x}  slots={e['slot_count']}  "
                  f"decoded={e['decoded_dominant_iface_count']}/{e['decoded_total']}",
                  file=sys.stderr)

    # Optionally locate RunIPCFrame for each iface
    if args.find_runipcframe:
        iface_hashes = {}
        for iface, entries in result.items():
            hs = []
            for entry in entries:
                for m in entry.get("methods", []):
                    # `methods` produced by older path uses "internal_name"/"func_va"; the
                    # newer dominant-iface attribution path stores them but the funcHash
                    # is in the wrapper extraction (extract_internal_name returns no
                    # funcHash — TODO if needed). For now read from extract_funchashes.py
                    # output if present.
                    pass
            iface_hashes[iface] = hs

        # extract_funchashes.py output is what we actually want for hashes. Re-run that
        # algorithm inline by walking the wrappers we already found and scanning for
        # `C7 45 ?? IMM32 6A 04 50 57 E8`.
        import re as _re
        FH_PAT = _re.compile(rb"\xC7\x45.(....)\x6A\x04\x50\x57\xE8", _re.DOTALL)
        for iface, entries in result.items():
            hs = set()
            for entry in entries:
                for m in entry.get("methods", []):
                    if not m.get("func_va"):
                        continue
                    va = int(m["func_va"], 16)
                    off = reader.va2off(va)
                    if off is None: continue
                    body = reader.raw[off:off + 0x400]
                    mm = FH_PAT.search(body)
                    if mm:
                        h = struct.unpack("<I", mm.group(1))[0]
                        hs.add(h)
            iface_hashes[iface] = list(hs)

        runipc = find_run_ipc_frames(reader, text_ranges, iface_hashes)
        for iface in result:
            if iface in runipc:
                result[iface] = {
                    "vtables": result[iface] if isinstance(result[iface], list) else [result[iface]],
                    "run_ipc_frame": runipc[iface],
                }

    text = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(text)
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
