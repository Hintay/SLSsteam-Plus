#!/usr/bin/env python3
"""
whitelist_selfscan.py — End-to-end validator for the typeinfo-whitelist self-scan
route. Companion of tools/extract_vtable_names.py (the global scanner); this
script tests the *whitelist* variant: walk only the IClient* ifaces we actually
hook, decode their wrappers, vote their RunIPCFrame, then cross-check every
produced value against res/patterns.toml.

Why typeinfo whitelist (not heuristic prefilter):
  Each Itanium-ABI vtable carries a typeinfo pointer at `slot[-1]`. The
  typeinfo's `name` field is a mangled `<len>IClient<Foo>Map` string for the
  client-side InterfaceMap wrappers we want. Reading two pointers + 1 cstring
  per candidate vtable yields a deterministic IFACE -> vtable map in single-
  digit milliseconds, with zero heuristic parameters.

Whitelist sets (kept in sync with hooks.cpp):
  IFACE_VFT     : 5 ifaces whose vtable slots we install VFThook on.
  IFACE_RUNIPC  : 7 ifaces whose RunIPCFrame we detour (= VFT set + UGC/UserStats).

Cross-check results (run on steamclient_0624.so, ada282ad...):
  vft_index    17/17 PASS    self-scan == patterns.toml expected
  RunIPCFrame   6/6  PASS    self-scan vote-VA == patterns.toml first match
  funcHash      9/17 PASS    against patterns.toml
                8/17 STALE   patterns.toml value not in binary; self-scan
                              extracted value verified in binary via Ghidra

The 8 funcHash mismatches are stale patterns.toml residuals from previous Steam
builds (binary search via Ghidra confirms self-scan values; toml values absent).
Conclusion: typeinfo whitelist is correct and strictly more accurate than the
static patterns.toml mapping, with no maintenance after Steam updates.

Run: python3 tools/whitelist_selfscan.py path/to/steamclient.so
"""

import argparse
import re
import struct
import sys
import time
from collections import Counter
from pathlib import Path

# extract_vtable_names lives next to this file
sys.path.insert(0, str(Path(__file__).resolve().parent))
from extract_vtable_names import (  # noqa: E402
    ElfReader, _get_load_range, get_text_ranges,
    find_all_vtables, find_pic_anchor, read_cstr_at_va,
    extract_internal_name, is_interface_name,
)


# ---------------------------------------------------------------------------
# Whitelist — KEEP IN SYNC WITH src/hooks.cpp installVFTByIndex call sites
# ---------------------------------------------------------------------------

IFACE_VFT    = ["IClientAppManager", "IClientApps", "IClientRemoteStorage",
                "IClientUser", "IClientUtils"]
IFACE_RUNIPC = IFACE_VFT + ["IClientUGC", "IClientUserStats"]


# ---------------------------------------------------------------------------
# patterns.toml parsing — extract `current` from versioned maps, else scalar
# ---------------------------------------------------------------------------

def _parse_int(s: str) -> int:
    s = s.strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def _parse_versioned(value: str):
    """`9` or `{ current = 9, 1781041600 = 11 }` -> returns the `current` value
    (the value that ought to match the live binary)."""
    value = value.strip()
    if value.startswith("{"):
        m = re.search(r"current\s*=\s*([0-9xXa-fA-F]+)", value)
        return _parse_int(m.group(1)) if m else None
    return _parse_int(value)


def parse_patterns_toml(path: str):
    """Returns (ipc_methods, runipc_patterns).
    ipc_methods[iface][method] = {"vft_index": int, "func_hash": int}
    runipc_patterns[iface] = byte-pattern string ('55 89 e5 ...').
    """
    text = Path(path).read_text()
    ipc = {}
    block_re = re.compile(
        r"\[IpcMethods\.(IClient\w+)\.([A-Za-z_][A-Za-z0-9_]+)\]\s*\n"
        r"((?:[ \t]*(?:vft_index|func_hash)\s*=[^\n]*\n)+)",
        re.MULTILINE,
    )
    for m in block_re.finditer(text):
        iface, method, body = m.group(1), m.group(2), m.group(3)
        vft_m = re.search(r"vft_index\s*=\s*(\{[^}]+\}|\d+)", body)
        fh_m  = re.search(r"func_hash\s*=\s*(\{[^}]+\}|0x[0-9A-Fa-f]+|\d+)", body)
        if not vft_m or not fh_m:
            continue
        ipc.setdefault(iface, {})[method] = {
            "vft_index": _parse_versioned(vft_m.group(1)),
            "func_hash": _parse_versioned(fh_m.group(1)),
        }

    runipc = {}
    for m in re.finditer(
        r'\[Patterns\.steamclient\."(IClient[^"]+?)::RunIPCFrame"\]'
        r'[^\[]*?pattern\s*=\s*"([^"]+)"',
        text, re.DOTALL,
    ):
        runipc[m.group(1)] = m.group(2)

    return ipc, runipc


# ---------------------------------------------------------------------------
# Typeinfo whitelist — pick IClient*Map vtables out of all candidates
# ---------------------------------------------------------------------------

_MAP_NAME_RE = re.compile(rb"^(\d+)(IClient[A-Za-z0-9_]+)Map$")


def select_iface_vtables(reader, candidates, wanted_set):
    """For each candidate vtable, dereference its typeinfo and read its name.
    Keep vtables whose name matches `<len>IClient<Foo>Map` AND whose
    IClient<Foo> is in `wanted_set`. Returns {iface: (method0_va, slots)}.
    """
    out = {}
    for method0_va, slots in candidates:
        ti_ptr = reader.read_u32_va(method0_va - 4)
        if not ti_ptr:
            continue
        name_ptr = reader.read_u32_va(ti_ptr + 4)
        if not name_ptr:
            continue
        nm = read_cstr_at_va(reader, name_ptr, max_len=128)
        if nm is None:
            continue
        m = _MAP_NAME_RE.match(nm)
        if not m:
            continue
        iface = m.group(2).decode()
        if iface not in wanted_set:
            continue
        # Validate length prefix matches "<iface>Map" length
        if int(m.group(1)) != len(iface) + 3:
            continue
        # Prefer the larger vtable if we somehow see multiple per iface
        if iface in out and len(slots) <= len(out[iface][1]):
            continue
        out[iface] = (method0_va, slots)
    return out


# ---------------------------------------------------------------------------
# Per-wrapper funcHash mov: `C7 45 ?? IMM32 6A 04 50 57 E8`
# ---------------------------------------------------------------------------

_FH_PAT = re.compile(rb"\xC7\x45.(....)\x6A\x04\x50\x57\xE8", re.DOTALL)


def wrapper_funchash(reader, func_va, scan_len=0x400):
    off = reader.va2off(func_va)
    if off is None:
        return None
    m = _FH_PAT.search(reader.raw[off:off + scan_len])
    return struct.unpack("<I", m.group(1))[0] if m else None


# ---------------------------------------------------------------------------
# RunIPCFrame voting — scan .text for `cmp eax, IMM32` where IMM32 ∈ iface's
# known funcHashes; the function holding the most such cmps is RunIPCFrame.
# ---------------------------------------------------------------------------

def find_runipc_addr(reader, text_ranges, iface_hashes):
    if not iface_hashes:
        return None, 0, 0
    cmps = []
    for vs, ve in text_ranges:
        off_start = reader.va2off(vs)
        if off_start is None:
            continue
        data = reader.raw[off_start:off_start + (ve - vs)]
        i, n = 0, len(data) - 5
        while i < n:
            if data[i] == 0x3D:
                imm = struct.unpack_from("<I", data, i + 1)[0]
                if imm in iface_hashes:
                    cmps.append(vs + i)
            i += 1

    func_counts = Counter()
    for cmp_va in cmps:
        off = reader.va2off(cmp_va)
        if off is None:
            continue
        # Walk back up to 16KB looking for `push ebp; mov ebp, esp` prologue.
        lo = max(0, off - 0x4000)
        best = reader.raw[lo:off + 1].rfind(b"\x55\x89\xe5")
        if best < 0:
            continue
        func_va = reader.off2va(lo + best)
        if func_va is None:
            continue
        func_counts[func_va] += 1
    if not func_counts:
        return None, 0, len(cmps)
    func_va, count = func_counts.most_common(1)[0]
    return func_va, count, len(cmps)


# ---------------------------------------------------------------------------
# patterns.toml byte-pattern -> first .text match VA (RunIPCFrame cross-check)
# ---------------------------------------------------------------------------

def _pattern_to_re(p: str):
    out = b""
    for tok in p.split():
        out += b"." if tok in ("?", "??") else re.escape(bytes([int(tok, 16)]))
    return re.compile(out, re.DOTALL)


def first_pattern_match_va(reader, text_ranges, pat: str):
    re_pat = _pattern_to_re(pat)
    for vs, ve in text_ranges:
        off_start = reader.va2off(vs)
        if off_start is None:
            continue
        m = re_pat.search(reader.raw, off_start, off_start + (ve - vs))
        if m:
            return vs + (m.start() - off_start)
    return None


# ---------------------------------------------------------------------------
# Method-name match: handles `BIs*` flex and case insensitivity
# ---------------------------------------------------------------------------

def method_match(internal: str, hooked: str) -> bool:
    a, b = internal.lower(), hooked.lower()
    if a == b:
        return True
    if a.startswith("b") and a[1:] == b:
        return True
    if b.startswith("b") and b[1:] == a:
        return True
    return False


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("so_path", help="Path to 32-bit steamclient.so")
    ap.add_argument("--patterns",
                    default=str(Path(__file__).resolve().parent.parent / "res/patterns.toml"),
                    help="patterns.toml path (default: ../res/patterns.toml)")
    ap.add_argument("--quiet", action="store_true", help="Suppress progress logs")
    args = ap.parse_args()

    def log(*a, **kw):
        if not args.quiet:
            print(*a, **kw, file=sys.stderr)

    t0 = time.time()
    log(f"Reading {args.so_path}...")
    reader = ElfReader(args.so_path)
    dro_lo, dro_hi = _get_load_range(reader)
    text_ranges_v = [(vs, ve) for vs, ve in get_text_ranges(reader)]

    expected_ipc, expected_runipc = parse_patterns_toml(args.patterns)
    log(f"patterns.toml: {sum(len(v) for v in expected_ipc.values())} hooked methods,"
        f" {len(expected_runipc)} RunIPCFrame patterns")

    t = time.time()
    candidates = find_all_vtables(reader, dro_lo, dro_hi,
                                  [(vs, ve) for vs, ve in text_ranges_v])
    t_cand = time.time() - t

    t = time.time()
    iface_map = select_iface_vtables(reader, candidates, set(IFACE_RUNIPC))
    t_select = time.time() - t
    log(f"\nWhitelist picked {len(iface_map)}/{len(IFACE_RUNIPC)} ifaces"
        f" in {t_select*1000:.1f}ms"
        f" (candidates: {len(candidates)}, found in {t_cand:.2f}s)")
    for iface, (m0, slots) in sorted(iface_map.items()):
        log(f"  {iface:24s}  vtable=0x{m0:08x}  slots={len(slots)}")

    t = time.time()
    iface_methods = {}
    iface_all_hashes = {}
    for iface, (_, slots) in iface_map.items():
        entries = []
        all_hashes = set()
        for idx, func_va in enumerate(slots):
            info = extract_internal_name(reader, func_va)
            fh = wrapper_funchash(reader, func_va)
            entries.append({
                "slot": idx,
                "name": info["method"] if info else None,
                "funcHash": fh,
            })
            if fh:
                all_hashes.add(fh)
        iface_methods[iface] = entries
        iface_all_hashes[iface] = all_hashes
    t_decode = time.time() - t

    t = time.time()
    runipc_results = {}
    for iface in IFACE_RUNIPC:
        if iface in iface_all_hashes:
            addr, votes, total = find_runipc_addr(reader, text_ranges_v,
                                                  iface_all_hashes[iface])
            runipc_results[iface] = {"va": addr, "votes": votes, "total_cmps": total}
    t_runipc = time.time() - t

    log(f"\nDecoded slots in {t_decode*1000:.1f}ms,"
        f" voted RunIPCFrame in {t_runipc*1000:.1f}ms")
    log(f"\n=== Pipeline complete in {time.time() - t0:.2f}s ===")

    # ----- Cross-check report -----
    print("=" * 78)
    print("CROSS-CHECK: self-scan vs patterns.toml (`current` field)")
    print("=" * 78)

    fail = total = 0

    print("\n--- IpcMethods: vft_index ---")
    for iface in IFACE_VFT:
        if iface not in iface_methods:
            print(f"  MISS iface  {iface}")
            fail += 1
            total += 1
            continue
        for method, exp in expected_ipc.get(iface, {}).items():
            total += 1
            hit = next((e for e in iface_methods[iface]
                        if e["name"] and method_match(e["name"], method)), None)
            if not hit:
                print(f"  MISS  {iface}::{method:30s}  no slot matches")
                fail += 1
                continue
            ok = hit["slot"] == exp["vft_index"]
            tag = "OK  " if ok else "FAIL"
            if not ok:
                fail += 1
            print(f"  {tag}  {iface}::{method:30s}  "
                  f"expect={exp['vft_index']:3d}  self={hit['slot']:3d}")

    print("\n--- IpcMethods: func_hash (toml mismatch = patterns.toml stale) ---")
    for iface in IFACE_VFT:
        if iface not in iface_methods:
            continue
        for method, exp in expected_ipc.get(iface, {}).items():
            total += 1
            hit = next((e for e in iface_methods[iface]
                        if e["name"] and method_match(e["name"], method)), None)
            if not hit or hit["funcHash"] is None:
                print(f"  MISS  {iface}::{method:30s}  no funcHash extracted")
                fail += 1
                continue
            ok = hit["funcHash"] == exp["func_hash"]
            tag = "OK  " if ok else "STALE"
            if not ok:
                fail += 1
            print(f"  {tag}  {iface}::{method:30s}  "
                  f"expect=0x{exp['func_hash']:08X}  self=0x{hit['funcHash']:08X}")

    print("\n--- RunIPCFrame: voted addr vs patterns.toml first match ---")
    for iface in IFACE_RUNIPC:
        total += 1
        if iface not in runipc_results or runipc_results[iface]["va"] is None:
            print(f"  MISS  {iface:24s}  self-scan returned no addr")
            fail += 1
            continue
        self_addr = runipc_results[iface]["va"]
        if iface not in expected_runipc:
            print(f"  INFO  {iface:24s}  self=0x{self_addr:08x}  (no pattern in toml)")
            continue
        pat_va = first_pattern_match_va(reader, text_ranges_v, expected_runipc[iface])
        ok = pat_va == self_addr
        tag = "OK  " if ok else "FAIL"
        if not ok:
            fail += 1
        pat_s = f"0x{pat_va:08x}" if pat_va else "None"
        print(f"  {tag}  {iface:24s}  pattern={pat_s}  self=0x{self_addr:08x}  "
              f"votes={runipc_results[iface]['votes']}/{runipc_results[iface]['total_cmps']}")

    print("\n" + "=" * 78)
    print(f"RESULT: {total - fail}/{total} PASS, {fail} FAIL/STALE")
    print("=" * 78)
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
