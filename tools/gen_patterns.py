#!/usr/bin/env python3
# Generate C++ Pattern_t definitions + IpcHash constants from patterns.yaml.
# Host-side build tool; not shipped in the .so. Single source of truth is the YAML.
import sys, hashlib, json, yaml

MODULE_PTR = {            # module key -> lm_module_t* expression
    "steamclient": "nullptr",        # find() defaults to g_modSteamClient
    "steamui": "&g_modSteamUI",
}

def bytes_vec(hex_str):
    """Convert a space-separated hex string to a C++ initializer list.
    Wildcards ('?') are excluded. The original string is preserved as a comment."""
    if not hex_str:
        return "{}"
    parts = [b for b in hex_str.split() if b != "?"]
    inner = ", ".join("0x" + b for b in parts)
    return f"{{ {inner} }} /* {hex_str} */"

def split_name(key):
    segs = key.split("::")
    return segs[:-1], segs[-1]

def first_hash(val):
    """Extract the first (baked) hash value from a YAML entry.
    Supports: scalar (0x1234), list of scalars [0x1234, 0x5678],
    list of maps [{hash: 0x1234}, {hash: 0x5678, max_version: ...}]."""
    if isinstance(val, list):
        item = val[0]
        return item["hash"] if isinstance(item, dict) else item
    return val

def emit_ipchash(ipc_hashes):
    lines = ['#pragma once', '#include <cstdint>', '', 'namespace IpcHash {']
    all_hashes = []
    for iface, methods in (ipc_hashes or {}).items():
        lines.append(f"namespace {iface} {{")
        for method, val in methods.items():
            h = first_hash(val)
            lines.append(f"    static constexpr uint32_t k{method} = {h:#010x};")
            lines.append(f'    static constexpr const char* k{method}_Name = "{iface}::{method}";')
            all_hashes.append(f"{h:#010x}")
        lines.append("}")
    inits = ", ".join(all_hashes)
    lines.append(f"static constexpr uint32_t kAllBaked[] = {{ {inits} }};")
    lines.append("}")
    return "\n".join(lines) + "\n"

def emit(patterns, raw_bytes):
    baked_hash = hashlib.sha256(raw_bytes).hexdigest()
    hpp = ['#pragma once', 'extern const char* PATTERN_BAKED_HASH;', 'namespace Patterns {']
    cpp = ['#include "patterns.hpp"', '#include "globals.hpp"', '',
           f'const char* PATTERN_BAKED_HASH = "{baked_hash}";', '',
           'namespace Patterns {']

    for module, fns in (patterns or {}).items():
        modptr = MODULE_PTR[module]
        for key, spec in fns.items():
            ns, sym = split_name(key)
            opener = "".join(f"namespace {n} {{ " for n in ns)
            closer = " }" * len(ns)
            hpp.append(f"{opener}extern Pattern_t {sym};{closer}")

            follow = spec.get("follow", "None")
            prologue = bytes_vec(spec.get("prologue", ""))
            optional = "true" if spec.get("optional", False) else "false"
            cands = ",\n        ".join(json.dumps(c) for c in spec["candidates"])
            name_str = spec.get("name", key)
            cpp.append(f"{opener}Pattern_t {sym} {{")
            cpp.append(f'    {json.dumps(name_str)},')
            cpp.append(f"    {{ {cands} }},")
            cpp.append(f"    MemHlp::SigFollowMode::{follow},")
            cpp.append(f"    {prologue},")
            cpp.append(f"    {modptr},")
            cpp.append(f"    {optional}")
            cpp.append(f"}};{closer}")

    hpp.append("}")
    cpp.append("}")
    return "\n".join(hpp) + "\n", "\n".join(cpp) + "\n"

def main():
    if len(sys.argv) != 3:
        print("usage: gen_patterns.py <patterns.yaml> <out_dir>", file=sys.stderr)
        sys.exit(2)
    yml_path, out_dir = sys.argv[1], sys.argv[2]
    raw = open(yml_path, "rb").read()
    try:
        doc = yaml.safe_load(raw)
        if not isinstance(doc, dict):
            raise ValueError("YAML root must be a mapping")
        patterns = doc.get("Patterns") or {}
        ipc_hashes = doc.get("IpcHashes") or {}
        if patterns and not isinstance(patterns, dict):
            raise ValueError("Patterns must be a mapping")
        if ipc_hashes and not isinstance(ipc_hashes, dict):
            raise ValueError("IpcHashes must be a mapping")
        for module, fns in patterns.items():
            if module not in MODULE_PTR:
                raise ValueError(f"unknown module key: {module}")
            if not isinstance(fns, dict):
                raise ValueError(f"{module}: function list must be a mapping")
            for key, spec in fns.items():
                if not spec.get("candidates"):
                    raise ValueError(f"{module}.{key}: empty candidates")
        hpp, cpp = emit(patterns, raw)
        ipch = emit_ipchash(ipc_hashes)
    except Exception as e:
        print(f"gen_patterns: {e}", file=sys.stderr)
        sys.exit(1)
    open(f"{out_dir}/patterns.gen.hpp", "w").write(hpp)
    open(f"{out_dir}/patterns.gen.cpp", "w").write(cpp)
    open(f"{out_dir}/ipchash.gen.hpp", "w").write(ipch)

if __name__ == "__main__":
    main()
