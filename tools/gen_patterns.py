#!/usr/bin/env python3
# Generate Pattern_t definitions from patterns.toml.
# Host-side build tool; not shipped in the .so. Single source of truth is the TOML.
#
# Previously also emitted ipchash.gen.hpp + vftableinfo.gen.hpp from an
# [IpcMethods.*] table; that path is gone — vtable indices and funcHashes are now
# resolved at runtime by VtableScan from the live steamclient.so (see
# src/vtablescan.cpp). Any [IpcMethods.*] entries in patterns.toml are ignored
# silently — they can be deleted whenever convenient.
import sys, json
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

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

def bake_pattern(pat):
    """Extract the baked (latest) pattern string.
    pat is a string (simple) or a dict/table (versioned: 'current' + version keys)."""
    if isinstance(pat, str):
        if not pat:
            raise ValueError("pattern must not be empty")
        return pat
    if isinstance(pat, dict):
        if "current" not in pat:
            raise ValueError("versioned pattern table must have a 'current' key")
        if not pat["current"]:
            raise ValueError("pattern 'current' must not be empty")
        return pat["current"]
    raise ValueError(f"pattern must be a string or table, got {type(pat).__name__}")

def emit(patterns, raw_bytes):
    import hashlib
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

            sig = bake_pattern(spec["pattern"])
            follow = spec.get("follow", "None")
            prologue = bytes_vec(spec.get("prologue", ""))
            optional = "true" if spec.get("optional", False) else "false"
            cpp.append(f"{opener}Pattern_t {sym} {{")
            cpp.append(f'    {json.dumps(spec.get("name", key))},')
            cpp.append(f"    {json.dumps(sig)},")
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
        print("usage: gen_patterns.py <patterns.toml> <out_dir>", file=sys.stderr)
        sys.exit(2)
    toml_path, out_dir = sys.argv[1], sys.argv[2]
    raw = open(toml_path, "rb").read()
    try:
        doc = tomllib.loads(raw.decode())
        if not isinstance(doc, dict):
            raise ValueError("TOML root must be a mapping")
        patterns = doc.get("Patterns") or {}
        if patterns and not isinstance(patterns, dict):
            raise ValueError("Patterns must be a mapping")
        for module, fns in patterns.items():
            if module not in MODULE_PTR:
                raise ValueError(f"unknown module key: {module}")
            if not isinstance(fns, dict):
                raise ValueError(f"{module}: function list must be a mapping")
            for key, spec in fns.items():
                if "pattern" not in spec:
                    raise ValueError(f"{module}.{key}: missing 'pattern' field")
                bake_pattern(spec["pattern"])
        hpp, cpp = emit(patterns, raw)
    except Exception as e:
        print(f"gen_patterns: {e}", file=sys.stderr)
        sys.exit(1)
    open(f"{out_dir}/patterns.gen.hpp", "w").write(hpp)
    open(f"{out_dir}/patterns.gen.cpp", "w").write(cpp)

if __name__ == "__main__":
    main()
