#!/usr/bin/env python3
# Generate Pattern_t definitions, IpcHash constants, and vtable indexes from patterns.toml.
# Host-side build tool; not shipped in the .so. Single source of truth is the TOML.
import sys, hashlib, json
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

def bake_hash(val):
    """Extract the baked (latest) hash value.
    val is a scalar int (simple) or a dict/table (versioned: 'current' + version keys).
    A baked value of 0 means the current build's hash is unknown/untrusted; the
    generated all-hash diagnostics skip it, but the named constant is still emitted.
    """
    if isinstance(val, int):
        return val
    if isinstance(val, dict):
        if "current" in val:
            return val["current"]
        raise ValueError("versioned hash table must have a 'current' key")
    raise ValueError(f"hash must be an integer or table, got {type(val).__name__}")

def bake_index(val):
    """Extract the baked (latest) vtable index.
    val is a scalar int (simple) or a dict/table (versioned: 'current' + version keys)."""
    if isinstance(val, int):
        return val
    if isinstance(val, dict):
        if "current" not in val:
            raise ValueError("versioned vft_index table must have a 'current' key")
        if not isinstance(val["current"], int):
            raise ValueError("vft_index 'current' must be an integer")
        for key, index in val.items():
            if not isinstance(index, int):
                raise ValueError(f"vft_index value for {key!r} must be an integer")
            if key != "current":
                try:
                    int(key)
                except ValueError:
                    raise ValueError(f"vft_index version key {key!r} must be numeric")
        return val["current"]
    raise ValueError(f"vft_index must be an integer or table, got {type(val).__name__}")

def versioned_index_entries(val):
    if isinstance(val, int):
        return [(val, 0)]
    current = [(val["current"], 0)]
    bounded = sorted((index, int(key)) for key, index in val.items() if key != "current")
    return current + bounded

def normalize_ipc_methods(doc):
    ipc_methods = doc.get("IpcMethods") or {}
    if "IpcHashes" in doc:
        raise ValueError("legacy IpcHashes is no longer supported; use IpcMethods.<Interface>.<Method>.func_hash")
    if ipc_methods:
        if not isinstance(ipc_methods, dict):
            raise ValueError("IpcMethods must be a mapping")
        for iface, methods in ipc_methods.items():
            if not isinstance(methods, dict):
                raise ValueError(f"IpcMethods.{iface}: method list must be a mapping")
            for method, spec in methods.items():
                if not isinstance(spec, dict):
                    raise ValueError(f"IpcMethods.{iface}.{method}: method spec must be a mapping")
                if "func_hash" not in spec:
                    raise ValueError(f"IpcMethods.{iface}.{method}: missing 'func_hash' field")
                bake_hash(spec["func_hash"])
                if "vft_index" in spec:
                    bake_index(spec["vft_index"])
        return ipc_methods

    return {}

def emit_ipchash(ipc_methods):
    lines = ['#pragma once', '#include <cstdint>', '', 'namespace IpcHash {']
    all_hashes = []
    for iface, methods in (ipc_methods or {}).items():
        lines.append(f"namespace {iface} {{")
        for method, spec in methods.items():
            h = bake_hash(spec["func_hash"])
            lines.append(f"    static constexpr uint32_t k{method} = {h:#010x};")
            lines.append(f'    static constexpr const char* k{method}_Name = "{iface}::{method}";')
            if h != 0:
                all_hashes.append(f"{h:#010x}")
        lines.append("}")
    inits = ", ".join(all_hashes)
    lines.append(f"static constexpr uint32_t kAllBaked[] = {{ {inits} }};")
    lines.append("}")
    return "\n".join(lines) + "\n"

def emit_vftableinfo(ipc_methods):
    lines = [
        '#pragma once',
        '',
        '#include "steamversion.hpp"',
        '',
        '#include <cstddef>',
        '#include <cstdint>',
        '',
        'namespace VFTIndexes {',
        'namespace Detail {',
        'struct VersionedIndex { int index; uint32_t maxVersion; };',
        'inline int pick(const VersionedIndex* items, size_t count)',
        '{',
        '    if (!items || count == 0) return -1;',
        '    const uint32_t ver = SteamVersion::get();',
        '    if (ver == 0) return items[0].index;',
        '    const VersionedIndex* best = nullptr;',
        '    for (size_t i = 0; i < count; ++i)',
        '    {',
        '        const uint32_t mv = items[i].maxVersion;',
        '        if (mv == 0)',
        '        {',
        '            if (!best || best->maxVersion != 0) best = &items[i];',
        '        }',
        '        else if (mv >= ver)',
        '        {',
        '            if (!best || best->maxVersion == 0 || mv < best->maxVersion) best = &items[i];',
        '        }',
        '    }',
        '    return best ? best->index : items[0].index;',
        '}',
        '}',
    ]
    for iface, methods in (ipc_methods or {}).items():
        indexed = [(method, spec["vft_index"]) for method, spec in methods.items() if "vft_index" in spec]
        if not indexed:
            continue
        lines.append(f"namespace {iface} {{")
        for method, val in indexed:
            if isinstance(val, int):
                lines.append(f"    static inline int {method}() {{ return {val}; }}")
            else:
                entries = ", ".join(f"{{ {index}, {max_version} }}" for index, max_version in versioned_index_entries(val))
                lines.append(f"    static inline int {method}()")
                lines.append("    {")
                lines.append(f"        static constexpr Detail::VersionedIndex kEntries[] = {{ {entries} }};")
                lines.append("        return Detail::pick(kEntries, sizeof(kEntries) / sizeof(kEntries[0]));")
                lines.append("    }")
        lines.append("}")
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
        ipc_methods = normalize_ipc_methods(doc)
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
        ipch = emit_ipchash(ipc_methods)
        vfti = emit_vftableinfo(ipc_methods)
    except Exception as e:
        print(f"gen_patterns: {e}", file=sys.stderr)
        sys.exit(1)
    open(f"{out_dir}/patterns.gen.hpp", "w").write(hpp)
    open(f"{out_dir}/patterns.gen.cpp", "w").write(cpp)
    open(f"{out_dir}/ipchash.gen.hpp", "w").write(ipch)
    open(f"{out_dir}/vftableinfo.gen.hpp", "w").write(vfti)

if __name__ == "__main__":
    main()
