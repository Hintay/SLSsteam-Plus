import subprocess, sys, tempfile, os, pathlib

GEN = pathlib.Path(__file__).parent / "gen_patterns.py"

SAMPLE = '''
[Patterns.steamclient."LoadDepotDecryptionKey"]
follow = "None"
pattern = "55 57 56 53"

[Patterns.steamclient."CUser::GetSubscribedApps"]
follow = "PrologueUpwards"
prologue = "55 89 E5"
pattern = "8B 45 08"

[Patterns.steamclient."CUser::PostCallback"]
name = "CSteamEngine::PostCallback"
follow = "None"
pattern = "AA BB"

[Patterns.steamui."SomeUIFn"]
follow = "Relative"
optional = true
pattern = "E8 ? ? ? ?"

[IpcMethods.IClientApps.GetAppData]
vft_index = 0
func_hash = 0x87D25D33

[IpcMethods.IClientApps.GetDLCCount]
vft_index = { current = 8, 1781041600 = 8 }
func_hash = 0x6EFFB356

[IpcMethods.IClientApps.UnknownCurrentHash]
vft_index = 11
func_hash = 0
'''

def run(toml_text):
    d = tempfile.mkdtemp()
    toml_file = os.path.join(d, "patterns.toml")
    open(toml_file, "w").write(toml_text)
    r = subprocess.run([sys.executable, str(GEN), toml_file, d],
                       capture_output=True, text=True)
    return r, d

def test_generates_expected_symbols():
    r, d = run(SAMPLE)
    assert r.returncode == 0, r.stderr
    hpp = open(os.path.join(d, "patterns.gen.hpp")).read()
    cpp = open(os.path.join(d, "patterns.gen.cpp")).read()

    assert "namespace CUser" in hpp and "extern Pattern_t GetSubscribedApps;" in hpp
    assert "extern Pattern_t LoadDepotDecryptionKey;" in hpp
    assert '"CUser::GetSubscribedApps"' in cpp
    assert "55 89 E5" in cpp
    assert "SigFollowMode::PrologueUpwards" in cpp
    assert "true" in cpp
    assert "&g_modSteamUI" in cpp
    assert "PATTERN_BAKED_HASH" in cpp
    assert "extern const char* PATTERN_BAKED_HASH;" in hpp

    assert "extern Pattern_t PostCallback;" in hpp, "PostCallback symbol must appear in hpp"
    cuser_block = hpp[hpp.index("namespace CUser"):]
    assert "extern Pattern_t PostCallback;" in cuser_block, "PostCallback must be in namespace CUser"
    assert '"CSteamEngine::PostCallback"' in cpp, "name field must be used as Pattern_t name string"
    assert '"CUser::PostCallback"' not in cpp, "key must not bleed through as name string when name: is set"

    ipch = open(os.path.join(d, "ipchash.gen.hpp")).read()
    assert "kGetAppData = 0x87d25d33" in ipch, "hash constant must be emitted"
    assert 'kGetAppData_Name = "IClientApps::GetAppData"' in ipch, "name constant must be emitted"
    assert "kGetDLCCount" in ipch, "all IpcMethods entries must appear"
    assert "kUnknownCurrentHash = 0x00000000" in ipch, "unknown current hash constant must be emitted"
    assert "0x00000000" not in ipch[ipch.index("kAllBaked"):], "unknown current hash must not be checked globally"
    assert "namespace IClientApps" in ipch

    vfti = open(os.path.join(d, "vftableinfo.gen.hpp")).read()
    assert "namespace VFTIndexes" in vfti, "vtable index namespace must be emitted"
    assert '#include "steamversion.hpp"' in vfti, "versioned vtable indexes need SteamVersion"
    assert "static inline int GetAppData() { return 0; }" in vfti, "scalar vtable index must be emitted as selector function"
    assert "static inline int GetDLCCount()" in vfti, "versioned vtable index must be emitted as selector function"
    assert "VersionedIndex kEntries[]" in vfti, "versioned vtable index table must be emitted"
    assert "{ 8, 0 }" in vfti, "current vtable index must be emitted"
    assert "{ 8, 1781041600 }" in vfti, "bounded vtable index must be emitted"

def test_bad_toml_fails():
    r, _ = run("Patterns = 'not a table'")
    assert r.returncode != 0

def test_escapes_special_chars():
    t = ('[Patterns.steamclient."Quoted"]\n'
         'name = "a\\"b"\n'
         'follow = "None"\n'
         'pattern = "55"\n')
    r, d = run(t)
    assert r.returncode == 0, r.stderr
    cpp = open(os.path.join(d, "patterns.gen.cpp")).read()
    assert '"a\\"b"' in cpp, "quote in name must be escaped as a valid C++ literal"

if __name__ == "__main__":
    test_generates_expected_symbols()
    test_bad_toml_fails()
    test_escapes_special_chars()
    print("gen_patterns_test OK")
