import subprocess, sys, tempfile, os, pathlib

GEN = pathlib.Path(__file__).parent / "gen_patterns.py"

SAMPLE = '''
[Patterns.steamclient."LoadDepotDecryptionKey"]
follow = "None"
candidates = ["55 57 56 53"]

[Patterns.steamclient."CUser::GetSubscribedApps"]
follow = "PrologueUpwards"
prologue = "55 89 E5"
candidates = ["8B 45 08"]

[Patterns.steamclient."CUser::PostCallback"]
name = "CSteamEngine::PostCallback"
follow = "None"
candidates = ["AA BB"]

[Patterns.steamui."SomeUIFn"]
follow = "Relative"
optional = true
candidates = ["E8 ? ? ? ?"]

[IpcHashes.IClientApps]
GetAppData = 0x87D25D33
GetDLCCount = 0x6EFFB356
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

    assert not os.path.exists(os.path.join(d, "vftableinfo.gen.hpp")), "vftableinfo.gen.hpp should not be generated"

    ipch = open(os.path.join(d, "ipchash.gen.hpp")).read()
    assert "kGetAppData = 0x87d25d33" in ipch, "hash constant must be emitted"
    assert 'kGetAppData_Name = "IClientApps::GetAppData"' in ipch, "name constant must be emitted"
    assert "kGetDLCCount" in ipch, "all IpcHashes entries must appear"
    assert "namespace IClientApps" in ipch

def test_bad_toml_fails():
    r, _ = run("Patterns = 'not a table'")
    assert r.returncode != 0

def test_escapes_special_chars():
    t = ('[Patterns.steamclient."Quoted"]\n'
         'name = "a\\"b"\n'
         'follow = "None"\n'
         'candidates = ["55"]\n')
    r, d = run(t)
    assert r.returncode == 0, r.stderr
    cpp = open(os.path.join(d, "patterns.gen.cpp")).read()
    assert '"a\\"b"' in cpp, "quote in name must be escaped as a valid C++ literal"

if __name__ == "__main__":
    test_generates_expected_symbols()
    test_bad_toml_fails()
    test_escapes_special_chars()
    print("gen_patterns_test OK")
