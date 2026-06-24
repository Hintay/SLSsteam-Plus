{
  rev,
  slssteamVersion,
  lib,
  stdenv,
  pkgs,
  buildDotnetModule,
  dotnetCorePackages,
}: let
  # 32-bit package set. Every dependency archive linked into the final .so must be
  # i686 + match the project's pre-C++11 std::string ABI (Steam is built that way),
  # so the C++ deps below are compiled with -D_GLIBCXX_USE_CXX11_ABI=0.
  i686 = pkgs.pkgsi686Linux;

  # Parse ../deps.mk — the single source of truth for fetched dependency versions
  # + hashes, also `include`d by the Makefile. Each entry is a `NAME := VALUE`
  # line; turn the file into an attrset { NAME = "VALUE"; ... }. On the Nix side
  # libmem and protobuf read from here (lua comes from nixpkgs, toml++ is header-only); the
  # Makefile still uses every entry for its .7z / Arch from-source builds.
  deps = let
    lines = lib.splitString "\n" (builtins.readFile ../deps.mk);
    matches =
      builtins.filter (m: m != null)
      (builtins.map (l: builtins.match "[[:blank:]]*([A-Za-z0-9_]+)[[:blank:]]*:=[[:blank:]]*([^[:blank:]]+).*" l) lines);
  in
    builtins.listToAttrs
    (builtins.map (m: {
        name = builtins.elemAt m 0;
        value = builtins.elemAt m 1;
      })
      matches);

  # ABI/arch flags shared by the C++ dependency archives. -m32 is redundant under
  # the i686 stdenv but kept explicit to mirror the Makefile recipes; the ABI macro
  # is the load-bearing one (see above).
  abiCxxFlags = "-m32 -fPIC -D_GLIBCXX_USE_CXX11_ABI=0";
  abiCFlags = "-m32 -fPIC";

  # Build one i686, ABI-matched static archive (+ its headers) from a CMake source.
  # Used for protobuf-lite and libmem (the deps not available in current nixpkgs);
  # lua comes from nixpkgs. The default extraNixCflags (-include stdint.h)
  # fixes both old libs on modern gcc.
  #   libFile       : path under build/ of the produced .a
  #   headerCopySrc : source-relative dir copied to $out/include/<basename>
  mkAbiStaticLib = {
    pname,
    version,
    src,
    cmakeSrcDir ? ".",
    cmakeFlags ? [],
    target,
    libFile,
    headerCopySrc,
    preBuild ? "",
    extraNativeBuildInputs ? [],
    # Flags injected into EVERY compile via the cc-wrapper (reaches nested
    # ExternalProject sub-builds that cmake flags don't always propagate to).
    # Default -include stdint.h: keystone's vendored old LLVM (bundled by libmem)
    # relies on implicit <cstdint>/<stdint.h> includes that modern gcc (13+) no
    # longer provides transitively (intptr_t errors).
    extraNixCflags ? "-include stdint.h",
  }:
    i686.stdenv.mkDerivation {
      inherit pname version src;
      nativeBuildInputs = [pkgs.cmake] ++ extraNativeBuildInputs;
      NIX_CFLAGS_COMPILE = extraNixCflags;
      dontConfigure = true;
      buildPhase = ''
        runHook preBuild
        ${preBuild}
        cmake -S ${cmakeSrcDir} -B build \
          -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_CXX_FLAGS="${abiCxxFlags}" \
          -DCMAKE_C_FLAGS="${abiCFlags}" \
          ${lib.escapeShellArgs cmakeFlags}
        cmake --build build --target ${target} -j $NIX_BUILD_CORES
        runHook postBuild
      '';
      installPhase = ''
        runHook preInstall
        mkdir -p $out/lib $out/include
        cp build/${libFile} $out/lib/
        cp -r ${headerCopySrc} $out/include/
        runHook postInstall
      '';
    };

  # ---- Fetched sources (libmem + protobuf; lua from nixpkgs, toml++ header-only) --
  # nixpkgs-unstable has no protobuf 3.15 and does not package libmem at all, so
  # both are fetched from source here (versions/hashes from deps.mk).

  protobufVersion = deps.PROTOBUF_VER;
  protobufSrc = pkgs.fetchurl {
    url = "https://github.com/protocolbuffers/protobuf/releases/download/v${protobufVersion}/protobuf-cpp-${protobufVersion}.tar.gz";
    sha256 = deps.PROTOBUF_SHA256;
  };

  libmemVersion = deps.LIBMEM_VER;
  libmemSrc = pkgs.fetchurl {
    # The codeload tags URL ends in the bare version, so stdenv's unpackPhase can't
    # tell it's a tarball — force a .tar.gz name. (capstone/keystone below are
    # untarred explicitly in preBuild, so their names don't matter.)
    name = "libmem-${libmemVersion}.tar.gz";
    url = "https://codeload.github.com/rdbo/libmem/tar.gz/refs/tags/${libmemVersion}";
    sha256 = deps.LIBMEM_SHA256;
  };

  # libmem 5.1.0 records these as git submodules; GitHub source archives keep the
  # submodule directories empty, so the exact commits are staged into external/.
  libmemCapstoneRev = deps.LIBMEM_CAPSTONE_REV;
  libmemCapstoneSrc = pkgs.fetchurl {
    url = "https://codeload.github.com/rdbo/capstone/tar.gz/${libmemCapstoneRev}";
    sha256 = deps.LIBMEM_CAPSTONE_SHA256;
  };

  libmemKeystoneRev = deps.LIBMEM_KEYSTONE_REV;
  libmemKeystoneSrc = pkgs.fetchurl {
    url = "https://codeload.github.com/rdbo/keystone/tar.gz/${libmemKeystoneRev}";
    sha256 = deps.LIBMEM_KEYSTONE_SHA256;
  };

  # ---- Dependency derivations (each cached granularly in the store) --------------

  # Host protoc: the official prebuilt linux-x86_64 binary, patched for Nix with
  # autoPatchelfHook. Same 3.15.8 as the lite runtime below, so codegen and runtime
  # agree. Avoids compiling the full protoc from source (the slowest dep step) and
  # avoids pinning a whole old nixpkgs channel just for protobuf. HOST x86_64.
  protoc = pkgs.stdenv.mkDerivation {
    pname = "slssteam-protoc";
    version = protobufVersion;
    src = pkgs.fetchurl {
      url = "https://github.com/protocolbuffers/protobuf/releases/download/v${protobufVersion}/protoc-${protobufVersion}-linux-x86_64.zip";
      sha256 = deps.PROTOC_BIN_SHA256;
    };
    nativeBuildInputs = [pkgs.unzip pkgs.autoPatchelfHook];
    buildInputs = [pkgs.stdenv.cc.cc.lib pkgs.zlib];
    dontConfigure = true;
    unpackPhase = "unzip $src bin/protoc";
    installPhase = "install -Dm755 bin/protoc $out/bin/protoc";
  };

  # i686 libprotobuf-lite.a + headers, ABI-matched, built from the same 3.15.8 source
  # (deps.mk). Headers come from the source tree (src/google), mirroring -isystem src.
  protobufLite = mkAbiStaticLib {
    pname = "slssteam-protobuf-lite";
    version = protobufVersion;
    src = protobufSrc;
    cmakeSrcDir = "cmake";
    cmakeFlags = [
      "-DCMAKE_POLICY_VERSION_MINIMUM=3.5"
      "-Dprotobuf_BUILD_TESTS=OFF"
      "-Dprotobuf_BUILD_SHARED_LIBS=OFF"
      "-Dprotobuf_BUILD_PROTOC_BINARIES=OFF"
    ];
    target = "libprotobuf-lite";
    libFile = "libprotobuf-lite.a";
    headerCopySrc = "src/google";
  };

  # i686 liblibmem.a (bundles capstone/keystone) + headers, ABI-matched. LIBMEM_ARCH
  # is forced to i386 because CMake's host processor reads as x86_64.
  libmem = mkAbiStaticLib {
    pname = "slssteam-libmem";
    version = libmemVersion;
    src = libmemSrc;
    # keystone bundles LLVM, whose llvm-build tooling needs a Python interpreter.
    extraNativeBuildInputs = [pkgs.python3];
    # Two modern-gcc fixes, injected into every compile:
    #  - keystone's vendored old LLVM relies on implicit <cstdint> includes that
    #    new gcc no longer provides transitively (intptr_t errors).
    #  - libmem's src/linux/memory.c calls process_vm_readv/writev, which need
    #    _GNU_SOURCE to be declared (else implicit-declaration error on gcc 14+).
    extraNixCflags = "-include stdint.h -D_GNU_SOURCE";
    preBuild = ''
      # Stage the fixed capstone/keystone commits libmem's CMake expects.
      mkdir -p external/capstone external/keystone
      tar xzf ${libmemCapstoneSrc} -C external/capstone --strip-components=1
      tar xzf ${libmemKeystoneSrc} -C external/keystone --strip-components=1
      # Build only the X86 LLVM target in keystone — SLSsteam only assembles x86, but
      # keystone defaults to 7 targets, which dominates the build time. Inject into the
      # keystone sub-build (LLVM_TARGETS_TO_BUILD is a non-FORCE CACHE var → overrides "all").
      sed -i '/ExternalProject_Add(keystone-engine/ s/})$/} -DLLVM_TARGETS_TO_BUILD=X86)/' external/CMakeLists.txt
    '';
    cmakeFlags = [
      "-DLIBMEM_BUILD_TESTS=OFF"
      "-DLIBMEM_DEEP_TESTS=OFF"
      "-DLIBMEM_BUILD_STATIC=ON"
      "-DLIBMEM_ARCH=i386"
    ];
    target = "libmem";
    libFile = "liblibmem.a";
    headerCopySrc = "include/libmem";
  };

  # toml++ from nixpkgs (header-only, arch-independent — no i686 override needed).
  tomlpp = pkgs.tomlplusplus;

  # Lua 5.4 from nixpkgs (i686). It ships a static liblua.a + headers; Lua is C, so
  # the C++ ABI macro is irrelevant. Injected by full path below, so the liblua.a
  # name (vs the old liblua5.4.a) does not matter.
  luaLib = i686.lua5_4;

  # 64-bit Proton DLL injection helper. Freestanding C++17 (no STL, no
  # exceptions, no RTTI) so the clone()-spawned poll thread stays safe.
  # Also depends on src/feats/protoninject_protocol.h for the IPC protocol,
  # so the source fileset includes both directories.
  protonInject = pkgs.stdenv.mkDerivation {
    pname = "sls-proton-inject";
    version = rev;
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../tools/proton_inject
        ../src/feats/protoninject_protocol.h
      ];
    };
    dontConfigure = true;
    buildPhase = ''
      g++ -shared -fPIC -O2 -Wall -Wextra -Wpedantic \
        -std=c++17 -fno-exceptions -fno-rtti -fno-threadsafe-statics \
        -o sls_proton_inject.so \
        tools/proton_inject/inject.cpp \
        tools/proton_inject/loader.cpp \
        tools/proton_inject/ipc.cpp \
        tools/proton_inject/detour.cpp \
        tools/proton_inject/pe.cpp \
        tools/proton_inject/maps.cpp \
        tools/proton_inject/log.cpp
    '';
    installPhase = ''
      install -Dm755 sls_proton_inject.so $out/lib/sls_proton_inject.so
    '';
  };

  # ticket-grabber: the .NET companion CLI, built as its own derivation and
  # installed into $out below (see nix-modules/ticket-grabber.nix + deps.json).
  ticketGrabber = import ./ticket-grabber.nix {
    inherit rev buildDotnetModule dotnetCorePackages;
  };
in
  i686.stdenv.mkDerivation {
    pname = "SLSsteam";
    version = "${rev}";

    # Only the inputs that actually affect the .so build, so editing docs / CI /
    # README does not invalidate the (expensive) main compile.
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../src
        ../include
        ../res
        ../tools
        ../Makefile
        ../deps.mk
        ../embed-version.sh
        ../embed-config.sh
      ];
    };

    # No cmake here: every native dependency is a prebuilt derivation injected into
    # the Makefile below, so the main build only needs the compiler, pkg-config and
    # make (from stdenv).
    nativeBuildInputs = with pkgs; [
      pkg-config
      makeWrapper
      (python3.withPackages (ps: [ps.tomli]))
    ];

    buildInputs = with i686; [
      openssl
      which
      curl
    ];

    # Inject the prebuilt dependency archives/headers + host protoc into the
    # Makefile via its `?=` override points, and clear FETCHED_DEP_STAMPS so make
    # never runs its (network-bound, sandbox-incompatible) fetch/build rules. Nix
    # owns dependency building; the Makefile only compiles + links the project and
    # runs the protoc codegen.
    buildPhase = ''
      runHook preBuild
      make -j $NIX_BUILD_CORES bin/SLSsteam.so bin/library-inject.so \
        LUA_A=${luaLib}/lib/liblua.a \
        LUA_INCLUDE=${luaLib}/include \
        PROTOC=${protoc}/bin/protoc \
        PROTOBUF_LITE_A=${protobufLite}/lib/libprotobuf-lite.a \
        PROTOBUF_INCLUDE=${protobufLite}/include \
        LIBMEM_A=${libmem}/lib/liblibmem.a \
        LIBMEM_INCLUDE=${libmem}/include \
        TOMLPP_INCLUDE=${tomlpp}/include \
        SLSSTEAM_VERSION=${slssteamVersion} \
        SLSSTEAM_COMMIT=${rev} \
        FETCHED_DEP_STAMPS=
      runHook postBuild
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p $out/
      cp bin/SLSsteam.so $out/
      cp bin/library-inject.so $out/
      cp ${protonInject}/lib/sls_proton_inject.so $out/
      cp ${ticketGrabber}/bin/ticket-grabber $out/ticket-grabber

      # Set rpath for the dynamically-linked runtime deps (curl + openssl). All
      # other deps are statically linked, so they need no rpath entry.
      patchelf --set-rpath ${
        lib.makeLibraryPath [
          i686.curl
          i686.openssl
        ]
      } $out/SLSsteam.so
      runHook postInstall
    '';

    meta = {
      description = "Steamclient Modification for Linux";
      homepage = "https://github.com/AceSLS/SLSsteam";
      license = lib.licenses.agpl3Only;
      platforms = lib.platforms.linux;
    };
  }
