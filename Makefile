#Thanks to https://stackoverflow.com/questions/52034997/how-to-make-makefile-recompile-when-a-header-file-is-changed for the -MMD & -MP flags
#Without them headers wouldn't trigger recompilation

#Force g++ cause clang crashes on some hooks
CXX := g++
CC := gcc

include deps.mk

DEFAULT_LUA_A := obj/liblua5.4.a
DEFAULT_PROTOC := tools/protoc
DEFAULT_PROTOBUF_LITE_A := lib/libprotobuf-lite.a
DEFAULT_LIBMEM_A := lib/liblibmem.a

srcs := $(shell find src/ -type f -iname "*.cpp")
srcs := $(filter-out src/patterns.gen.cpp,$(srcs)) src/patterns.gen.cpp
objs := $(srcs:src/%.cpp=obj/%.o)
deps := $(objs:%.o=%.d)

# Pattern codegen from res/patterns.toml (see tools/gen_patterns.py).
PYTHON ?= python3
PATTERN_GEN_STAMP := src/.patterns-gen.stamp
$(PATTERN_GEN_STAMP): res/patterns.toml tools/gen_patterns.py
	$(PYTHON) tools/gen_patterns.py res/patterns.toml src
	@touch $@
src/patterns.gen.hpp src/patterns.gen.cpp: $(PATTERN_GEN_STAMP)
$(objs): | $(PATTERN_GEN_STAMP)

# Lua 5.4 is fetched at build time (checksum-verified, NOT committed to git) and
# built into a static archive linked into the .so. This removes any external
# 32-bit lua runtime dependency on every target (gcc .7z / Arch makepkg / Nix),
# matching upstream which only depends on openssl + curl.
# NOTE: deps.mk is the single source of truth for versions and hashes. The paths
# below are overridable so Nix/other external builds can inject their own headers
# and archives without using the Makefile's fetch/build rules.
LUA_DIR     ?= third_party/lua
LUA_STAMP   ?= $(LUA_DIR)/.fetched-$(LUA_VER)
LUA_INCLUDE ?= $(LUA_DIR)
LUA_A       ?= $(DEFAULT_LUA_A)

# protobuf is fetched + built at build time (host protoc + 32-bit libprotobuf-lite),
# mirroring the Lua handling above. NOT committed. External builds may override
# PROTOC / PROTOBUF_LITE_A / PROTOBUF_INCLUDE and clear FETCHED_DEP_STAMPS.
PROTOBUF_DIR     ?= third_party/protobuf
PROTOBUF_STAMP   ?= $(PROTOBUF_DIR)/.fetched-$(PROTOBUF_VER)
PROTOC           ?= $(DEFAULT_PROTOC)
PROTOBUF_LITE_A  ?= $(DEFAULT_PROTOBUF_LITE_A)
PROTOBUF_INCLUDE ?= $(PROTOBUF_DIR)/src

# libmem is fetched + built at build time to avoid committed headers/prebuilt .a
# blobs. The upstream static build bundles capstone/keystone/llvm into liblibmem.a,
# matching the old committed archive name.
LIBMEM_DIR     ?= third_party/libmem
LIBMEM_STAMP   ?= $(LIBMEM_DIR)/.fetched-$(LIBMEM_VER)
LIBMEM_A       ?= $(DEFAULT_LIBMEM_A)
LIBMEM_INCLUDE ?= $(LIBMEM_DIR)/include

# toml++ is a header-only C++17 library. No cmake, no .a — just fetch and -isystem.
TOMLPP_DIR     ?= third_party/tomlplusplus
TOMLPP_STAMP   ?= $(TOMLPP_DIR)/.fetched-$(TOMLPP_VER)
TOMLPP_INCLUDE ?= $(TOMLPP_DIR)/include


# All static libraries used by the final link. No prebuilt .a files are committed
# for the default build; external/Nix builds may override these paths.
STATIC_LIBS ?= $(LIBMEM_A) $(PROTOBUF_LITE_A)
FETCHED_DEP_STAMPS ?= $(LUA_STAMP) $(PROTOBUF_STAMP) $(LIBMEM_STAMP) $(TOMLPP_STAMP)

# The lua 5.4 library sources (everything except the lua.c/luac.c standalone
# mains). Hard-coded rather than $(wildcard) because the tree does not exist at
# parse time on a fresh checkout.
lua_names  := lapi lauxlib lbaselib lcode lcorolib lctype ldblib ldebug ldo \
              ldump lfunc lgc linit liolib llex lmathlib lmem loadlib lobject \
              lopcodes loslib lparser lstate lstring lstrlib ltable ltablib ltm \
              lundump lutf8lib lvm lzio
lua_objs   := $(lua_names:%=obj/luavendor/%.o)

CXXFLAGS := -O3 -flto=auto -fPIC -m32 -std=c++20 -Wall -Wextra -Wpedantic -Wno-error=format-security -D_GLIBCXX_USE_CXX11_ABI=0
CXXFLAGS += -I$(LUA_INCLUDE)
# Fetched third-party headers. Keep -isystem include for the small committed
# base64 header only.
CXXFLAGS += -isystem $(PROTOBUF_INCLUDE)
CXXFLAGS += -isystem $(LIBMEM_INCLUDE)
CXXFLAGS += -isystem $(TOMLPP_INCLUDE)
CXXFLAGS += -Iobj/proto

LDFLAGS := -shared -Wl,--no-undefined
LDFLAGS += $(shell pkg-config --libs "openssl")
LDFLAGS += $(shell pkg-config --libs "libcurl")
# Bundled lua is linked via $(LUA_A); -ldl satisfies loadlib's dlopen (a no-op
# stub on modern glibc, so it adds no external package dependency).
LDFLAGS += -ldl

SLSSTEAM_VERSION ?= $(shell if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then git log -1 --format=%cd --date=format:%Y%m%d%H%M%S; else date -u "+%Y%m%d%H%M%S"; fi)
SLSSTEAM_COMMIT ?= $(shell if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then git rev-parse --short=12 HEAD; else echo unknown; fi)
DATE := $(SLSSTEAM_VERSION)

ifeq ($(shell echo $$NATIVE),1)
	CXXFLAGS += -march=native
endif

#Speed up compilation if additional dependencies are found
ifeq ($(shell type ccache &> /dev/null && echo "found"),found)
	export PATH := /usr/lib/ccache/bin:$(PATH)
endif
ifeq ($(shell type mold &> /dev/null && echo "found"),found)
	LDFLAGS += -fuse-ld=mold
endif

# Smoke-test binary: validates Lua VM init + case-insensitive binding lookup.
# Self-contained: does not link SLSsteam internals (no libmem, no toml++, etc.).
# Run on the Deck: make lua_smoke && ./bin/lua_smoke
SMOKE_CXXFLAGS := -m32 -std=c++20 -O0 -g \
                  $(shell pkg-config --cflags "lua5.4")
SMOKE_LDFLAGS := $(shell pkg-config --libs "lua5.4")

bin/lua_smoke: tools/lua_smoke/smoke.cpp
	@mkdir -p bin
	$(CXX) $(SMOKE_CXXFLAGS) $< -o $@ $(SMOKE_LDFLAGS)

lua_smoke: bin/lua_smoke

bin/pkg_smoke: tools/pkg_smoke/smoke.cpp
	@mkdir -p bin
	g++ -std=c++17 -o bin/pkg_smoke tools/pkg_smoke/smoke.cpp

pkg_smoke: bin/pkg_smoke

bin/netpacket_smoke: tools/netpacket_smoke/smoke.cpp src/sdk/RawNetPacket.hpp src/sdk/RawNetPacket.cpp src/sdk/CNetPacket.hpp
	@mkdir -p bin
	g++ -std=c++20 -m32 -Og -g -o bin/netpacket_smoke tools/netpacket_smoke/smoke.cpp src/sdk/RawNetPacket.cpp

netpacket_smoke: bin/netpacket_smoke

bin/cloudsaves_smoke: tools/cloudsaves_smoke/smoke.cpp src/feats/cloudsaves/sha1.cpp src/feats/cloudsaves/manifest.cpp src/feats/cloudsaves/save_store.cpp src/feats/cloudsaves/peer_check.cpp src/feats/cloudsaves/appinfo_kv.cpp src/feats/cloudsaves/rpc_engine.cpp src/feats/cloudsaves/cloud_ui_reveal.cpp src/feats/cloudsaves/cloud_enable_policy.cpp obj/proto/slssteam_messages.pb.cc $(PROTOBUF_LITE_A)
	@mkdir -p bin
	g++ -std=c++20 -m32 -Og -g -D_GLIBCXX_USE_CXX11_ABI=0 -o bin/cloudsaves_smoke \
	  tools/cloudsaves_smoke/smoke.cpp src/feats/cloudsaves/sha1.cpp src/feats/cloudsaves/manifest.cpp src/feats/cloudsaves/save_store.cpp src/feats/cloudsaves/peer_check.cpp src/feats/cloudsaves/appinfo_kv.cpp src/feats/cloudsaves/rpc_engine.cpp src/feats/cloudsaves/cloud_ui_reveal.cpp src/feats/cloudsaves/cloud_enable_policy.cpp obj/proto/slssteam_messages.pb.cc \
	  -Iobj/proto -Isrc -isystem $(PROTOBUF_INCLUDE) -Llib -lprotobuf-lite

cloudsaves_smoke: bin/cloudsaves_smoke
	./bin/cloudsaves_smoke

bin/pattern_smoke: tools/pattern_smoke/smoke.cpp src/memhlp_pure.cpp src/memhlp.hpp
	@mkdir -p bin
	g++ -std=c++20 -m32 -Og -g -o bin/pattern_smoke tools/pattern_smoke/smoke.cpp src/memhlp_pure.cpp -Iinclude

pattern_smoke: bin/pattern_smoke
	./bin/pattern_smoke

audit-libs: bin/SLSsteam.so bin/library-inject.so tools/ticket-grabber/bin/Release/net9.0/linux-x64/publish/ticket-grabber

# Fetch + verify + unpack Lua sources on first build. Network is needed only
# here; the Nix build pre-stages the tree + this stamp (its sandbox has no net).
$(LUA_STAMP):
	@mkdir -p $(LUA_DIR)
	curl -fsSL "https://www.lua.org/ftp/lua-$(LUA_VER).tar.gz" -o "$(LUA_DIR)/lua.tar.gz"
	printf '%s  %s\n' "$(LUA_SHA256)" "$(LUA_DIR)/lua.tar.gz" | sha256sum -c -
	tar xzf "$(LUA_DIR)/lua.tar.gz" -C "$(LUA_DIR)" --strip-components=2 "lua-$(LUA_VER)/src"
	rm -f "$(LUA_DIR)/lua.tar.gz" "$(LUA_DIR)/lua.c" "$(LUA_DIR)/luac.c"
	touch "$@"

# Fetch + verify + unpack the full protobuf source tree (need cmake/ + src/, so no
# aggressive strip). Network is needed only here; the Nix build pre-stages this tree
# + stamp (its sandbox has no net).
$(PROTOBUF_STAMP):
	@mkdir -p $(PROTOBUF_DIR)
	curl -fsSL "https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOBUF_VER)/protobuf-cpp-$(PROTOBUF_VER).tar.gz" -o "$(PROTOBUF_DIR)/protobuf.tar.gz"
	printf '%s  %s\n' "$(PROTOBUF_SHA256)" "$(PROTOBUF_DIR)/protobuf.tar.gz" | sha256sum -c -
	tar xzf "$(PROTOBUF_DIR)/protobuf.tar.gz" -C "$(PROTOBUF_DIR)" --strip-components=1 "protobuf-$(PROTOBUF_VER)"
	rm -f "$(PROTOBUF_DIR)/protobuf.tar.gz"
	touch "$@"

# Fetch + verify + unpack libmem plus its fixed capstone/keystone submodules.
# The GitHub tarball keeps the submodule directories empty, while libmem's CMake
# requires them to build the bundled static archive.
$(LIBMEM_STAMP):
	@mkdir -p $(LIBMEM_DIR)
	curl -fsSL "https://codeload.github.com/rdbo/libmem/tar.gz/refs/tags/$(LIBMEM_VER)" -o "$(LIBMEM_DIR)/libmem.tar.gz"
	printf '%s  %s\n' "$(LIBMEM_SHA256)" "$(LIBMEM_DIR)/libmem.tar.gz" | sha256sum -c -
	tar xzf "$(LIBMEM_DIR)/libmem.tar.gz" -C "$(LIBMEM_DIR)" --strip-components=1 "libmem-$(LIBMEM_VER)"
	curl -fsSL "https://codeload.github.com/rdbo/capstone/tar.gz/$(LIBMEM_CAPSTONE_REV)" -o "$(LIBMEM_DIR)/capstone.tar.gz"
	printf '%s  %s\n' "$(LIBMEM_CAPSTONE_SHA256)" "$(LIBMEM_DIR)/capstone.tar.gz" | sha256sum -c -
	@mkdir -p "$(LIBMEM_DIR)/external/capstone"
	tar xzf "$(LIBMEM_DIR)/capstone.tar.gz" -C "$(LIBMEM_DIR)/external/capstone" --strip-components=1
	curl -fsSL "https://codeload.github.com/rdbo/keystone/tar.gz/$(LIBMEM_KEYSTONE_REV)" -o "$(LIBMEM_DIR)/keystone.tar.gz"
	printf '%s  %s\n' "$(LIBMEM_KEYSTONE_SHA256)" "$(LIBMEM_DIR)/keystone.tar.gz" | sha256sum -c -
	@mkdir -p "$(LIBMEM_DIR)/external/keystone"
	tar xzf "$(LIBMEM_DIR)/keystone.tar.gz" -C "$(LIBMEM_DIR)/external/keystone" --strip-components=1
	# Build only the X86 LLVM target in keystone — SLSsteam only assembles x86, but
	# keystone defaults to 7 targets (AArch64;ARM;Mips;PowerPC;Sparc;SystemZ;X86),
	# which is the single biggest chunk of build time. LLVM_TARGETS_TO_BUILD is a
	# non-FORCE CACHE var, so injecting it into the keystone sub-build overrides "all".
	sed -i '/ExternalProject_Add(keystone-engine/ s/})$$/} -DLLVM_TARGETS_TO_BUILD=X86)/' "$(LIBMEM_DIR)/external/CMakeLists.txt"
	rm -f "$(LIBMEM_DIR)/libmem.tar.gz" "$(LIBMEM_DIR)/capstone.tar.gz" "$(LIBMEM_DIR)/keystone.tar.gz"
	touch "$@"

# Fetch + verify + unpack toml++ (header-only). No build step — the stamp
# signals that headers are present under $(TOMLPP_INCLUDE).
$(TOMLPP_STAMP):
	@mkdir -p $(TOMLPP_DIR)
	curl -fsSL "https://github.com/marzer/tomlplusplus/archive/refs/tags/$(TOMLPP_VER).tar.gz" -o "$(TOMLPP_DIR)/tomlplusplus.tar.gz"
	printf '%s  %s\n' "$(TOMLPP_SHA256)" "$(TOMLPP_DIR)/tomlplusplus.tar.gz" | sha256sum -c -
	tar xzf "$(TOMLPP_DIR)/tomlplusplus.tar.gz" -C "$(TOMLPP_DIR)" --strip-components=1 "tomlplusplus-$(TOMLPP_VER:v%=%)"
	rm -f "$(TOMLPP_DIR)/tomlplusplus.tar.gz"
	touch "$@"

# Host protoc: download the official prebuilt linux-x86_64 binary for the pinned
# version instead of compiling protoc from source. Building the full protoc
# (libprotobuf + libprotoc + every language backend) is the slowest dep step, and
# protoc is only a build tool — the shipped runtime ($(PROTOBUF_LITE_A)) and the
# generated code still come from source, so reproducibility of the .so is intact.
# Hash-pinned (PROTOC_BIN_SHA256). HOST x86_64 — the .7z path builds on x86_64; the
# Nix path injects PROTOC from nixpkgs and never runs this rule.
$(DEFAULT_PROTOC):
	@mkdir -p tools "$(PROTOBUF_DIR)"
	curl -fsSL "https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOBUF_VER)/protoc-$(PROTOBUF_VER)-linux-x86_64.zip" -o "$(PROTOBUF_DIR)/protoc-bin.zip"
	printf '%s  %s\n' "$(PROTOC_BIN_SHA256)" "$(PROTOBUF_DIR)/protoc-bin.zip" | sha256sum -c -
	unzip -o -j "$(PROTOBUF_DIR)/protoc-bin.zip" "bin/protoc" -d tools
	rm -f "$(PROTOBUF_DIR)/protoc-bin.zip"
	chmod +x "$(DEFAULT_PROTOC)"

# Build the 32-bit libprotobuf-lite.a from the same fetched source. MUST match the
# project ABI: -m32 -fPIC and -D_GLIBCXX_USE_CXX11_ABI=0 (std::string ABI must agree
# with the rest of the .so). PROTOC_BINARIES OFF — only the lite runtime is built.
$(DEFAULT_PROTOBUF_LITE_A): $(PROTOBUF_STAMP)
	@mkdir -p lib $(PROTOBUF_DIR)/build-lite32
	cmake -S "$(PROTOBUF_DIR)/cmake" -B "$(PROTOBUF_DIR)/build-lite32" \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
		-Dprotobuf_BUILD_TESTS=OFF \
		-Dprotobuf_BUILD_SHARED_LIBS=OFF \
		-Dprotobuf_BUILD_PROTOC_BINARIES=OFF \
		-DCMAKE_CXX_FLAGS="-m32 -fPIC -D_GLIBCXX_USE_CXX11_ABI=0" \
		-DCMAKE_C_FLAGS="-m32 -fPIC"
	cmake --build "$(PROTOBUF_DIR)/build-lite32" --target libprotobuf-lite -j
	cp "$(PROTOBUF_DIR)/build-lite32/libprotobuf-lite.a" "$(DEFAULT_PROTOBUF_LITE_A)"

# Build 32-bit libmem and bundle its static dependencies into lib/liblibmem.a.
# LIBMEM_ARCH must be forced because CMake's host processor is x86_64 even when
# compiling with -m32.
$(DEFAULT_LIBMEM_A): $(LIBMEM_STAMP)
	@mkdir -p lib $(LIBMEM_DIR)/build-static32
	cmake -S "$(LIBMEM_DIR)" -B "$(LIBMEM_DIR)/build-static32" \
		-DCMAKE_BUILD_TYPE=Release \
		-DLIBMEM_BUILD_TESTS=OFF \
		-DLIBMEM_DEEP_TESTS=OFF \
		-DLIBMEM_BUILD_STATIC=ON \
		-DLIBMEM_ARCH=i386 \
		-DCMAKE_CXX_FLAGS="-m32 -fPIC -D_GLIBCXX_USE_CXX11_ABI=0" \
		-DCMAKE_C_FLAGS="-m32 -fPIC"
	cmake --build "$(LIBMEM_DIR)/build-static32" --target libmem -j
	cp "$(LIBMEM_DIR)/build-static32/liblibmem.a" "$(DEFAULT_LIBMEM_A)"

# Generate the single curated schema at build time. No .pb.cc -> .pb.cpp rename:
# the generated .cc is compiled directly by an explicit rule below.
proto_src := src/sdk/protobufs/slssteam_messages.proto
proto_gen := obj/proto/slssteam_messages.pb.cc
proto_obj := obj/proto/slssteam_messages.pb.o

$(proto_gen): $(proto_src) | $(PROTOC)
	@mkdir -p obj/proto
	$(PROTOC) --cpp_out=lite:obj/proto -I src/sdk/protobufs $<

$(proto_obj): $(proto_gen)
	@mkdir -p obj/proto
	$(CXX) $(CXXFLAGS) -isysteminclude -c $< -o $@

# The unpacked .c files are produced by the fetch step (order-only: the stamp's
# mtime must not force a rebuild of every object).
$(LUA_DIR)/%.c: | $(LUA_STAMP) ;

# Compile each lua source as C (gcc) into obj/luavendor/ — a separate tree from
# obj/lua/ (which holds the project's own src/lua/*.cpp) so the pattern rules
# never collide. LUA_USE_LINUX enables the POSIX/dlopen feature set; readline is
# only used by the excluded standalone interpreter.
obj/luavendor/%.o: $(LUA_DIR)/%.c | $(LUA_STAMP)
	@mkdir -p $(dir $@)
	$(CC) -m32 -fPIC -O2 -DLUA_USE_LINUX -I$(LUA_DIR) -c $< -o $@

$(DEFAULT_LUA_A): $(lua_objs)
	@mkdir -p $(dir $@)
	ar rcs $@ $^

# Project sources compile with -I$(LUA_INCLUDE) and some #include <lua.h>, so every
# object must wait for the lua fetch/extract. Order-only (|): the stamp's mtime
# must not force a full rebuild of the tree.
# proto_gen (slssteam_messages.pb.h) must also be present before any source
# that transitively includes it via CProtoBufMsgBase.hpp.
src/version.gen.hpp: embed-version.sh FORCE
	SLSSTEAM_VERSION="$(SLSSTEAM_VERSION)" SLSSTEAM_COMMIT="$(SLSSTEAM_COMMIT)" sh ./embed-version.sh

$(objs): | $(FETCHED_DEP_STAMPS) $(proto_gen) src/version.gen.hpp
$(proto_obj): | $(FETCHED_DEP_STAMPS)

bin/SLSsteam.so: $(objs) $(proto_obj) $(LUA_A) $(STATIC_LIBS)
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) $^ -o bin/SLSsteam.so $(LDFLAGS)

bin/library-inject.so: tools/library-inject/main.cpp tools/library-inject/build.sh
	sh tools/library-inject/build.sh
	@mkdir -p bin
	cp tools/library-inject/library-inject.so bin/library-inject.so

tools/ticket-grabber/bin/Release/net9.0/linux-x64/publish/ticket-grabber:
	sh tools/ticket-grabber/build.sh

-include $(deps)
obj/config.o: src/config.cpp res/config.toml
	$(shell sh ./embed-config.sh)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -isysteminclude -MMD -MP -c $< -o $@

-include $(deps)
obj/%.o : src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -isysteminclude -MMD -MP -c $< -o $@

clean:
	rm -rvf "obj/" "bin/" "zips/" "tools/ticket-grabber/bin"
	rm -f src/version.gen.hpp src/patterns.gen.hpp src/patterns.gen.cpp src/ipchash.gen.hpp src/vftableinfo.gen.hpp src/.patterns-gen.stamp

FORCE:

install:
	sh setup.sh

zips: rebuild
	@mkdir -p zips
	7z a -mx9 -m9=lzma2 \
		"zips/SLSsteam $(DATE).7z" \
		"bin/SLSsteam.so" \
		"bin/library-inject.so" \
		"setup.sh" \
		"docs/LICENSE" \
		"res/config.toml" \
		"tools/ticket-grabber/bin/Release/net9.0/linux-x64/publish/ticket-grabber"

	#Compatibility for Github issues
	7z a -mx9 -m9=lzma \
		"zips/SLSsteam $(DATE).zip" \
		"bin/SLSsteam.so" \
		"bin/library-inject.so" \
		"setup.sh" \
		"docs/LICENSE" \
		"res/config.toml" \
		"tools/ticket-grabber/bin/Release/net9.0/linux-x64/publish/ticket-grabber"

zips-config:
	7z a -mx9 -m9=lzma "zips/SLSsteam - SLSConfig $(DATE).zip" "$(HOME)/.config/SLSsteam/config.toml"
	#Compatibility for Github issues
	7z a -mx9 -m9=lzma2 "zips/SLSsteam - SLSConfig $(DATE).7z" "$(HOME)/.config/SLSsteam/config.toml"

# Build every dependency (fetched/compiled) but NOT the project itself. Lets a
# build run `make deps` first (deps build serially — each cmake sub-build already
# uses all cores, so no core over-subscription / OOM) and then `make -j ... bin/...`
# to compile the project's own objects in parallel. The Nix build injects prebuilt
# deps and skips this entirely.
deps: $(PROTOC) $(LUA_A) $(STATIC_LIBS) $(proto_gen)

build: audit-libs
rebuild: clean build
all: clean build zips

.PHONY: all build clean rebuild zips lua_smoke pkg_smoke netpacket_smoke cloudsaves_smoke pattern_smoke deps
.NOTPARALLEL: clean rebuild zips
