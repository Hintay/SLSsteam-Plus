# Single source of truth for the fetched third-party dependency versions + hashes.
#
# Consumed by BOTH:
#   - Makefile               via `include deps.mk`
#   - nix-modules/default.nix via parseDeps (builtins.match over this file)
#
# Edit a version/hash HERE only — never duplicate these values elsewhere. The
# Nix sandbox has no network, so default.nix re-fetches the identical tarballs as
# fixed-output derivations; reading them from this file keeps the two build paths
# from drifting (a mismatch used to be a silent build break).
#
# FORMAT CONTRACT: every dependency fact is a single `NAME := VALUE` line with no
# spaces in VALUE. The nix-side parser matches exactly this shape, so keep new
# entries in the same form (plain assignments, comments start with '#').

LUA_VER    := 5.4.8
LUA_SHA256 := 4f18ddae154e793e46eeab727c59ef1c0c0c2b744e7b94219710d76f530629ae

PROTOBUF_VER    := 3.15.8
PROTOBUF_SHA256 := 9b57647b898e45253c98fae35146f6a5e9e788817d29019f9280270c951a0038
# Official prebuilt host protoc (linux-x86_64) for the same version — the Makefile
# downloads this instead of compiling protoc from source (the from-source build of
# the full protoc/libprotoc is the slowest dep step). The shipped runtime + codegen
# stay from-source; only the build tool is fetched. The Nix path ignores this (it
# gets protoc from nixpkgs).
PROTOC_BIN_SHA256 := b9ff821d2a4f9e9943dc2a13e6a76d99c7472dac46ddd3718a3a4c3b877c044a

LIBMEM_VER    := 5.1.0
LIBMEM_SHA256 := 9f61b53ce86fd59afb13bc4f48db40e8c8dc156f56879b9e9929014924f95495
LIBMEM_CAPSTONE_REV    := 929d0ff8daf599d6a7f81487651477580e7876f0
LIBMEM_CAPSTONE_SHA256 := 3af1dd92c3e4359e6cb108004288631bc42e1101ae0e6bf2799fae6b02029eb0
LIBMEM_KEYSTONE_REV    := 484ba14eb77a0acc1b12cd66cee1fe2056232242
LIBMEM_KEYSTONE_SHA256 := f9d04c917cdf834e6c761614684c367540e7df14dc9fea9f72608d6450ae613d

TOMLPP_VER    := v3.4.0
TOMLPP_SHA256 := 8517f65938a4faae9ccf8ebb36631a38c1cadfb5efa85d9a72e15b9e97d25155
