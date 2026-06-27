# i686 (32-bit) build toolchain for SLSsteam on SteamOS via Nix — no base-image changes
#
# Two toolchains are exposed to mirror nix-modules/default.nix, which produces
# a 32-bit SLSsteam.so (i686.stdenv) and a 64-bit sls_proton_inject.so
# (pkgs.stdenv). The interactive nix-shell PATH defaults to the i686 g++ used
# for the main .so build; HOST_CXX is pinned to the 64-bit g++ absolute path so
# `make bin/sls_proton_inject.so` produces a 64-bit ELF (which is what Wine's
# 64-bit ld.so will actually accept; a 32-bit helper is silently rejected).
{ pkgs ? import <nixpkgs> {} }:
let
  p = pkgs.pkgsi686Linux;
  hostGcc = pkgs.gcc;
in p.mkShell {
  # python3 + pyyaml are host build tools for the pattern codegen
  # (tools/gen_patterns.py); host pkgs, not the i686 set. hostGcc is the
  # 64-bit cross/host compiler used for the Proton injection helper.
  nativeBuildInputs = [ p.gcc p.gnumake p.pkg-config pkgs.cmake hostGcc
                        (pkgs.python3.withPackages (ps: [ ps.pyyaml ])) ];
  buildInputs = [ p.openssl p.curl p.lua5_4 ];

  shellHook = ''
    # Pin HOST_CXX so the Makefile rule for bin/sls_proton_inject.so always
    # invokes the 64-bit compiler, regardless of the i686 PATH ordering above.
    export HOST_CXX="${hostGcc}/bin/g++"
  '';
}
