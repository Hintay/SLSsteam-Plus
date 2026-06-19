# i686 (32-bit) build toolchain for SLSsteam on SteamOS via Nix — no base-image changes
{ pkgs ? import <nixpkgs> {} }:
let p = pkgs.pkgsi686Linux;
in p.mkShell {
  # python3 + pyyaml are host build tools for the pattern codegen
  # (tools/gen_patterns.py); host pkgs, not the i686 set.
  nativeBuildInputs = [ p.gcc p.gnumake p.pkg-config pkgs.cmake
                        (pkgs.python3.withPackages (ps: [ ps.pyyaml ])) ];
  buildInputs = [ p.openssl p.curl p.lua5_4 ];
}
