{
  description = "SLSsteam";

  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    forAllSystems = fn:
      nixpkgs.lib.genAttrs nixpkgs.lib.platforms.linux (
        system:
          fn (import nixpkgs {
            inherit system;
            config.allowUnfreePredicate = pkg:
              builtins.elem (nixpkgs.lib.getName pkg) ["steam" "steam-unwrapped"];
          })
      );

    rev = self.rev or self.dirtyRev or "unknown";
    slssteamVersion = self.lastModifiedDate or "19700101000000";
  in {
    formatter = forAllSystems (pkgs: pkgs.alejandra);

    packages = forAllSystems (pkgs: rec {
      sls-steam = pkgs.callPackage ./nix-modules/default.nix {inherit rev slssteamVersion;};
      wrapped = pkgs.callPackage ./nix-modules/wrapped.nix {inherit rev;};
      default = sls-steam;
    });

    homeModules = {
      sls-steam = import ./nix-modules/home.nix;
    };
  };
}
