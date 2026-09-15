{
  description = "YubiKey stack — ykman plus ed25519-sk ssh and signing conventions, as a home-manager module";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, home-manager }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in {
      homeManagerModules = {
        default = import ./modules/home-manager.nix;
        yubikey = import ./modules/home-manager.nix;
      };

      # `nix run .#ykman` without declaring the module, for a one-off check.
      packages = forAllSystems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          ykman = pkgs.yubikey-manager;
          default = self.packages.${system}.ykman;
        }
      );
    };
}
