{
  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOs/nixpkgs/nixos-unstable-small";
    shamir.flake = false;
    shamir.url = "github:aidanaden/shamir-zig";
    zig2nix.inputs.nixpkgs.follows = "nixpkgs";
    zig2nix.url = "github:Cloudef/zig2nix";
  };

  outputs = {self, ...} @ inputs:
    inputs.flake-parts.lib.mkFlake {inherit inputs;} {
      systems = inputs.nixpkgs.lib.systems.flakeExposed;
      perSystem = {
        pkgs,
        system,
        ...
      }: {
        packages = let
          zenv = inputs.zig2nix.outputs.zig-env.${system} {
            zig = inputs.zig2nix.outputs.packages.${system}.zig."0.13.0".bin;
          };
          build-zig = src: zigBuildZonLock: zenv.package {inherit src zigBuildZonLock;};
        in {
          shamir = build-zig (pkgs.lib.cleanSource inputs.zfe) ./build.zig.zon2json-lock;
        };
      };
    };
}
