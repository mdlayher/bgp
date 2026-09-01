{
  description = "Development environment for github.com/mdlayher/bgp";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages =
            [
              # go.mod's language version floor is what this must
              # satisfy; bump alongside it.
              pkgs.go_1_27
            ]
            ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
              # The interop suite's netns runtime (Linux only): frr on
              # $PATH puts vtysh where the harness discovers the
              # daemons when Docker is unavailable, and iproute2 wires
              # the veth pair. flake.lock pins nixpkgs, so FRR only
              # moves on a deliberate flake update — and must then
              # still match the frrVersion pin in interop/frr.go,
              # whose version tripwire is the backstop.
              pkgs.frr
              pkgs.iproute2
            ];
        };
      });
    };
}
