{
  description = "libkrun with x86_64 PVH direct boot (feat/pvh-boot fork) — boots NetBSD/FreeBSD amd64 microVMs";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      # libkrun on macOS is a different beast (Hypervisor.framework + EFI, no
      # libkrunfw, not in nixpkgs) — this flake covers the Linux/KVM side, which
      # is what the PVH fork is for.
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems
          (system: f (import nixpkgs { inherit system; }));
    in
    {
      packages = forAllSystems (pkgs: rec {
        # Reuse nixpkgs' libkrun recipe (cargoSetupHook + bindgenHook, libkrunfw,
        # glibc.static for the init blob, the --no-as-needed libkrunfw RUSTFLAGS,
        # dev-output split) with this fork as the source. importCargoLock reads
        # our own Cargo.lock, so there is no vendor hash to keep in sync.
        libkrun = pkgs.libkrun.overrideAttrs (old: {
          pname = "libkrun-pvh";
          version = "1.19.4-pvh";
          src = self;
          cargoDeps = pkgs.rustPlatform.importCargoLock {
            lockFile = ./Cargo.lock;
          };
          # blk + net are what bsdkrun's BSD guests ride on (virtio-blk root,
          # virtio-net via gvproxy). Duplicate flags are harmless if nixpkgs'
          # recipe already sets them.
          makeFlags = (old.makeFlags or [ ]) ++ [ "BLK=1" "NET=1" ];
        });
        default = libkrun;
      });

      # `nix develop` — everything `make BLK=1 NET=1` needs (cargo, rustc,
      # bindgen/libclang, pkg-config, libkrunfw, static glibc), inherited from
      # the package itself so the two can't drift apart.
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ self.packages.${pkgs.stdenv.hostPlatform.system}.libkrun ];
          packages = with pkgs; [
            rustfmt
            clippy
            rust-analyzer
            patchelf
          ];
        };
      });
    };
}
