{
  description = "libkrun with x86_64 PVH direct boot (feat/pvh-boot fork) — boots NetBSD/FreeBSD amd64 microVMs";

  # CI (.github/workflows/nix.yml) builds every push of this branch and pushes
  # the result here — declare the cache so consumers substitute instead of
  # compiling (nix asks once to trust it).
  nixConfig = {
    extra-substituters = [ "https://bsdkrun.cachix.org" ];
    extra-trusted-public-keys =
      [ "bsdkrun.cachix.org-1:KzvN59TR6k15k7Fl7SxTEhxJnE0MvbxLC2HpxdVlC9Q=" ];
  };

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
          # Filter docs/CI/flake files out of the source so commits that only
          # touch them don't change the derivation — otherwise every push
          # (src = self) would invalidate the Cachix cache for consumers.
          src = nixpkgs.lib.cleanSourceWith {
            name = "libkrun-pvh-src";
            src = self;
            filter = path: _type:
              let base = baseNameOf path;
              in
              !(base == ".github" || base == "flake.nix" || base == "flake.lock"
                || nixpkgs.lib.hasSuffix ".md" base);
          };
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
