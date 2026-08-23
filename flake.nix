{ description = "p2poolv2 - Peer to peer mining pool for bitcoin";

inputs = {
  nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  flake-utils.url = "github:numtide/flake-utils";
  rust-overlay.url = "github:oxalica/rust-overlay";
  crane.url = "github:ipetkov/crane";
};

outputs = { self, nixpkgs, flake-utils, rust-overlay, crane, ... }:
  flake-utils.lib.eachDefaultSystem (system:
    let
      overlays = [ rust-overlay.overlays.default ];
      pkgs = import nixpkgs {
        inherit system overlays;
        config = { allowUnfree = false; };
      };

      # Pin Rust to the version required by the workspace (1.88)
      rust = pkgs.rust-bin.stable.latest.default.override {
        extensions = [ "rust-src" "rustfmt" "clippy" ];
      };

      # System dependencies required by workspace crates
      nativeBuildInputs = with pkgs; [
        pkg-config
        openssl
        rocksdb
        zlib
        snappy
        zstd
        zeromq
        protobuf
      ];

      buildInputs = with pkgs; [
        openssl
        rocksdb
        zlib
        snappy
        zstd
        zeromq
      ];

      craneLib = (crane.mkLib pkgs).overrideToolchain rust;

      src = craneLib.cleanCargoSource ./.;

      # Common args for all crane builds
      commonArgs = {
        inherit src;
        strictDeps = true;
        buildInputs = buildInputs;
        nativeBuildInputs = nativeBuildInputs;
        cargoLock = { lockFile = ./Cargo.lock; };
      };

      # Build the whole workspace
      workspaceArtifacts = craneLib.buildDepsOnly commonArgs;

      workspace = craneLib.buildPackage (commonArgs // {
        cargoExtraArgs = "--workspace";
      });

    in {
      packages = {
        default = workspace;
        # Convenience packages for the main binaries
        p2poolv2_node = craneLib.buildPackage (commonArgs // {
          pname = "p2poolv2_node";
          version = "0.10.4";
          cargoExtraArgs = "-p p2poolv2_node";
        });
        p2poolv2_cli = craneLib.buildPackage (commonArgs // {
          pname = "p2poolv2_cli";
          version = "0.10.4";
          cargoExtraArgs = "-p p2poolv2_cli";
        });
        p2poolv2_api = craneLib.buildPackage (commonArgs // {
          pname = "p2poolv2_api";
          version = "0.10.4";
          cargoExtraArgs = "-p p2poolv2_api";
        });
      };

      apps = {
        default = {
          type = "app";
          program = "${self.packages.${system}.p2poolv2_node}/bin/p2poolv2";
        };
      };

      devShells.default = pkgs.mkShell {
        name = "p2poolv2-dev";
        packages = with pkgs; [
          rust
          cargo
          rustfmt
          clippy
          just
          pkg-config
          openssl
          rocksdb
          zeromq
          zlib
          snappy
          zstd
          protobuf
        ];
        buildInputs = buildInputs;
        nativeBuildInputs = nativeBuildInputs;
        shellHook = ''
          export RUST_BACKTRACE=1
          export RUST_LOG=info
          echo "p2poolv2 development shell"
          echo "Rust: $(rustc --version)"
        '';
      };

      formatter = pkgs.nixpkgs-fmt;
    }
  );
}
