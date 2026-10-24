{
  description = "p2poolv2 - Peer to peer mining pool for bitcoin";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    flake-utils.url = "github:numtide/flake-utils";

    rust-overlay.url = "github:oxalica/rust-overlay";

    crane.url = "github:ipetkov/crane";

    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
      crane,
      advisory-db,
      ...
    }:

    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ rust-overlay.overlays.default ];
        pkgs = import nixpkgs {
          inherit system overlays;
          config = {
            allowUnfree = false;
          };
        };

        # Pin Rust to the minimum version required by the workspace (1.88)
        rust = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "rustfmt"
            "clippy"
          ];
        };

        # Native build inputs: tools needed at build time (pkg-config propagates
        # CFLAGS/LDFLAGS for the libraries below)
        nativeBuildInputs = with pkgs; [
          pkg-config
        ];

        # libclang is needed by bindgen (used by librocksdb-sys) to generate
        # FFI bindings.  bindgen does not respect LD_LIBRARY_PATH, so we set
        # LIBCLANG_PATH explicitly in the shellHook.
        libclang = pkgs.llvmPackages.libclang;

        # Build inputs: shared libraries the workspace links against
        buildInputs = with pkgs; [
          libclang
          openssl
          rocksdb
          zlib
          snappy
          zstd
          zeromq
        ];

        craneLib = (crane.mkLib pkgs).overrideToolchain rust;

        # craneLib.filterCargoSources only keeps .rs and .toml files by default.
        # Include .dat genesis files so include_bytes! can find them at build time.
        datFilter = path: _type: builtins.match ".*\\.dat$" path != null;
        cargoAndDat = path: type:
          (craneLib.filterCargoSources path type) || (datFilter path type);
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = cargoAndDat;
          name = "p2poolv2-source";
        };

        # Common args shared across all crane builds
        commonArgs = {
          inherit src;
          strictDeps = true;
          buildInputs = buildInputs;
          nativeBuildInputs = nativeBuildInputs;
          cargoLock = ./Cargo.lock;
          # bindgen (used by librocksdb-sys) needs LIBCLANG_PATH to find
          # libclang during the build, since it does not respect LD_LIBRARY_PATH.
          env.LIBCLANG_PATH = "${libclang.lib}/lib";
        };

        # First build only dependencies (used as a shared cache by subsequent
        # builds).  Both the workspace and individual packages depend on this
        # so the dependency tree is built once.
        depsOnly = craneLib.buildDepsOnly (commonArgs // { pname = "p2poolv2-deps"; });

        # Build the entire workspace (all crates, including dev-dependencies).
        # doCheck is false because the dev shell runs tests via `just test`.
        workspace = craneLib.buildPackage (
          commonArgs
          // {
            pname = "p2poolv2";
            cargoArtifacts = depsOnly;
            cargoExtraArgs = "--workspace";
            inherit (craneLib.crateNameFromCargoToml { inherit src; }) version;
            doCheck = false;
          }
        );

        # Individual binary packages, each depending on the shared deps-only
        # build to avoid rebuilding the dependency tree.
        p2poolv2_node = craneLib.buildPackage (
          commonArgs
          // {
            pname = "p2poolv2_node";
            cargoArtifacts = depsOnly;
            cargoExtraArgs = "-p p2poolv2_node";
            version = workspace.version;
            doCheck = false;
          }
        );

        p2poolv2_sim = craneLib.buildPackage (
          commonArgs
          // {
            pname = "p2poolv2_sim";
            cargoArtifacts = depsOnly;
            cargoExtraArgs = "-p p2poolv2_sim --features sim";
            version = workspace.version;
            doCheck = false;
          }
        );

      in
      {
        packages = {
          # Default package: the main node binary
          default = p2poolv2_node;

          # Workspace build (all crates)
          workspace = workspace;

          # Main node binary (also available as workspace default)
          p2poolv2_node = p2poolv2_node;

          # No-PoW load-test simulation binary
          p2poolv2_sim = p2poolv2_sim;
        };

        apps = {
          # Run the p2poolv2 node
          default = {
            type = "app";
            program = "${p2poolv2_node}/bin/p2poolv2";
          };
        };

        devShells.default = pkgs.mkShell {
          name = "p2poolv2-dev";
          packages = with pkgs; [
            # Rust toolchain (already includes rustc, cargo, rust-src, rustfmt,
            # clippy via the override above)
            rust

            # cargo-deny for license/advisory checks (used by `just deny`)
            pkgs.cargo-deny

            # Development tooling
            just
            cargo-nextest
            cargo-llvm-cov
            rust-analyzer
            nixpkgs-fmt
          ];
          buildInputs = buildInputs;
          nativeBuildInputs = nativeBuildInputs;
          shellHook = ''
            export RUST_BACKTRACE=1
            export RUST_LOG=info
            export LIBCLANG_PATH="${libclang.lib}/lib"
            echo "p2poolv2 development shell"
            echo "Rust: $(rustc --version)"
            echo "Clippy: $(cargo clippy --version)"
            echo "Crane: $(crane --version 2>/dev/null || echo 'not in PATH')"
          '';
        };

        formatter = pkgs.nixpkgs-fmt;
      }
    );
}
