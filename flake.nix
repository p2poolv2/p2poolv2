{
  description = "P2Poolv2 - Peer to peer mining pool for bitcoin";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-26.05";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      rust-overlay,
      crane,
      ...
    }:

    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
        # adopt rust toolchain from rust-toolchain.toml file
        rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

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
        cargoAndDat = path: type: (craneLib.filterCargoSources path type) || (datFilter path type);
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
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [
            rust
            pkgs.cargo-nextest
            pkgs.pkg-config
            pkgs.cmake
            pkgs.rustPlatform.bindgenHook
            pkgs.just

            # needed for justfile
            pkgs.cargo-llvm-cov
            pkgs.cargo-deny
          ];
        };
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

        formatter = pkgs.nixpkgs-fmt;
      }
    );
}
