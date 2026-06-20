{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    systems.url = "github:nix-systems/default";
    # rust-flake.url = "github:juspay/rust-flake";
    # rust-flake.inputs.nixpkgs.follows = "nixpkgs";
    crane.url = "github:ipetkov/crane";
    devenv.url = "github:cachix/devenv";

    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs"; 
    # Dev tools
    treefmt-nix.url = "github:numtide/treefmt-nix";
  };

  outputs = inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      systems = import inputs.systems;

      imports = [
        inputs.treefmt-nix.flakeModule
        # inputs.rust-flake.flakeModules.default
        # inputs.rust-flake.flakeModules.nixpkgs
        inputs.devenv.flakeModule
      ];

      perSystem = { config, self', pkgs, lib, system, ... }: let 
        rpkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [(import inputs.rust-overlay)];
        };
        # craneLib = (inputs.crane.mkLib pkgs);
        craneLib = (inputs.crane.mkLib rpkgs).overrideToolchain (p: p.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml);
          # stable.latest.default.override {
          #   targets = [ "wasm32-wasip1" ];
          # }\

        # src = lib.fileset.toSource {
        #     root = unfilteredRoot;
        #     fileset = lib.fileset.unions [
        #         (craneLib.fileset.commonCargoSources unfilteredRoot)
        #         ./migrations
        #         ./.sqlx
        #         ./static
        #         ./luckperms_api
        #         ./luckperms_reconciler
        #     ];
        # };

        src = craneLib.cleanCargoSource ./.;


        commonArgs = {
            inherit src;
            strictDeps = true;
            nativeBuildInputs = [
                pkgs.pkg-config
            ];
            buildInputs = [];
        };
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        individualCrateArgs = commonArgs // {
          inherit cargoArtifacts;
          inherit (craneLib.crateNameFromCargoToml { inherit src; }) version;
          # NB: we disable tests since we'll run them all via cargo-nextest
          doCheck = false;
        };

        unfilteredRoot = ./.;

        fileSetForCrate =
          crate:
          lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./migrations
              ./.sqlx
              ./static
              (craneLib.fileset.commonCargoSources ./luckperms_api)
              (craneLib.fileset.commonCargoSources ./luckperms_reconciler)
              (craneLib.fileset.commonCargoSources crate)
            ];
          };


        # oauth_bridge = craneLib.buildPackage (commonArgs // {
        #     inherit cargoArtifacts;
        #     nativeBuildInputs = (commonArgs.nativeBuildInputs or []) ++ [
        #         pkgs.sqlx-cli
        #     ];
        #     # preBuild = ''
        #     #     export DATABASE_URL=
        #     # '';
        # });
        oauth_bridge = craneLib.buildPackage (
          individualCrateArgs
          // {
            pname = "oauth_bridge";
            cargoExtraArgs = "-p oauth-bridge";
            src = fileSetForCrate ./.;
          }
        );
        luckperms_reconciler = craneLib.buildPackage (
          individualCrateArgs
          // {
            pname = "luckperms_reconciler";
            cargoExtraArgs = "-p luckperms_reconciler";
            src = fileSetForCrate ./luckperms_reconciler;
          }
        );
        # oauth_bridge = craneLib.buildPackage (commonArgs // {
        #     inherit cargoArtifacts;
        #     nativeBuildInputs = (commonArgs.nativeBuildInputs or []) ++ [
        #         pkgs.sqlx-cli
        #     ];
        #     # preBuild = ''
        #     #     export DATABASE_URL=
        #     # '';
        # });

        luckperms-openapi-spec = pkgs.fetchurl {
            url = "https://raw.githubusercontent.com/LuckPerms/rest-api/5ca1495e522d11f17d74d823ec32b93a9716460d/src/main/resources/luckperms-openapi.yml";
            hash = "sha256-N3SrTWxNbbMu5Jy6Oiq7tv0kfnfO205tCZO1mT7wsvU=";
        };
      in {
        # rust-project.crane.args = {
        #   buildInputs = lib.optionals pkgs.stdenv.isDarwin (
        #     with pkgs.darwin.apple_sdk.frameworks; [
        #       IOKit
        #     ]
        #   );
        # };

        # Add your auto-formatters here.
        # cf. https://numtide.github.io/treefmt/
        treefmt.config = {
          projectRootFile = "flake.nix";
          programs = {
            nixpkgs-fmt.enable = true;
            rustfmt.enable = true;
          };
        };

        devenv.shells.default = {
          languages.rust = {
              enable = true;
              wild.enable = true;
              toolchainFile = ./rust-toolchain.toml;
              # channel = "stable";
              # version = "latest";
          };

          languages.javascript.enable = true;
          packages = with pkgs; [ 
            cargo-watch 
            sqlx-cli 
            mold 
            openssl
            tailwindcss_4

            openapi-generator-cli
          ];

          env = {
            LUCKPERMS_OPENAPI_SPEC = "${luckperms-openapi-spec}";
            # RUSTFLAGS = "-Clink-arg=-fuse-ld=${pkgs.mold}/bin/mold";
          };

          # Spawn dependencies
          services.postgres = {
            enable = true;
            package = pkgs.postgresql_18;
            initialDatabases = [{ name = "mc_oauth_bridge"; }];

            extensions = extensions: [
              #extensions.postgis
              #extensions.timescaledb
            ];
            listen_addresses = "0.0.0.0";
            port = 5432;

            #settings.shared_preload_libraries = "timescaledb";
            initialScript = ''
              CREATE ROLE postgres SUPERUSER;
              ALTER USER postgres WITH LOGIN;
              ALTER USER postgres WITH PASSWORD 'postgres';
            '';
          };
          dotenv.enable = true;

          services.adminer = {
            enable = true;
            listen = "127.0.0.1:9090";
          };
          services.redis = {
            enable = true;
            #package = pkgs.keydb;
            #listen = ""
          };
          # pre-commit.hooks = {
          #   # lint shell scripts
          #   shellcheck.enable = true;
          #   clippy.enable = true;
          #   clippy.packageOverrides.cargo = pkgs.cargo;
          #   clippy.packageOverrides.clippy = pkgs.clippy;
          #   # some hooks provide settings
          #   clippy.settings.allFeatures = true;
          # };
        };

        # devShells.default = pkgs.mkShell {
        #   inputsFrom = [ self'.devShells.atlas ];
        #   packages = [ pkgs.cargo-watch pkgs.sqlx-cli];
        # };
        
        packages.default = oauth_bridge;
        packages.oauth_bridge = oauth_bridge;
        packages.luckperms_reconciler = luckperms_reconciler;

        packages.oauth_bridge_container = pkgs.dockerTools.buildImage {
          name = "oauth-bridge";
          config = {
            Cmd = [ "${oauth_bridge}/bin/oauth-bridge" ];
          };
        };
        packages.luckperms_reconciler_container = pkgs.dockerTools.buildImage {
          name = "luckperms_reconciler";
          config = {
            Cmd = [ "${luckperms_reconciler}/bin/luckperms_reconciler" ];
          };
        };
      };
    };
}

