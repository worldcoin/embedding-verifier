{
  description = "embedding-verifier — reproducible Nitro enclave images";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nitro-cli-src = {
      url = "github:aws/aws-nitro-enclaves-cli/v1.4.2";
      flake = false;
    };
  };

  outputs =
    {
      nixpkgs,
      crane,
      rust-overlay,
      nitro-cli-src,
      ...
    }:
    let
      root = ./.;
      # EIFs are linux/amd64 only, so there is nothing to gain from other systems here.
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
      enclaveBins = import ./nix/enclave-binaries.nix {
        inherit root pkgs crane;
      };
      faceModels = import ./nix/face-models.nix {
        inherit pkgs;
      };
      nitroCli = import ./nix/nitro-cli.nix {
        inherit pkgs;
        src = nitro-cli-src;
      };
      enclaveImages = import ./nix/enclave-images.nix {
        inherit pkgs enclaveBins nitroCli;
        deepfaceModels = faceModels.package;
      };
    in
    {
      packages.${system} =
        enclaveBins
        // enclaveImages
        // {
          default = enclaveImages.deepface-oci;
          deepfaceModels = faceModels.package;
          nitro-cli = nitroCli;
        };

      faceModels = faceModels.metadata;

      devShells = import ./nix/dev-shells.nix {
        inherit root nixpkgs rust-overlay;
      };
    };
}
