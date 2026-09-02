{ pkgs, src }:
pkgs.rustPlatform.buildRustPackage {
  pname = "aws-nitro-enclaves-cli";
  version = "1.4.2";

  inherit src;
  cargoLock.lockFile = src + "/Cargo.lock";

  nativeBuildInputs = [ pkgs.pkg-config ];
  buildInputs = [ pkgs.openssl ];

  cargoBuildFlags = [
    "--bin"
    "nitro-cli"
  ];
  doCheck = false;

  postInstall = ''
    mkdir -p "$out/share/aws-nitro-enclaves-cli/blobs"
    cp -r "$src/blobs/x86_64" "$out/share/aws-nitro-enclaves-cli/blobs/"
  '';
}
