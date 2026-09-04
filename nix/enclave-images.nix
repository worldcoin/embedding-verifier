{
  system,
  pkgs,
  nitro-util,
  enclaveBins,
  verifierModels,
}:
let
  nitroLib = nitro-util.lib.${system};
  nitroBlobs = nitroLib.blobs.x86_64;

  buildEnclaveImage =
    {
      workload,
      pname,
      extraRoot ? [ ],
    }:
    let
      version = enclaveBins.${pname}.version;
      imageName = "flamingo-verifier-${workload}-enclave";

      root = pkgs.runCommand "${pname}-root" { } ''
        mkdir -p "$out/bin" "$out/etc/ssl/certs"
        cp ${enclaveBins.${pname}}/bin/${pname} "$out/bin/${pname}"
        cp ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt "$out/etc/ssl/certs/ca-bundle.crt"
        ${
          if extraRoot == [ ] then
            ""
          else
            ''
              mkdir -p "$out/models"
              ${pkgs.lib.concatMapStringsSep "\n" (path: "cp -R ${path}/models/. \"$out/models/\"") extraRoot}
            ''
        }
      '';

      dockerArchive = pkgs.dockerTools.buildLayeredImage {
        name = imageName;
        tag = version;
        created = "1970-01-01T00:00:01Z";
        contents = [ root ];
        config = {
          Entrypoint = [ "/bin/${pname}" ];
          Env = [
            "RUST_LOG=info"
            "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
          ];
        };
      };

      ociImage =
        pkgs.runCommand "${pname}-oci-${version}"
          {
            nativeBuildInputs = [ pkgs.skopeo ];
          }
          ''
            mkdir -p "$out"
            skopeo --tmpdir "$TMPDIR" --insecure-policy copy \
              "docker-archive:${dockerArchive}" \
              "oci:$out:${version}"
          '';

      eif = nitroLib.buildEif {
        name = pname;
        inherit version;
        arch = "x86_64";
        kernel = nitroBlobs.kernel;
        kernelConfig = nitroBlobs.kernelConfig;
        nsmKo = nitroBlobs.nsmKo;
        init = nitroBlobs.init;
        copyToRoot = root;
        copyToRootWithClosure = false;
        entrypoint = "/bin/${pname}";
        env = ''
          RUST_LOG=info
          SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
        '';
      };
    in
    {
      oci = ociImage;
      inherit eif;
    };

  di = buildEnclaveImage {
    workload = "di";
    pname = "di-enclave";
  };
  verifier = buildEnclaveImage {
    workload = "verifier";
    pname = "flamingo-verifier-enclave";
    extraRoot = [ verifierModels ];
  };
in
{
  di-oci = di.oci;
  di-eif = di.eif;
  verifier-oci = verifier.oci;
  verifier-eif = verifier.eif;
}
