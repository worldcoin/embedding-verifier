{
  system,
  pkgs,
  nitro-util,
  enclaveBins,
  deepfaceModels,
}:
let
  nitroLib = nitro-util.lib.${system};
  nitroBlobs = nitroLib.blobs.x86_64;

  buildEnclaveImage =
    {
      pname,
      extraRoot ? [ ],
    }:
    let
      version = enclaveBins.${pname}.version;
      root = pkgs.buildEnv {
        name = "${pname}-root";
        paths = [
          enclaveBins.${pname}
          pkgs.cacert
        ]
        ++ extraRoot;
        pathsToLink = [
          "/bin"
          "/etc"
          "/models"
        ];
      };

      # dockerTools constructs the filesystem closure and image configuration without a
      # container daemon. Its timestamps, layer ordering and JSON are deterministic.
      dockerArchive = pkgs.dockerTools.buildLayeredImage {
        name = pname;
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

      # Expose a standards-compliant OCI image layout rather than dockerTools' transport
      # archive. skopeo preserves the reproducible config and layer bytes; the OCI manifests
      # are content-addressed, so this remains a pure Nix output.
      ociImage =
        pkgs.runCommand "${pname}-oci-${version}"
          {
            nativeBuildInputs = [ pkgs.skopeo ];
          }
          ''
            mkdir -p "$out"
            skopeo --insecure-policy copy \
              "docker-archive:${dockerArchive}" \
              "oci:$out:${version}"
          '';

      # aws-nitro-util consumes a directory, so materialize the OCI layers into their rootfs.
      # This is the only filesystem passed to EIF assembly: the OCI image is therefore the
      # explicit, independently buildable boundary between the workload and the EIF format.
      ociRootfs =
        pkgs.runCommand "${pname}-oci-rootfs-${version}"
          {
            nativeBuildInputs = [ pkgs.umoci ];
          }
          ''
            umoci raw unpack \
              --rootless \
              --image "${ociImage}:${version}" \
              "$out"
          '';

      eif = nitroLib.buildEif {
        name = pname;
        inherit version;
        arch = "x86_64";
        kernel = nitroBlobs.kernel;
        kernelConfig = nitroBlobs.kernelConfig;
        nsmKo = nitroBlobs.nsmKo;
        # AWS's blob init is the same binary used by nitro-cli-built EIFs. Keeping the
        # deterministic aws-nitro-util assembler avoids nitro-cli's timestamped EIF output.
        init = nitroBlobs.init;
        copyToRoot = ociRootfs;
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

  di = buildEnclaveImage { pname = "di-enclave"; };
  deepface = buildEnclaveImage {
    pname = "deepface-enclave";
    extraRoot = [ deepfaceModels ];
  };
in
{
  di-oci = di.oci;
  di-eif = di.eif;
  deepface-oci = deepface.oci;
  deepface-eif = deepface.eif;
}
