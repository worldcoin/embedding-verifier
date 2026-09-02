{
  pkgs,
  enclaveBins,
  nitroCli,
  deepfaceModels,
}:
let
  buildEnclaveImage =
    {
      workload,
      pname,
      extraRoot ? [ ],
    }:
    let
      version = enclaveBins.${pname}.version;
      imageName = "embedding-verifier-${workload}-enclave";
      imageRef = "${imageName}:${version}";
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

      # dockerTools replaces the old workload Dockerfile. It builds the complete image
      # filesystem and config without a daemon, with fixed timestamps and stable layer order.
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

      # Publish a proper OCI image layout as the independently reproducible boundary.
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

      # This is the pre-#38 conversion path, packaged by Nix: load the Nix-built OCI image
      # into Docker, then let AWS nitro-cli drive its bundled LinuxKit and EIF builder.
      eifBuilder = pkgs.writeShellApplication {
        name = "build-${workload}-eif";
        runtimeInputs = [
          pkgs.coreutils
          pkgs.docker-client
          pkgs.gnused
          pkgs.skopeo
          nitroCli
        ];
        text = ''
          if [[ $# -ne 1 ]]; then
            echo "Usage: build-${workload}-eif <output.eif>" >&2
            exit 2
          fi

          output_file="$(realpath -m "$1")"
          mkdir -p "$(dirname "$output_file")"

          work_dir="$(mktemp -d)"
          trap 'rm -rf "$work_dir"' EXIT
          mkdir -p "$work_dir/skopeo" "$work_dir/artifacts" "$work_dir/logs"

          docker info >/dev/null
          skopeo --tmpdir "$work_dir/skopeo" --insecure-policy copy \
            "oci:${ociImage}:${version}" \
            "docker-daemon:${imageRef}"

          build_output="$work_dir/build-output"
          if ! NITRO_CLI_BLOBS="${nitroCli}/share/aws-nitro-enclaves-cli/blobs/x86_64" \
            NITRO_CLI_ARTIFACTS="$work_dir/artifacts" \
            NITRO_CLI_LOGS_PATH="$work_dir/logs" \
              nitro-cli build-enclave \
                --docker-uri "${imageRef}" \
                --output-file "$output_file" > "$build_output"; then
            cat "$build_output" >&2
            exit 1
          fi

          # Nitro CLI prefixes its JSON with progress messages. Keep those visible while
          # giving callers a machine-readable stdout contract like the former Nix builder.
          sed '/^[[:space:]]*{$/,$d' "$build_output" >&2
          sed -n '/^[[:space:]]*{$/,$p' "$build_output"
        '';
      };
    in
    {
      oci = ociImage;
      eif = eifBuilder;
    };

  di = buildEnclaveImage {
    workload = "di";
    pname = "di-enclave";
  };
  deepface = buildEnclaveImage {
    workload = "deepface";
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
