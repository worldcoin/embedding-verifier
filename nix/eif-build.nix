{
  system,
  pkgs,
  nitro-util,
  enclaveBins,
  deepfaceModels,
}:
let
  nitroBlobs = nitro-util.lib.${system}.blobs.x86_64;

  # The EIF is assembled entirely inside Nix by monzo/aws-nitro-util: deterministic cpio
  # ramdisks (sorted entries, epoch mtimes, root-owned) fed to AWS's eif_build, using the
  # same AWS-published kernel/init/nsm.ko blobs nitro-cli ships. No Docker daemon and no
  # nitro-cli on the measured path — converting a rootfs through a container runtime makes
  # PCR0/PCR2 depend on the machine doing the conversion.
  buildEif =
    {
      pname,
      extraRoot ? [ ],
    }:
    nitro-util.lib.${system}.buildEif {
      name = pname;
      version = enclaveBins.${pname}.version;
      arch = "x86_64";
      kernel = nitroBlobs.kernel;
      kernelConfig = nitroBlobs.kernelConfig;
      nsmKo = nitroBlobs.nsmKo;
      # AWS's blob init — the same binary nitro-cli EIFs boot — rather than nitro-util's
      # from-source Go rewrite, which does not evaluate against this nixpkgs.
      init = nitroBlobs.init;
      copyToRoot = pkgs.buildEnv {
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
      entrypoint = "/bin/${pname}";
      env = ''
        RUST_LOG=info
        SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
      '';
    };
in
{
  di-eif = buildEif { pname = "di-enclave"; };
  deepface-eif = buildEif {
    pname = "deepface-enclave";
    extraRoot = [ deepfaceModels ];
  };
}
