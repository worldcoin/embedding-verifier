{
  root,
  pkgs,
  crane,
}:
let
  lib = pkgs.lib;

  # The same rust-toolchain.toml cargo already uses, so a channel bump moves the enclaves
  # and the hosts together instead of drifting. rust-overlay carries the component hashes,
  # so there is no hash to paste in here and none to go stale.
  rustToolchain = pkgs.rust-bin.fromRustupToolchainFile (root + "/rust-toolchain.toml");
  craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

  # Only the files cargo actually reads. Whole directories would make the derivation hash —
  # and so the PCRs — move when a README or a workflow changes next to the code.
  cargoFiles = lib.fileset.fileFilter (
    file:
    file.hasExt "rs"
    || file.name == "Cargo.toml"
    || file.name == "Cargo.lock"
    # Assets pulled in with include_str!/include_bytes!: the face engine graph configs,
    # the AWS Nitro root CA, and the attestation fixture its tests parse. A new embedded
    # asset type has to be added here or the build fails to find it.
    || file.hasExt "yaml"
    || file.hasExt "der"
    || file.hasExt "b64"
  );

  # Each enclave is its own cargo workspace with its own lockfile, so its build reads that
  # manifest, that lockfile, and the path crates they name — never the root workspace.
  # Listing those crates per workload is what makes the isolation real: with the whole tree
  # as src, a deepface/host edit would still move di's PCR0. A new path dependency has to be
  # added here or the build fails to find it.
  srcFor =
    crates:
    lib.fileset.toSource {
      inherit root;
      fileset = lib.fileset.unions ((map cargoFiles crates) ++ [ (root + "/rust-toolchain.toml") ]);
    };

  # The biometric-engines rev the deepface enclave's lockfile pins, so the assets grafted
  # into the vendor tree below cannot come from a different commit than the crates built
  # against them. Read from that lockfile and no other: the root workspace no longer
  # resolves face-engine at all.
  lockedFaceEngineRev =
    let
      lock = builtins.fromTOML (builtins.readFile (root + "/deepface/enclave/Cargo.lock"));
      sources = lib.unique (
        lib.filter (source: source != null && lib.hasInfix "worldcoin/biometric-engines" source) (
          map (package: package.source or null) lock.package
        )
      );
    in
    assert lib.assertMsg (lib.length sources == 1) (
      "expected one worldcoin/biometric-engines git source in deepface/enclave/Cargo.lock,"
      + " found "
      + toString (lib.length sources)
    );
    lib.last (lib.splitString "#" (lib.head sources));

  # Fetched here rather than taken as a flake input so there is no second pin to keep in
  # step with Cargo.lock. This is a private repo, and `builtins.fetchGit` runs on the host
  # with the host's git credentials — a credential helper or an ssh agent. No secret
  # reaches a derivation or the store. crane resolves the crates themselves the same way.
  biometricEngines = builtins.fetchGit {
    url = "https://github.com/worldcoin/biometric-engines";
    rev = lockedFaceEngineRev;
    allRefs = true;
  };

  # face-engine's consts.rs reads its default graph configs with
  # include_str!("../../../assets/..."), which resolves only in a monorepo checkout —
  # cargo vendors every crate standalone. That path lands at the root of the vendored
  # checkout, one level above the crate directories, so restoring assets/ there satisfies
  # it without patching the crate. Nothing verifies the addition: cargo writes
  # `{"files":{}}` as the checksum manifest for vendored git crates.
  deepfaceVendorDir = craneLib.vendorCargoDeps {
    cargoLock = root + "/deepface/enclave/Cargo.lock";
    overrideVendorGitCheckout =
      packages: drv:
      if
        lib.any (package: lib.hasInfix "worldcoin/biometric-engines" (package.source or "")) packages
      then
        pkgs.runCommandLocal "biometric-engines-checkout-with-assets" { } ''
          cp -R --no-preserve=mode,ownership ${drv} $out
          chmod -R u+w $out
          cp -R ${biometricEngines}/assets $out/assets
        ''
      else
        drv;
  };

  # Nothing in di's graph comes from a git source, so this needs no override and no
  # credentials — the lane that would notice a private dependency arriving is CI's.
  diVendorDir = craneLib.vendorCargoDeps {
    cargoLock = root + "/di/enclave/Cargo.lock";
  };

  commonArgs = {
    strictDeps = true;

    # The build must not depend on the machine running it, only on the commit. Two defaults
    # break that: cargo sets -j from the host's CPU count and hands it to every build script
    # as NUM_JOBS, and release codegen splits each crate across 16 units. Pinning both makes
    # a 4-core runner and a 32-core box do the same work in the same order.
    CARGO_BUILD_JOBS = "4";
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS = "1";

    # LLVM's LICM scalar promotion orders work by pointer value, so rustc (1.97 and 1.98
    # both) emits different code for the same input under different address-space layouts —
    # the same commit measured different PCRs on different machines. Nix disables ASLR in
    # builds, which hides it locally: each machine is self-consistent and machines disagree.
    # Disabling the promotion makes codegen address-independent, verified by building the
    # enclave under ASLR and varied stack rlimits and getting identical bytes. The cost is
    # one loop optimization. Do not drop this without re-running that experiment.
    RUSTFLAGS = "-C llvm-args=-disable-licm-promotion";

    # Panic locations embed absolute source paths. Under Nix the source is a store path that
    # is identical on every machine, so nothing needs trimming — but cargo hashes the
    # absolute workspace path into each crate's -Cmetadata, so the same source built in two
    # different directories produces two different binaries and two different PCRs.
    # Sandboxed builds all run in /build; give sandbox-less builders the same path. Where
    # /build is absent this is a no-op and the sandbox carries reproducibility.
    #
    # Every string in this derivation is measured: the enclave's store path is baked into
    # the initramfs, so editing anything here — even a no-op — moves PCR0 and PCR2. Two
    # known weaknesses are left alone for that reason, to be fixed with the next deliberate
    # rotation: the `rm -rf` races if two unsandboxed builds run at once, and where /build
    # is absent the build measures differently without saying so.
    postUnpack = ''
      if [ "$NIX_BUILD_TOP" != /build ] && [ -d /build ] && [ -w /build ]; then
        rm -rf "/build/$sourceRoot"
        mv "$sourceRoot" "/build/$sourceRoot"
        cd /build
        export NIX_BUILD_TOP=/build
      fi
    '';
  };

  # face-engine builds its ONNX Runtime bindings with bindgen, which needs clang.
  faceEngineArgs = {
    nativeBuildInputs = with pkgs; [
      clang
      pkg-config
    ];
    LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
  };

  # The enclave manifests spell their version out rather than inheriting it, so read it from
  # there. Taking it from the root workspace would put a host-side version bump in the PCRs.
  versionOf = manifest: (builtins.fromTOML (builtins.readFile manifest)).package.version;

  # Two deviations from a stock crane build, both forced by the workspace being nested
  # inside the source rather than at its root:
  #
  # `cd` into the workspace instead of passing --manifest-path. crane's install step reads
  # `cargo metadata` with no arguments to decide which artifacts belong to the workspace, so
  # from the source root it finds no Cargo.toml and the build fails after compiling. Running
  # cargo from the workspace directory is what that step expects. postPatch, because it runs
  # before crane's own hooks and the working directory carries into every later phase.
  #
  # cargoArtifacts = null builds dependencies and crate in one derivation instead of
  # splitting them across a `buildDepsOnly` dummy build. The split saves nothing on the cold
  # build that PCRs are measured from, and crane's dummy source generation has the same
  # root-of-source assumption.
  buildEnclaveBin =
    {
      pname,
      workspace,
      crates,
      cargoVendorDir,
      extraArgs ? { },
    }:
    craneLib.buildPackage (
      commonArgs
      // extraArgs
      // {
        inherit pname cargoVendorDir;
        version = versionOf (root + "/${workspace}/Cargo.toml");
        src = srcFor crates;
        postPatch = "cd ${workspace}";
        cargoArtifacts = null;
        cargoExtraArgs = "--locked --bin ${pname}";
      }
    );
in
{
  di-enclave = buildEnclaveBin {
    pname = "di-enclave";
    workspace = "di/enclave";
    crates = [
      (root + "/di/enclave")
    ];
    cargoVendorDir = diVendorDir;
  };
  deepface-enclave = buildEnclaveBin {
    pname = "deepface-enclave";
    workspace = "deepface/enclave";
    crates = [
      (root + "/deepface/enclave")
      (root + "/deepface/enclave-types")
      (root + "/deepface/protocol")
      (root + "/shared/attested-channel")
    ];
    cargoVendorDir = deepfaceVendorDir;
    extraArgs = faceEngineArgs;
  };
}
