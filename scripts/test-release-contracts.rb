require "fileutils"
require "json"
require "open3"
require "tmpdir"
require "yaml"

ROOT = File.expand_path("..", __dir__)

def check(condition, message)
  raise message unless condition
end

def run(script, env, dir = ROOT, success: true)
  stdout, stderr, status = Open3.capture3(env, "bash", "-euo", "pipefail", "-c", script, chdir: dir)
  check(status.success? == success, "Unexpected exit #{status.exitstatus}: #{stdout}#{stderr}")
end

def workflow(name)
  YAML.load_file(File.join(ROOT, ".github/workflows/#{name}.yml"))
end

Dir.mktmpdir("release-contracts-") do |dir|
  bin = File.join(dir, "bin")
  store = File.join(dir, "store")
  FileUtils.mkdir_p([bin, store])
  File.write(File.join(store, "image.eif"), "test EIF")
  measurements = { "PCR0" => "a" * 96, "PCR1" => "b" * 96, "PCR2" => "c" * 96 }
  File.write(File.join(store, "pcr.json"), JSON.generate(measurements))
  File.write(File.join(bin, "nix"), <<~'BASH')
    #!/bin/bash
    set -euo pipefail
    printf '%s\n' "$*" >> "$NIX_CALLS"
    if [[ "$1" == eval ]]; then
      printf '{}\n'
      exit 0
    fi
    [[ "$1" == build ]] || exit 2
    for arg in "$@"; do
      case "$arg" in
        .#flamingo-verifier-oci|.#flamingo-verifier-eif|.#di-oci|.#di-eif)
          [[ "$arg" != "${FAIL_OUTPUT:-}" ]] || exit 1
          printf '%s\n' "$TEST_STORE"
          exit 0
          ;;
      esac
    done
    echo "Unexpected Nix output: $*" >&2
    exit 2
  BASH
  File.write(File.join(bin, "tar"), "#!/bin/bash\nprintf '%s\\n' \"$*\" > \"$TAR_CALLS\"\n")
  File.chmod(0755, File.join(bin, "nix"), File.join(bin, "tar"))
  env = {
    "PATH" => "#{bin}:#{ENV.fetch('PATH')}", "TEST_STORE" => store,
    "NIX_CALLS" => File.join(dir, "nix-calls"), "TAR_CALLS" => File.join(dir, "tar-calls"),
    "GITHUB_OUTPUT" => File.join(dir, "outputs"), "HUGGING_FACE_TOKEN" => "", "TEST_OUTPUT" => File.join(dir, "failed")
  }
  exports = File.read(File.join(ROOT, "nix/enclave-images.nix")).scan(/^  ([\w-]+) = (?:di|verifier)\.(?:oci|eif);$/).flatten
  package_step = workflow("release-enclaves").fetch("jobs").fetch("build").fetch("steps").find { |s| s["name"] == "Package OCI layout" }
  { "verifier" => "flamingo-verifier", "di" => "di" }.each do |workload, package|
    output = File.join(dir, workload)
    File.write(env.fetch("NIX_CALLS"), "")
    args = workload == "verifier" ? [] : ["--workload", workload]
    stdout, stderr, status = Open3.capture3(env, "bash", "scripts/build-enclaves.sh", *args, output, chdir: ROOT)
    check(status.success?, "#{workload} build failed: #{stdout}#{stderr}")
    check(File.read(File.join(output, "#{workload}-enclave.eif")) == "test EIF", "Wrong EIF filename")
    check(JSON.parse(File.read(File.join(output, "#{workload}-pcr.json"))) == measurements, "Wrong PCR contract")
    %w[oci eif].each do |kind|
      check(exports.include?("#{package}-#{kind}"), "Missing Nix export")
      check(File.read(env.fetch("NIX_CALLS")).include?(".##{package}-#{kind}"), "Build selected the wrong Nix output")
    end
    File.write(env.fetch("NIX_CALLS"), "")
    run(package_step.fetch("run"), env.merge("WORKLOAD" => workload))
    check(File.read(env.fetch("NIX_CALLS")).include?(".##{package}-oci"), "Release selected the wrong Nix output")
    check(File.read(env.fetch("TAR_CALLS")).include?("target/release/#{workload}-oci.tar.gz"), "Wrong OCI artifact")
    run("bash scripts/build-enclaves.sh --workload #{workload} \"$TEST_OUTPUT\"", env.merge("FAIL_OUTPUT" => ".##{package}-oci"), success: false)
    run("bash scripts/build-enclaves.sh --workload #{workload} \"$TEST_OUTPUT\"", env.merge("FAIL_OUTPUT" => ".##{package}-eif"), success: false)
  end
  run("bash scripts/build-enclaves.sh --workload deepface", env, success: false)
  run(package_step.fetch("run"), env.merge("WORKLOAD" => "deepface"), success: false)
  File.write(File.join(store, "pcr.json"), JSON.generate(measurements.merge("PCR2" => "invalid")))
  run('bash scripts/build-enclaves.sh --workload di "$TEST_OUTPUT"', env, success: false)

  hosts = workflow("release-hosts").fetch("jobs")
  prepare = hosts.fetch("prepare")
  release = prepare.fetch("steps").find { |s| s["id"] == "release" }.fetch("run")
  check(prepare.fetch("outputs").fetch("tag") == "${{ steps.release.outputs.tag }}", "Tag output is not forwarded")
  publish = hosts.fetch("release").fetch("steps").first
  check(publish.fetch("env").fetch("RELEASE_TAG") == "${{ needs.prepare.outputs.tag }}", "Release must reuse the parsed tag")
  check(publish.fetch("env").fetch("GH_REPO") == "${{ github.repository }}", "Release needs a repository without a checkout")
  matrix = workflow("build-docker").fetch("jobs").fetch("resolve-matrix").fetch("steps").first.fetch("run")
  File.write(File.join(bin, "gh"), "#!/bin/bash\nprintf '%s\\n' \"$@\" > \"$GH_CALLS\"\n")
  File.chmod(0755, File.join(bin, "gh"))
  { "verifier" => "flamingo-verifier-host", "di" => "di-host" }.each do |workload, prefix|
    [["push", "false"], ["workflow_dispatch", "true"], ["workflow_dispatch", "false"]].each do |event, dry_run|
      tag = "#{prefix}/v1.2.3-rc.1"
      File.write(env.fetch("GITHUB_OUTPUT"), "")
      run(release, env.merge("GITHUB_EVENT_NAME" => event, "GITHUB_REF_NAME" => tag,
                            "INPUT_WORKLOAD" => workload, "INPUT_VERSION" => "1.2.3-rc.1", "DRY_RUN" => dry_run))
      outputs = File.readlines(env.fetch("GITHUB_OUTPUT")).map { |line| line.chomp.split("=", 2) }.to_h
      check(outputs.fetch("workload") == workload, "Host workload does not match the build matrix")
      check(outputs.fetch("tag") == tag, "Wrong host release tag")
      check(outputs.fetch("version") == "1.2.3-rc.1", "Wrong host version")
      check(outputs.fetch("publish") == (dry_run == "true" ? "false" : "true"), "Wrong publish decision")
      File.write(env.fetch("GITHUB_OUTPUT"), "")
      run(matrix, env.merge("WORKLOAD" => outputs.fetch("workload")))
      selected = JSON.parse(File.read(env.fetch("GITHUB_OUTPUT")).delete_prefix("include="))
      check(selected.length == 1 && selected.first.fetch("workload") == workload, "Release must build exactly its selected host")
      check(File.file?(File.join(ROOT, selected.first.fetch("dockerfile"))), "Host Dockerfile is missing")
      run(publish.fetch("run"), env.merge("RELEASE_TAG" => outputs.fetch("tag"), "RELEASE_SHA" => outputs.fetch("sha"),
          "IMAGE" => "test-image", "DIGEST" => "sha256:test", "RUNNER_TEMP" => dir, "GH_CALLS" => File.join(dir, "gh-calls")))
      check(File.readlines(File.join(dir, "gh-calls")).last.chomp == tag, "Published tag differs from the prepared tag")
    end
  end
  run(release, env.merge("GITHUB_EVENT_NAME" => "push", "GITHUB_REF_NAME" => "verifier-host/v1.2.3"), success: false)
  ["", "1/2", "1\npublish=true", "1" * 128].each do |version|
    run(release, env.merge("GITHUB_EVENT_NAME" => "workflow_dispatch", "INPUT_WORKLOAD" => "verifier",
                          "INPUT_VERSION" => version, "DRY_RUN" => "true"), success: false)
  end
end

puts "Release contract checks passed"
