#!/usr/bin/env python3
"""Download the Face Engine v2 ONNX models used by the enclave MVP."""

import argparse
import hashlib
import os
import shutil
import tempfile
from pathlib import Path

# This placeholder comparison pipeline only needs:
# - RGBNet to find the subject face.
# - FaceEmbeddingGenerator (GhostFaceNet) to produce the vector being compared.
# Quality, liveness, spoof, and head-pose models are intentionally excluded until those checks
# become part of the route.
#
# Each default revision below is an immutable Hugging Face Git commit from biometric-engines
# v2.16.0's model_revisions.env. A revision identifies which repository snapshot to download; it
# is not the checksum of the ONNX file.
MODELS = (
    (
        "FaceEmbeddingGenerator",
        "REV_FACEEMBEDDINGGENERATOR",
        "5fcbd28a5304ca1f1a186c300261ebccafb5eeec",
    ),
    ("RGBNet", "REV_RGBNET", "e81cff53eaeb3881d18415407fc1a7b07c2b0600"),
)

REQUIRED_FILES = (
    "face_embedding_generator.onnx",
    "rgbnet.onnx",
)

# These are SHA-256 digests of the downloaded ONNX bytes. They independently ensure that a pinned
# revision produced the reviewed artifacts and catch corrupt or replaced files. Changing a model
# revision therefore requires reviewing and updating its digest here as the same change.
EXPECTED_SHA256 = {
    "face_embedding_generator.onnx": "3a5807e26adff1a6a25ac50dc0139cb6c5c87cbcb0594bd7065fa29bd185e19c",
    "rgbnet.onnx": "25bfb4cd007f616da02e6a8484121f97a5bced67f0485d234f88220958603638",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("models"))
    parser.add_argument("--token", default=os.environ.get("HUGGING_FACE_TOKEN"))
    args = parser.parse_args()

    if not args.token:
        parser.error("set HUGGING_FACE_TOKEN or pass --token")

    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        parser.error("install the downloader with: python3 -m pip install huggingface-hub")

    args.output.mkdir(parents=True, exist_ok=True)

    for model, revision_variable, default_revision in MODELS:
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory)
            snapshot_download(
                repo_id=f"Worldcoin/{model}",
                revision=os.environ.get(revision_variable, default_revision),
                allow_patterns=["onnx/*"],
                local_dir=destination,
                token=args.token,
            )

            flavor_directory = destination / "onnx"
            if not flavor_directory.is_dir():
                raise RuntimeError(f"{model} did not contain an onnx flavor")

            for model_file in flavor_directory.iterdir():
                if model_file.is_file():
                    shutil.copy2(model_file, args.output / model_file.name)

    missing = [name for name in REQUIRED_FILES if not (args.output / name).is_file()]
    if missing:
        raise RuntimeError(f"download completed without required models: {', '.join(missing)}")

    for name, expected_digest in EXPECTED_SHA256.items():
        model_path = args.output / name
        observed_digest = hashlib.sha256(model_path.read_bytes()).hexdigest()
        if observed_digest != expected_digest:
            raise RuntimeError(
                f"checksum mismatch for {name}: expected {expected_digest}, got {observed_digest}"
            )


if __name__ == "__main__":
    main()
