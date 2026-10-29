"""Pinned public-fixture interop, outside the source tree. Never use real keys.

python3 research/reproduce_draft_interop.py /absolute/scratch [--sign]
Default: download/hash-check, install pinned Noble without scripts, verify.
--sign additionally compiles C and reproduces uncached full-parameter KAT.
The upstream CLI accepts seed on argv and has a test RNG: NOT a wallet signer.
"""
import argparse
import hashlib
import json
import platform
import subprocess
import time
import urllib.request
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scratch", type=Path)
    parser.add_argument("--sign", action="store_true")
    parser.add_argument("--build-testnet-io", action="store_true")
    args = parser.parse_args()
    scratch = args.scratch.resolve()
    manifest = json.loads((PROJECT / "benchmarks/slh-draft-interop-sources.json").read_text())
    for entry in manifest["files"]:
        target = scratch / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.write_bytes(urllib.request.urlopen(manifest["base_url"] + entry["path"]).read())
        assert hashlib.sha256(target.read_bytes()).hexdigest() == entry["sha256"], target
    noble = scratch / "signers/noble-slh-dsa"
    subprocess.run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=noble, check=True)
    subprocess.run(["node", "patch-noble.mjs"], cwd=noble, check=True)
    module = noble / "build/slh-dsa-w4.mjs"
    subprocess.run(["node", "benchmarks/check_slh_draft_noble.mjs", str(module)], cwd=PROJECT, check=True)
    if args.build_testnet_io:
        c_dir = scratch / "signers/sphincsplus-128-24"
        sources = [str(scratch / entry["path"]) for entry in manifest["files"]
                   if "/sphincsplus-128-24/" in entry["path"] and entry["path"].endswith(".c")
                   and not entry["path"].endswith("/main.c")]
        output = PROJECT / "build/slh-testnet-io"
        output.parent.mkdir(exist_ok=True)
        subprocess.run(["cc", "-O3", "-Wall", "-Wextra", "-std=c99", "-I"+str(c_dir),
                        str(PROJECT / "research/slh_testnet_io.c"), *sources, "-o", str(output)], check=True)
    if args.sign:
        c_dir = scratch / "signers/sphincsplus-128-24"
        subprocess.run(["make", "clean"], cwd=c_dir, check=True)
        subprocess.run(["make"], cwd=c_dir, check=True)
        fixture = json.loads((PROJECT / "tests/fixtures/slh-draft/gpu.json").read_text())
        # Published upstream seed48, not a new KDF or a secret used for deposits.
        seed = ("e7678ccc25f61528cd0d30d2f84b2a22"
                "de8305a2fcb697d73434a939c879bebf"
                "750e7b30f37700dd14b20a5c647bb936")
        start = time.monotonic()
        result = subprocess.run([str(c_dir / "slhdsa-sha2-128-24"), seed,
                                 "0000" + fixture["message"], "00"*16],
                                capture_output=True, text=True, check=True)
        elapsed = time.monotonic() - start
        raw = bytes.fromhex(result.stdout.strip())
        assert raw.hex() == fixture["public_key"] + fixture["signature"]
        print(json.dumps({"uncached_keygen_and_sign_seconds": elapsed,
                          "platform": platform.platform(),
                          "output_sha256": hashlib.sha256(raw).hexdigest(),
                          "public_kat_exact_match": True}))


if __name__ == "__main__":
    main()
