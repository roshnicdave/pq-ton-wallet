#!/usr/bin/env python3
"""Structural/arithmetic checker for the frozen wallet's conditional gas bound.

This is not a general TVM analyzer or a machine-checked control-flow proof.
See README.md for scope and remaining proof obligations.
Requires pytoniq-core==0.2.1; --acton also checks compilation and stack metadata.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from pytoniq_core import Cell
from pytoniq_core.boc.hashmap.parse import deserialize_hml
from slh_gas_structure import opcode_counts

if not __debug__:
    raise SystemExit("The proof checks require assertions; do not run with python -O.")

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "benchmarks/slh-wallet-security"
CODE_HASH = "71d67e17e8af4de8c843482f091ead58cf9f0acdd0210eb1cff5401ee04ced08"
ASM_SHA256 = "4b6077b85adebb02de305b71b195f7e4a935593e3440c1d4817fd93c923c64b8"
SOURCES = {
    "contracts/SlhWallet.tolk": "b6f54cca026b05061d60587d86b68429af6b2386c622d255ed231b7dd5f22740",
    "contracts/slh_wallet.tolk": "66a9844d4e732c8732562fb2a47dfaac2a47bf8353be5a86162584c90fe52746",
    "contracts/slh_sha2_128_24.tolk": "85a85c52813a7cd14dc311d609af7e8b6dbcacc0e65c6f721af8dd729b3d6545",
    "contracts/slh_common.tolk": "22bfd8ab20dd73a14a2d853a02d5cf9699c85581399fed4f59e0f008c5d59cb8",
}

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dictionary_depths(cell, remaining=19, prefix="", depth=1):
    s = cell.begin_parse()
    length, label = deserialize_hml(s, remaining)
    prefix += label.to01()
    remaining -= length
    if remaining == 0:
        return {int(prefix, 2): depth}
    return (dictionary_depths(s.load_ref(), remaining - 1, prefix + "0", depth + 1)
            | dictionary_depths(s.load_ref(), remaining - 1, prefix + "1", depth + 1))


def check_compilation(acton, expected_code, expected_asm):
    version = subprocess.check_output([acton, "--version"], text=True).strip()
    assert version.startswith("acton 1.2.1 "), "use the pinned toolchain"
    # Print neither project/wallet diagnostics nor environment data. Disable
    # doctor's API probes and retain only the public native-library revisions.
    report = subprocess.check_output([acton, "doctor", "--color", "never"], cwd=ROOT,
                                    env=dict(os.environ, ACTON_DOCTOR_API_TARGETS_JSON="[]"), text=True)
    native = json.loads((ARTIFACTS / "native-toolchain.json").read_text())
    revisions = {}
    for component, field in [("emulator", "native_emulator_commit"), ("tolk", "native_tolk_commit")]:
        match = re.search(r"(?m)^\s*" + component + r"\.ton_commit_hash:\s*([0-9a-f]+)\s*$", report)
        assert match and match[1] == native[field], "native library revision changed"
        revisions[component] = match[1]
    with tempfile.TemporaryDirectory(prefix="slh-gas-") as tmp:
        tmp = Path(tmp)
        subprocess.run([acton, "compile", "contracts/SlhWallet.tolk", "--boc",
                        str(tmp / "code.boc"), "--fift", str(tmp / "code.fif"),
                        "--source-map", str(tmp / "code.map.json")],
                       cwd=ROOT, check=True, capture_output=True)
        code = Cell.one_from_boc((tmp / "code.boc").read_bytes())
        assert code.hash == expected_code.hash, "compiled code changed"
        asm = subprocess.check_output([acton, "disasm", str(tmp / "code.boc")], cwd=ROOT)
        assert asm.decode().strip() == expected_asm.strip(), "disassembly changed"
        maxima, calls, arities = {}, {}, {}
        expanded_parts = {"slhDraftFors()": 2, "slhDraftXmss()": 11,
                          "onInternalMessage()": 5}
        expansion_sites = []
        current, stack = None, 0
        for line in (tmp / "code.fif").read_text().splitlines():
            if " PROC:<{" in line or " PROCREF:<{" in line:
                current = line.strip().split(" PROC")[0]
            if "MARK_STACK" in line:
                stack = len(re.findall(r"'[^ ]+", line.split("//", 1)[1]))
                arities.setdefault(current, stack)
                maxima[current] = max(maxima.get(current, 0), stack)
            if "EXPLODEVAR" in line:
                # Compiler metadata treats the asm helper atomically. Its
                # transient stack has n builders + count in place of one tuple.
                maxima[current] = max(maxima[current], stack + expanded_parts[current])
                expansion_sites.append(current)
            match = re.match(r"\s*(\S+) CALLDICT", line)
            if match:
                calls.setdefault(current, []).append((match[1], stack))

        def peak(function, prefix):
            heights = [prefix + maxima[function]]
            for callee, height in calls.get(function, []):
                heights += [prefix + height + 3,  # method index + dictionary + key length
                            peak(callee, prefix + height - arities[callee])]
            return max(heights)

        # Native internal-message stack retains balance, value and full message
        # below the body argument after dispatcher consumes method selector 0.
        result = peak("onInternalMessage()", 3)
        assert sorted(expansion_sites) == sorted(expanded_parts)
        assert result <= 32, "stack-copy gas needs a new proof"
        names = sorted({line.strip().split()[0] for line in expected_asm.splitlines()
                        if line.strip() and line.strip() not in ("}", "]", "ref {")
                        and "=>" not in line})
        catalog = json.loads(subprocess.check_output(
            [acton, "doc", "tvm", *names, "--json"], cwd=ROOT))
        aliases = {"MODPOW2#": "MODPOW2_"}
        fixed_bits = {aliases.get(r["name"], r["name"]): r["layout"]["skipLen"] for r in catalog}
        assert set(fixed_bits) == set(names), "missing opcode pricing metadata"
        assert all(type(n) is int and 10 + n <= 34 for n in fixed_bits.values())
        return {"toolchain": version, "peak_stack_with_inline_asm_expansion": result,
                "native_library_commits": revisions,
                "hash_part_counts": expanded_parts,
                "frame_maxima": maxima,
                "opcode_fixed_bits": dict(sorted(fixed_bits.items())),
                "opcode_base_gas_maximum": max(10 + n for n in fixed_bits.values()),
                "catalog_implementation_commits": sorted({r["implementation"]["commit_hash"] for r in catalog}),
                "catalog_is_not_a_native_surcharge_proof": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acton", help="path to pinned Acton 1.2.1 executable")
    args = parser.parse_args()
    for name, expected in SOURCES.items():
        assert digest(ROOT / name) == expected, f"source changed: {name}"
    code = Cell.one_from_boc((ARTIFACTS / "code.boc").read_bytes())
    assert code.hash.hex() == CODE_HASH
    asm = (ARTIFACTS / "wallet.tasm").read_text()
    assert digest(ARTIFACTS / "wallet.tasm") == ASM_SHA256
    depths = dictionary_depths(code.refs[0])
    assert depths == {0: 5, 1: 5, 2: 5, 3: 5, 4: 4, 5: 4, 101294: 2}
    counts, references, structure = opcode_counts(asm)
    instructions, calls = sum(counts.values()), counts["CALLDICT"]
    assert instructions == 14436 and calls == 312
    # Each dispatcher visit costs <=650: <=3 basic instructions, <=5 cold
    # dictionary cell loads, return/control margin. Its instructions are also
    # included in the deliberately excessive implicit-control allowance.
    charges = {
        "basic_opcodes_at_most_34_each": 34 * instructions,
        "dispatch_at_most_650_each": 650 * calls,
        "implicit_returns_and_jumps": 15 * (instructions + 3 * calls),
        "explicit_cell_finalization": 500 * counts["ENDC"],
        "data_cell_loads_all_cold": 100 * counts["CTOS"],
        "code_reference_loads_all_cold": 100 * (references + counts["PUSHREFCONT"] + counts["IFREFELSE"]),
        "three_output_action_cells": 1500,
        "hash_parts_and_tuple_margin": 5000,
        "exception_and_termination_margin": 1000,
        "entry_and_context_margin": 5000,
    }
    bound = sum(charges.values())
    assert bound < 1000000
    reproduction = check_compilation(args.acton, code, asm) if args.acton else None
    print(json.dumps({
        "status": "conditional structural certificate; local invariants and native/control costs require review",
        "code_hash": CODE_HASH, "assembly_sha256": ASM_SHA256,
        "global_version": 17, "scope": "internal compute, valid persistent state; actions charged separately",
        "gas_upper_bound": bound, "native_cap": 1000000,
        "source_sha256": SOURCES, "compiled_reproduction": reproduction,
        "instruction_count_upper_bound": instructions, "dictionary_depths": depths,
        "charges": charges, "instruction_counts": dict(sorted(counts.items())),
        "structure": structure,
        "supersedes": "gas-certificate.json: context-copy WHILE condition counted once instead of twice",
    }, indent=2))


if __name__ == "__main__":
    main()
