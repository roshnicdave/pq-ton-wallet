"""Count the frozen wallet's structured disassembly using local loop bounds.

This checks structure and propagates multiplicities, not TVM dataflow. The nine
local loop bounds and two branch bounds still require the documented invariants.
Unannotated WHILE/repeat sites, malformed bindings and recursive CALLDICT calls
are rejected. This parser is restricted to the separately hash-pinned program.
"""
from collections import Counter
from dataclasses import dataclass
import re


@dataclass
class Node:
    text: str
    line: int
    body: list | None = None

    @property
    def op(self):
        return self.text.split()[0]


def parse_methods(assembly):
    lines = assembly.splitlines()

    def block(i):
        result = []
        while i < len(lines):
            line, number = lines[i].strip(), i + 1
            if line == "}":
                return result, i + 1
            if line.endswith(" {"):
                body, i = block(i + 1)
                if line == "ref {":
                    # This is a code-cell seam, not a pushed continuation.
                    result += [Node("$code_ref", number), *body]
                else:
                    result.append(Node(line[:-2], number, body))
            else:
                if not line or line == "]" or "=>" in line:
                    raise ValueError(f"unexpected disassembly at line {number}")
                result.append(Node(line, number))
                i += 1
        raise ValueError("unterminated continuation")

    assert lines[:2] == ["SETCP 0", "DICTPUSHCONST 19 ["]
    methods, i = {}, 2
    while i < len(lines) and lines[i].strip() != "]":
        match = re.fullmatch(r"(\d+) => \{", lines[i].strip())
        if not match:
            raise ValueError(f"bad method header: {lines[i]}")
        method = int(match[1])
        if method in methods:
            raise ValueError("duplicate method")
        methods[method], i = block(i + 1)
    assert set(methods) == {0, 1, 2, 3, 4, 5, 101294}
    assert lines[i:] == ["]", "DICTIGETJMPZ", "THROWARG 11"]
    return methods


def descendants(nodes):
    for node in nodes:
        yield node
        if node.body is not None:
            yield from descendants(node.body)


def opcode_counts(assembly):
    methods = parse_methods(assembly)
    # Bounds on executions of each body, per invocation of its enclosing code.
    while_bounds = {
        (0, ("DUP", "GTINT 0")): 1,       # one fixed empty-context piece
        (3, ("DUP", "LESSINT 3")): 3,     # start is a base-4 digit
        (4, ("DUP", "LESSINT 6")): 6,
        (4, ("DUP", "LESSINT 24")): 24,
        (5, ("DUP", "LESSINT 68")): 68,
        (5, ("DUP", "LESSINT 22")): 22,
    }
    repeat_bounds = {(0, "REPEATBRK"): 1, (2, "REPEAT"): 4, (5, "REPEAT"): 64}
    seen_rules, witnesses, counts = set(), [], Counter()
    calls, method_sizes, references = Counter({0: 1}), {}, 0

    def targets(method):
        return {int(n.text.split()[1]) for n in descendants(methods[method])
                if n.op == "CALLDICT"}

    active, visited, order = set(), set(), []

    def visit(method):
        if method in active or method not in methods:
            raise ValueError("recursive or unknown method call")
        if method in visited:
            return
        active.add(method)
        for callee in sorted(targets(method)):
            visit(callee)
        active.remove(method)
        visited.add(method)
        order.append(method)

    visit(0)

    def walk(method, nodes, frequency):
        nonlocal references
        executable = [n for n in nodes if n.op != "$code_ref"]
        child_frequencies = {}
        for i, node in enumerate(executable):
            if node.op == "WHILE":
                cond, body = executable[i - 2:i]
                assert i >= 2 and cond.op.startswith("PUSH") and body.op.startswith("PUSH")
                assert cond.body is not None and body.body is not None
                signature = tuple(n.text for n in cond.body)
                key = (method, signature)
                trips = while_bounds[key]  # unknown loop is an error
                assert key not in seen_rules
                seen_rules.add(key)
                child_frequencies[cond.line] = frequency * (trips + 1)
                child_frequencies[body.line] = frequency * trips
                witnesses.append({"method": method, "line": node.line, "kind": "WHILE",
                                  "local_body_bound": trips, "enclosing_count": frequency,
                                  "condition_count": frequency * (trips + 1)})
            if node.op in ("REPEAT", "REPEATBRK"):
                body = executable[i - 1]
                assert i >= 1 and body.op.startswith("PUSH") and body.body is not None
                key = (method, node.op)
                trips = repeat_bounds[key]
                assert key not in seen_rules
                seen_rules.add(key)
                child_frequencies[body.line] = frequency * trips
                witnesses.append({"method": method, "line": node.line, "kind": node.op,
                                  "local_body_bound": trips, "enclosing_count": frequency})
            if node.op == "IFNOT" and method == 1:
                body = executable[i - 1]
                assert body.op == "PUSHCONT" and body.body is not None
                assert [n.text for n in body.body[:4]] == ["OVER", "SREFS", "EQINT 1", "THROWIFNOT 300"]
                # Seven blocks in the initial cell, then seven per checked cell.
                child_frequencies[body.line] = (calls[1] - 1) // 7
                witnesses.append({"method": 1, "line": node.line, "kind": "reader_chunk",
                                  "body_bound": child_frequencies[body.line]})
            if node.op == "IFNOT" and method == 5:
                assert [n.text for n in executable[i - 4:i - 1]] == ["DUP", "PUSHINT_4 7", "MOD"]
                body = executable[i - 1]
                assert body.op == "PUSHCONT_SHORT" and body.body is not None
                child_frequencies[body.line] = frequency // 7
                witnesses.append({"method": 5, "line": node.line, "kind": "pack_every_seventh",
                                  "body_bound": child_frequencies[body.line]})
        for node in nodes:
            if node.op == "$code_ref":
                references += frequency
                continue
            counts[node.op] += frequency
            if node.op == "CALLDICT":
                calls[int(node.text.split()[1])] += frequency
            if node.body is not None:
                if node.op == "PUSHREF":
                    assert not node.body, "data cell must not be interpreted as code"
                else:
                    walk(method, node.body, child_frequencies.get(node.line, frequency))

    # Callers precede callees, so helper bodies use their total invocation count.
    for method in reversed(order):
        before = sum(counts.values())
        walk(method, methods[method], calls[method])
        method_sizes[method] = sum(counts.values()) - before
    assert seen_rules == set(while_bounds) | set(repeat_bounds)
    assert calls == {0: 1, 1: 241, 2: 1, 3: 68, 4: 1, 5: 1}
    # Preserve the deliberately conservative initial missing-method throw count.
    counts.update({"SETCP": 1, "DICTPUSHCONST": 1, "DICTIGETJMPZ": 1, "THROWARG": 1})
    return counts, references, {"method_invocations": dict(sorted(calls.items())),
                                "method_instruction_bounds": dict(sorted(method_sizes.items())),
                                "local_bound_witnesses": sorted(witnesses, key=lambda w: w["line"])}
