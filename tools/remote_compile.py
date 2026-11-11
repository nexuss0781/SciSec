"""Compile each C++ translation unit through the Compiler Explorer API.

This is a development aid for environments without a local compiler.  It
inlines the project headers into each source file, posts it to Godbolt,
and reports the compiler diagnostics.
"""

from __future__ import annotations

import json
import pathlib
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
HEADERS = {
    "internal.h": (ROOT / "cpp/src/internal.h").read_text(encoding="utf-8"),
    "big.h": (ROOT / "cpp/src/big.h").read_text(encoding="utf-8"),
    "secsci.h": (ROOT / "cpp/include/secsci.h").read_text(encoding="utf-8"),
}
URL = "https://godbolt.org/api/compiler/g122/compile"


def compile_source(name: str, source: str) -> tuple[int, str]:
    payload = {
        "source": source,
        "options": {
            "userArguments": "-std=c++17 -c -Wall -Wextra",
            "filters": {"execute": False},
        },
    }
    request = urllib.request.Request(
        URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=180) as response:
        result = json.load(response)
    raw_stderr = result.get("stderr") or []
    if raw_stderr and isinstance(raw_stderr[0], dict):
        stderr = "\n".join(item.get("text", "") for item in raw_stderr)
    else:
        stderr = "".join(raw_stderr)
    return int(result.get("code") or 0), stderr


def main() -> int:
    failed = 0
    for path in sorted((ROOT / "cpp/src").glob("*.cpp")):
        source = path.read_text(encoding="utf-8")
        for header, text in HEADERS.items():
            source = source.replace(f'#include "{header}"', text)
        code, stderr = compile_source(path.name, source)
        print(f"=== {path.name}: exit {code}")
        if stderr.strip():
            print(stderr)
        if code != 0:
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
