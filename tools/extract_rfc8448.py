"""Regenerate tests/rfc8448_vectors.py from the saved RFC 8448 trace.

The saved trace lives in the OpenCode tool-output directory on this
machine; the checked-in vectors are what matter for CI.  Run this script
only when the trace is available again.
"""

import re
from pathlib import Path

TRACE = Path(
    r"C:\Users\Youth\.local\share\opencode\tool-output\tool_1c9a81769001SnGFsIzHFd3lJV"
)
OUT = Path(__file__).resolve().parents[1] / "tests" / "rfc8448_vectors.py"


def main() -> None:
    text = TRACE.read_text(encoding="utf-8", errors="replace")
    starts = [i for i in range(len(text)) if text.startswith("3.  Simple 1-RTT Handshake", i)]
    section = text[starts[-1] : text.find("4.  Resumed 0-RTT Handshake", starts[-1])]

    def grab_all(label: str, length: int) -> list[str]:
        out = []
        pattern = re.escape(label) + r"\s*\(" + str(length) + r" octets\):"
        hex_line = re.compile(r"(?:[0-9a-fA-F]{2}\s+)*[0-9a-fA-F]{2}")
        for match in re.finditer(pattern, section):
            collected: list[str] = []
            for line in section[match.end() :].splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                if (
                    "[Page" in stripped
                    or stripped.startswith("Thomson")
                    or stripped.startswith("RFC ")
                    or "Informational" in stripped
                    or "January 2019" in stripped
                    or "\x0c" in line
                ):
                    continue
                if hex_line.fullmatch(stripped):
                    collected.extend(
                        re.findall(r"(?<![0-9a-fA-F])[0-9a-fA-F]{2}(?![0-9a-fA-F])", stripped)
                    )
                    if len(collected) >= length:
                        break
                elif collected:
                    break
            out.append("".join(collected[:length]))
        return out

    def one(label: str, length: int) -> str:
        values = grab_all(label, length)
        assert len(values) == 1, (label, length, len(values))
        return values[0]

    vectors = {
        "CLIENT_HELLO": one("ClientHello", 196),
        "SERVER_HELLO": one("ServerHello", 90),
        "ENCRYPTED_EXTENSIONS": one("EncryptedExtensions", 40),
        "CERTIFICATE": one("Certificate", 445),
        "CERTIFICATE_VERIFY": one("CertificateVerify", 136),
    }
    finished = grab_all("Finished", 36)
    assert len(finished) == 2, len(finished)
    vectors["SERVER_FINISHED"], vectors["CLIENT_FINISHED"] = finished
    vectors["RECORD_SERVER_HANDSHAKE"] = one("complete record", 679)
    vectors["RECORD_CLIENT_FINISHED"] = one("complete record", 58)
    vectors["RECORD_NEW_SESSION_TICKET"] = one("complete record", 227)
    app = grab_all("complete record", 72)
    assert len(app) == 2, len(app)
    vectors["RECORD_CLIENT_APP_DATA"], vectors["RECORD_SERVER_APP_DATA"] = app
    alerts = grab_all("complete record", 24)
    assert len(alerts) == 2, len(alerts)
    vectors["RECORD_CLIENT_ALERT"], vectors["RECORD_SERVER_ALERT"] = alerts

    lines = [
        '"""RFC 8448 section 3 handshake vectors (TLS_AES_128_GCM_SHA256, X25519).',
        "",
        "Extracted verbatim from the RFC trace; regenerate with",
        "tools/extract_rfc8448.py.",
        '"""',
        "",
    ]
    for name, value in vectors.items():
        lines.append(f"{name} = (")
        for offset in range(0, len(value), 96):
            lines.append(f'    "{value[offset:offset + 96]}"')
        lines.append(")")
        lines.append("")
    OUT.write_text("\n".join(lines), encoding="utf-8")
    for name, value in vectors.items():
        print(name, len(value) // 2)


if __name__ == "__main__":
    main()
