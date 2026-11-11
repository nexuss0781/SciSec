"""Compile and execute C++ engine KATs through the Compiler Explorer API.

Development aid for environments without a local C++ toolchain.  Each
program is built as a single translation unit (headers inlined) so the
service can link and run it.
"""

from __future__ import annotations

import json
import pathlib
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
URL = "https://godbolt.org/api/compiler/g122/compile"

HEADERS = {
    "internal.h": (ROOT / "cpp/src/internal.h").read_text(encoding="utf-8"),
    "big.h": (ROOT / "cpp/src/big.h").read_text(encoding="utf-8"),
    "secsci.h": (ROOT / "cpp/include/secsci.h").read_text(encoding="utf-8"),
}

PRELUDE = r"""
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>

static int failures = 0;
static void check(const char *name, bool ok) {
    if (!ok) { std::printf("FAIL %s\n", name); ++failures; }
    else { std::printf("ok %s\n", name); }
}
static std::vector<uint8_t> hex(const std::string &s) {
    std::vector<uint8_t> out;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return c - 'A' + 10;
    };
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(uint8_t((nib(s[i]) << 4) | nib(s[i + 1])));
    return out;
}
static bool same(const uint8_t *a, const std::string &expected_hex) {
    auto e = hex(expected_hex);
    return e.size() == 32 || e.size() == 64 || e.size() == 16 || e.size() == 66
        ? std::memcmp(a, e.data(), e.size()) == 0 : false;
}
"""

MAINS = {
    "debug_hkdf": r"""
static void ph(const char *name, const uint8_t *data, size_t len) {
    std::printf("%s ", name);
    for (size_t i = 0; i < len; ++i) std::printf("%02x", data[i]);
    std::printf("\n");
}
int main() {
    auto salt = hex("000102030405060708090a0b0c");
    auto ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    auto info = hex("f0f1f2f3f4f5f6f7f8f9");
    uint8_t prk[32];
    secsci::hmac_sha256(salt.data(), salt.size(), ikm.data(), ikm.size(), prk);
    ph("prk", prk, 32);
    std::vector<uint8_t> m1(info); m1.push_back(1);
    uint8_t t1[32];
    secsci::hmac_sha256(prk, 32, m1.data(), m1.size(), t1);
    ph("t1", t1, 32);
    std::vector<uint8_t> m2(t1, t1 + 32); m2.insert(m2.end(), info.begin(), info.end()); m2.push_back(2);
    uint8_t t2[32];
    secsci::hmac_sha256(prk, 32, m2.data(), m2.size(), t2);
    ph("t2", t2, 32);
    uint8_t okm[42];
    secsci::hkdf_sha256(salt.data(), salt.size(), ikm.data(), ikm.size(), info.data(), info.size(), okm, 42);
    ph("okm", okm, 42);
    return 0;
}
""",
    "sha_drbg": r"""
int main() {
    uint8_t d32[32], d64[64];
    secsci::sha256(reinterpret_cast<const uint8_t *>("abc"), 3, d32);
    check("sha256 abc", same(d32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    secsci::sha512(reinterpret_cast<const uint8_t *>("abc"), 3, d64);
    check("sha512 abc", same(d64, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
    uint8_t key[20]; std::memset(key, 0x0b, sizeof(key));
    secsci::hmac_sha256(key, sizeof(key), reinterpret_cast<const uint8_t *>("Hi There"), 8, d32);
    check("hmac rfc4231", same(d32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    uint8_t ikm[22]; std::memset(ikm, 0x0b, sizeof(ikm));
    auto salt = hex("000102030405060708090a0b0c");
    auto info = hex("f0f1f2f3f4f5f6f7f8f9");
    uint8_t okm[42];
    secsci::hkdf_sha256(salt.data(), salt.size(), ikm, sizeof(ikm), info.data(), info.size(), okm, sizeof(okm));
    check("hkdf rfc5869", std::memcmp(okm, hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865").data(), 42) == 0);
    uint8_t entropy[32], nonce[16];
    for (int i = 0; i < 32; ++i) entropy[i] = uint8_t(i);
    for (int i = 0; i < 16; ++i) nonce[i] = uint8_t(i);
    secsci::Drbg *drbg = secsci::drbg_instantiate(entropy, 32, nonce, 16, nullptr, 0);
    check("drbg instantiate", drbg != nullptr);
    if (drbg) {
        uint8_t out[64];
        check("drbg generate", secsci::drbg_generate(drbg, nullptr, 0, out, 64));
        check("drbg vector", same(out, "3e0013f6f1e74912f56fec7e73bb590c06ecd0f69e1fe019c2e04063e9207ab93042fbef098b1e5ed61856bb1b807fd4b23839e62f885d76082eebe1fa43e8e2"));
        delete drbg;
    }
    std::printf(failures ? "FAILURES\n" : "ALL OK\n");
    return failures ? 1 : 0;
}
""",
    "aes_gcm": r"""
int main() {
    uint8_t key[32] = {}, nonce[12] = {}, tag[16], ct[16], pt[16];
    check("encrypt empty", secsci::aes256_gcm_encrypt(key, nonce, nullptr, 0, nullptr, 0, nullptr, tag));
    check("empty tag", same(tag, "530f8afbc74536b9a963b4f1c4cb738b"));
    check("encrypt block", secsci::aes256_gcm_encrypt(key, nonce, nullptr, 0, pt, 16, ct, tag));
    check("block ct", same(ct, "cea7403d4d606b6e074ec5d3baf39d18"));
    check("block tag", same(tag, "d0d1c8a799996bf0265b98b5d48ab919"));
    uint8_t out[16];
    check("decrypt", secsci::aes256_gcm_decrypt(key, nonce, nullptr, 0, ct, 16, tag, out));
    check("plaintext", std::memcmp(out, pt, 16) == 0);
    tag[0] ^= 1;
    check("tamper", !secsci::aes256_gcm_decrypt(key, nonce, nullptr, 0, ct, 16, tag, out));
    std::printf(failures ? "FAILURES\n" : "ALL OK\n");
    return failures ? 1 : 0;
}
""",
    "chacha": r"""
int main() {
    auto key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    auto nonce = hex("070000004041424344454647");
    auto aad = hex("50515253c0c1c2c3c4c5c6c7");
    std::string text = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    std::vector<uint8_t> ct(text.size()), tag(16), out(text.size());
    check("encrypt", secsci::chacha20poly1305_encrypt(key.data(), nonce.data(), aad.data(), aad.size(), reinterpret_cast<const uint8_t *>(text.data()), text.size(), ct.data(), tag.data()));
    check("ct", std::memcmp(ct.data(), hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116").data(), ct.size()) == 0);
    check("tag", same(tag.data(), "1ae10b594f09e26a7e902ecbd0600691"));
    check("decrypt", secsci::chacha20poly1305_decrypt(key.data(), nonce.data(), aad.data(), aad.size(), ct.data(), ct.size(), tag.data(), out.data()));
    check("plaintext", std::memcmp(out.data(), text.data(), text.size()) == 0);
    tag[0] ^= 1;
    check("tamper", !secsci::chacha20poly1305_decrypt(key.data(), nonce.data(), aad.data(), aad.size(), ct.data(), ct.size(), tag.data(), out.data()));
    std::printf(failures ? "FAILURES\n" : "ALL OK\n");
    return failures ? 1 : 0;
}
""",
    "gf521": r"""
static std::vector<uint8_t> fe(uint64_t v) {
    std::vector<uint8_t> out(66, 0);
    for (int i = 65; i >= 0 && v; --i) { out[size_t(i)] = uint8_t(v); v >>= 8; }
    return out;
}
int main() {
    auto two = fe(2), three = fe(3), six = fe(6), one = fe(1), zero = fe(0);
    uint8_t out[66];
    check("mul", secsci::gf521_mul(two.data(), three.data(), out));
    check("2*3=6", std::memcmp(out, six.data(), 66) == 0);
    check("inv", secsci::gf521_inv(two.data(), out));
    uint8_t check_one[66];
    check("2*inv2=1", secsci::gf521_mul(out, two.data(), check_one) && std::memcmp(check_one, one.data(), 66) == 0);
    check("add", secsci::gf521_add(two.data(), three.data(), out));
    check("2+3=5", out[65] == 5 && std::memcmp(out, zero.data(), 65) == 0);
    auto pm1 = fe(0); pm1.assign(66, 0xff); pm1[0] = 0x01; pm1[65] = 0xfe;
    check("0-1=p-1", secsci::gf521_sub(zero.data(), one.data(), out) && std::memcmp(out, pm1.data(), 66) == 0);
    check("wrap", secsci::gf521_add(pm1.data(), one.data(), out) && std::memcmp(out, zero.data(), 66) == 0);
    auto p = fe(0); p.assign(66, 0xff); p[0] = 0x01;
    check("reject p", !secsci::gf521_add(p.data(), zero.data(), out));
    std::printf(failures ? "FAILURES\n" : "ALL OK\n");
    return failures ? 1 : 0;
}
""",
    "x25519": r"""
int main() {
    auto scalar = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    auto point = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    uint8_t out[32];
    secsci::x25519(scalar.data(), point.data(), out);
    check("rfc 5.2", same(out, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));
    auto a = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    auto b = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    uint8_t ap[32], bp[32], sa[32], sb[32];
    secsci::x25519_base(a.data(), ap);
    secsci::x25519_base(b.data(), bp);
    check("alice pub", same(ap, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    check("bob pub", same(bp, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
    secsci::x25519(a.data(), bp, sa);
    secsci::x25519(b.data(), ap, sb);
    check("shared", std::memcmp(sa, sb, 32) == 0);
    check("shared vector", same(sa, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
    std::printf(failures ? "FAILURES\n" : "ALL OK\n");
    return failures ? 1 : 0;
}
""",
}

SOURCES = {
    "debug_hkdf": ["sha2.cpp"],
    "sha_drbg": ["sha2.cpp", "drbg.cpp"],
    "aes_gcm": ["aes_gcm.cpp"],
    "chacha": ["chacha20poly1305.cpp"],
    "gf521": ["big.cpp", "gf521.cpp"],
    "x25519": ["big.cpp", "x25519.cpp"],
}


def build(name: str) -> str:
    parts = [PRELUDE]
    for source in SOURCES[name]:
        text = (ROOT / "cpp/src" / source).read_text(encoding="utf-8")
        for header, contents in HEADERS.items():
            text = text.replace(f'#include "{header}"', contents)
        if name == "debug_hkdf" and source == "sha2.cpp":
            text = text.replace(
                "        outer.final(prk);\n    }\n    uint8_t previous[HashLen];",
                "        outer.final(prk);\n    }\n"
                "    std::printf(\"internal prk \");\n"
                "    for (size_t di = 0; di < HashLen; ++di) std::printf(\"%02x\", prk[di]);\n"
                "    std::printf(\"\\n\");\n"
                "    uint8_t previous[HashLen];",
            )
            text = text.replace(
                "        ctx.final(previous);\n        previous_len = HashLen;",
                "        ctx.final(previous);\n"
                "        std::printf(\"internal t%u \", unsigned(counter));\n"
                "        for (size_t di = 0; di < HashLen; ++di) std::printf(\"%02x\", previous[di]);\n"
                "        std::printf(\"\\n\");\n"
                "        previous_len = HashLen;",
            )
        parts.append(text)
    parts.append(MAINS[name])
    return "\n".join(parts)


def run(name: str) -> bool:
    payload = {
        "source": build(name),
        "options": {
            "userArguments": "-std=c++17 -O1",
            "filters": {"execute": True},
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
    with urllib.request.urlopen(request, timeout=240) as response:
        result = json.load(response)
    build_result = result.get("execResult", {}).get("buildResult", {})
    stderr = build_result.get("stderr") or []
    if stderr and isinstance(stderr[0], dict):
        stderr_text = "\n".join(item.get("text", "") for item in stderr)
    else:
        stderr_text = "".join(stderr)
    exec_result = result.get("execResult", {})
    stdout = exec_result.get("stdout") or []
    stdout_text = "\n".join(
        item.get("text", "") if isinstance(item, dict) else item
        for item in stdout
    )
    print(f"=== {name}: build exit {build_result.get('code')}, "
          f"run exit {exec_result.get('code')}, "
          f"executed {exec_result.get('didExecute')}")
    if stderr_text.strip():
        print(stderr_text)
    if stdout_text.strip():
        print(stdout_text)
    return (
        build_result.get("code") == 0
        and exec_result.get("code") == 0
        and exec_result.get("didExecute") is True
    )


def main() -> int:
    names = sys.argv[1:] or list(MAINS)
    failed = 0
    for name in names:
        if not run(name):
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
