"""BLAKE2b KATs (RFC 7693 Appendix A) and property tests."""

import pytest

from secsci.primitives.blake2b import BLAKE2b, blake2b


def test_rfc7693_abc_vector():
    assert blake2b(b"abc").hex() == (
        "ba80a53f981c4d0d6a2797b69f12f6e9"
        "4c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc95"
        "18d38aa8dbf1925ab92386edd4009923"
    )


def test_empty_vector():
    assert blake2b(b"").hex() == (
        "786a02f742015903c6c6fd852552d272"
        "912f4740e15847618a86e217f71f5419"
        "d25e1031afee585313896444934eb04b"
        "903a685b1448b755d56f701afe9be2ce"
    )


def test_truncated_digests():
    assert blake2b(b"", 32).hex() == (
        "0e5751c026e543b2e8ab2eb06099daa1"
        "d1e5df47778f7787faab45cdf12fe3a8"
    )
    assert blake2b(b"abc", 32).hex() == (
        "bddd813c634239723171ef3fee98579b"
        "94964e3bb1cb3e427262c8c068d52319"
    )


def test_keyed_vectors():
    # Keyed BLAKE2b reduces to the unkeyed hash when the key is empty;
    # a full 64-byte key exercises the padded key block.
    assert blake2b(b"", 64, bytes(range(64))).hex() == (
        "10ebb67700b1868efb4417987acf4690"
        "ae9d972fb7a590c2f02871799aaa4786"
        "b5e996e8f0f4eb981fc214b005f42d2f"
        "f4233499391653df7aefcbc13fc51568"
    )
    assert blake2b(
        b"The quick brown fox jumps over the lazy dog", 32, b"secret key"
    ).hex() == "38ada9011c2426095759248242f442ada613f4985efa5b4f487ea2b0cc264340"


def test_long_input_multiple_blocks():
    assert blake2b(bytes(range(256)) * 4).hex() == (
        "6b490f42e902f61b1ee12d3c85e34152"
        "e37c94d07ab9ea577cad6a6eb4690fad"
        "38064f53a19c225703a5c52cdc9a85ad"
        "d71b339d327e1630ee3432b920240e8a"
    )


@pytest.mark.parametrize("cut", [1, 63, 64, 65, 127, 128, 129, 255, 256])
def test_incremental_updates_match_one_shot(cut):
    data = bytes(range(256)) * 3 + b"tail"
    expected = blake2b(data)
    h = BLAKE2b()
    h.update(data[:cut])
    for i in range(cut, len(data), 97):
        h.update(data[i : i + 97])
    assert h.digest() == expected


def test_keyed_incremental_matches_one_shot():
    key = b"k" * 32
    data = bytes(range(200)) * 3
    h = BLAKE2b(48, key)
    for i in range(0, len(data), 50):
        h.update(data[i : i + 50])
    assert h.digest() == blake2b(data, 48, key)


def test_rejects_bad_parameters():
    with pytest.raises(ValueError):
        BLAKE2b(0)
    with pytest.raises(ValueError):
        BLAKE2b(65)
    with pytest.raises(ValueError):
        BLAKE2b(64, b"k" * 65)


def test_digest_is_non_destructive():
    h = BLAKE2b()
    h.update(b"x")
    h.digest()
    # digest() must not mutate the running state; further updates keep
    # accumulating into the same hash.
    h.update(b"y")
    assert h.digest() == blake2b(b"xy")
