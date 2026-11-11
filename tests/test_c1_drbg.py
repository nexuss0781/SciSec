"""C1 HMAC-DRBG KATs (NIST CAVP no-reseed SHA-256 vectors)."""

import pytest

from secsci.components.c1_drbg import HMACDRBG, random_below, random_bytes

NIST_CASES = [
    # entropy, nonce, personalization, add1, add2, expected (output of
    # the second Generate call; both calls use their own additional data)
    (
        "ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488",
        "659ba96c601dc69fc902940805ec0ca8",
        "",
        "",
        "",
        "e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89"
        "d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc1"
        "07694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668"
        "961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8",
    ),
    (
        "79737479ba4e7642a221fcfd1b820b134e9e3540a35bb48ffae29c20f5418ea3",
        "3593259c092bef4129bc2c6c9e19f343",
        "",
        "",
        "",
        "cf5ad5984f9e43917aa9087380dac46e410ddc8a7731859c84e9d0f31bd43655"
        "b924159413e2293b17610f211e09f770f172b8fb693a35b85d3b9e5e63b1dc25"
        "2ac0e115002e9bedfb4b5b6fd43f33b8e0eafb2d072e1a6fee1f159df9b51e6c"
        "8da737e60d5032dd30544ec51558c6f080bdbdab1de8a939e961e06b5f1aca37",
    ),
    (
        "5d3286bc53a258a53ba781e2c4dcd79a790e43bbe0e89fb3eed39086be34174b",
        "c5422294b7318952ace7055ab7570abf",
        "2dba094d008e150d51c4135bb2f03dcde9cbf3468a12908a1b025c120c985b9d",
        "793a7ef8f6f0482beac542bb785c10f8b7b406a4de92667ab168ecc2cf7573c6",
        "2238cdb4e23d629fe0c2a83dd8d5144ce1a6229ef41dabe2a99ff722e510b530",
        "d04678198ae7e1aeb435b45291458ffde0891560748b43330eaf866b5a6385e7"
        "4c6fa5a5a44bdb284d436e98d244018d6acedcdfa2e9f499d8089e4db86ae89"
        "a6ab2d19cb705e2f048f97fb597f04106a1fa6a1416ad3d859118e079a0c319e"
        "b95686f4cbcce3b5101c7a0b010ef029c4ef6d06cdfac97efb9773891688c37cf",
    ),
]


@pytest.mark.parametrize("entropy,nonce,pers,add1,add2,expected", NIST_CASES)
def test_nist_hmac_drbg_vectors(entropy, nonce, pers, add1, add2, expected):
    # CAVP no-reseed vectors contain two Generate calls; ReturnedBits
    # is the output of the second call (see Readme.txt in the NIST zip).
    drbg = HMACDRBG(bytes.fromhex(entropy), bytes.fromhex(nonce), bytes.fromhex(pers))
    drbg.generate(128, bytes.fromhex(add1))
    out = drbg.generate(128, bytes.fromhex(add2))
    assert out.hex() == expected


def test_nist_intermediate_state_after_first_generate():
    drbg = HMACDRBG(
        bytes.fromhex("ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488"),
        bytes.fromhex("659ba96c601dc69fc902940805ec0ca8"),
    )
    drbg.generate(128)
    assert drbg._v.hex() == (
        "bfbdcf455d5c82acafc59f339ce57126ff70b67aef910fa25db7617818faeafe"
    )
    assert drbg._k.hex() == (
        "911bf7cbda4387a172a1a3daf6c9fa8e17c4bfef69cc7eff1341e7eef88d2811"
    )


def test_two_instances_are_deterministic():
    e, n, p = b"e" * 32, b"n" * 16, b"personalization"
    a = HMACDRBG(e, n, p).generate(100)
    b = HMACDRBG(e, n, p).generate(100)
    assert a == b


def test_additional_input_changes_output():
    base = HMACDRBG(b"e" * 32, b"n" * 16)
    other = HMACDRBG(b"e" * 32, b"n" * 16)
    assert base.generate(32) != other.generate(32, b"additional")


def test_reseed_is_reproducible():
    a = HMACDRBG(b"e" * 32, b"n" * 16)
    b = HMACDRBG(b"e" * 32, b"n" * 16)
    a.generate(16)
    b.generate(16)
    a.reseed(b"r" * 32, b"extra")
    b.reseed(b"r" * 32, b"extra")
    assert a.generate(64) == b.generate(64)
    assert a.reseed_counter == 2


def test_random_below_range_and_variability():
    values = {random_below(10) for _ in range(100)}
    assert values <= set(range(10))
    assert len(values) > 3
    assert random_below(1) == 0
    with pytest.raises(ValueError):
        random_below(0)


def test_random_bytes_length():
    assert len(random_bytes(0)) == 0
    assert len(random_bytes(1)) == 1
    assert len(random_bytes(77)) == 77


def test_entropy_length_validation():
    with pytest.raises(ValueError):
        HMACDRBG(b"short", b"n" * 16)
    with pytest.raises(ValueError):
        HMACDRBG(b"e" * 32, b"short")
