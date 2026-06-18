"""Tests for the RFC 6962-style Merkle root.

The expected digests below are pinned known-answer vectors. They were computed
independently (see README "Merkle tree") for the file contents b"alpha",
b"beta", b"gamma" hashed with sha256, then combined with 0x00 leaf / 0x01
internal domain separation and odd-node promotion.
"""
import hashlib

# sha256 of the three sample file contents (the Merkle leaves' inputs).
H = {
    "alpha": hashlib.sha256(b"alpha").hexdigest(),
    "beta": hashlib.sha256(b"beta").hexdigest(),
    "gamma": hashlib.sha256(b"gamma").hexdigest(),
}

# Pinned roots from the worked example.
ROOT_3 = "bb1e6ce657790b193bfea0ec6c4bb2c8377aba31bb09d25cec48668f0fa3b159"
ROOT_4_DUP = "c8b59b9e1d4f9d682347cb8716bf06c0a1ce2b24dd49ea05a91fd47c49c95109"
# Single leaf == sha256(0x00 || sha256("alpha")).
LEAF_ALPHA = "34f04379cbb22ebf98da1e0475ab0082be13a18e78de0fd0cc32bfcfa98ee518"


def test_empty_is_blank(tool):
    assert tool.merkle_root([], "sha256") == ""


def test_single_leaf_is_domain_separated(tool):
    # A lone leaf is still 0x00-prefixed, never the bare file hash.
    assert tool.merkle_root([H["alpha"]], "sha256") == LEAF_ALPHA
    assert tool.merkle_root([H["alpha"]], "sha256") != H["alpha"]


def test_known_three_leaf_vector(tool):
    root = tool.merkle_root([H["alpha"], H["beta"], H["gamma"]], "sha256")
    assert root == ROOT_3


def test_odd_node_promotion_no_duplication_collision(tool):
    # CVE-2012-2459: a 3-file tree must NOT collide with a 4-file tree whose
    # last leaf is duplicated. The naive (pre-fix) construction produced equal
    # roots here.
    three = tool.merkle_root([H["alpha"], H["beta"], H["gamma"]], "sha256")
    four = tool.merkle_root([H["alpha"], H["beta"], H["gamma"], H["gamma"]], "sha256")
    assert three != four
    assert four == ROOT_4_DUP


def test_leaf_internal_domain_separation(tool):
    # Two leaves combine under the 0x01 internal prefix, which must differ from
    # treating the same concatenation as a leaf (0x00). This is the second
    # property that prevents tree-shape forgery.
    two = tool.merkle_root([H["alpha"], H["beta"]], "sha256")
    leaf_a = bytes.fromhex(LEAF_ALPHA)
    leaf_b = hashlib.sha256(b"\x00" + bytes.fromhex(H["beta"])).digest()
    as_leaf = hashlib.sha256(b"\x00" + leaf_a + leaf_b).hexdigest()
    assert two != as_leaf


def test_order_sensitivity(tool):
    a = tool.merkle_root([H["alpha"], H["beta"]], "sha256")
    b = tool.merkle_root([H["beta"], H["alpha"]], "sha256")
    assert a != b


def test_shake_length_supported(tool):
    # Variable-length algos must still produce a stable, length-correct root.
    root = tool.merkle_root([H["alpha"], H["beta"]], "shake_256:32")
    assert len(root) == 64  # 32 bytes hex
    # Deterministic.
    assert root == tool.merkle_root([H["alpha"], H["beta"]], "shake_256:32")
