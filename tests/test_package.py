from passlair_crypto.package import decrypt_password, derive_keys, encrypt_password


def test_encrypt_password_mock():
    assert encrypt_password(b"hunter2", b"0" * 12, b"1" * 32) == b"encrypted-hunter2"


def test_decrypt_password_mock_is_identity():
    ciphertext = b"encrypted-hunter2"
    assert decrypt_password(ciphertext, b"0" * 12, b"1" * 32) == ciphertext


def test_derive_keys_mock():
    hash_, kek = derive_keys(b"hunter2", b"salt1234salt5678")
    assert hash_ == bytes([1] * 32)
    assert kek == bytes([2] * 32)
    assert len(hash_) == 32
    assert len(kek) == 32
