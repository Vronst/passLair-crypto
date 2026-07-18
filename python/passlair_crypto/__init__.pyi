def decrypt_password(encrypted_password: str, nonce: str, dek: str) -> str: ...
"""Decrypts a password using the provided nonce and dek.

Args:
    encrypted_password (str): The encrypted password to decrypt.
    nonce (str): The nonce used for encryption.
    dek (str): The data encryption key used for decryption.

Returns:
    str: The decrypted password.
"""


def encrypt_password(password: str, nonce: str, dek: str) -> str: ...
"""Encrypts a password using the provided nonce and dek.

Nonce should be regenerated for each encryption operation.

Args:
    password (str): The password to encrypt.
    nonce (str): The nonce used for encryption.
    dek (str): The data encryption key used for encryption.

Returns:
    str: The encrypted password.
"""


def derive_hash_and_keys(password: str, salt: str) -> tuple: ...
"""Derives a hash and keys from the provided password and salt.

Args:
    password (str): The password to derive keys from.
    salt (str): The salt used for key derivation.

Returns:
    tuple: A tuple containing the derived hash and keys.
"""
