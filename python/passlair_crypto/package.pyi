def decrypt_password(encrypted_password: bytes, nonce: bytes, dek: bytes) -> bytes:
    """Decrypts a password using the provided nonce and dek.

    Args:
        encrypted_password (bytes): The encrypted password to decrypt.
        nonce (bytes): The nonce used for encryption.
        dek (bytes): The data encryption key used for decryption.

    Returns:
        bytes: The decrypted password.
    """
    ...


def encrypt_password(password: bytes, dek: bytes) -> tuple[bytes, bytes]:
    """Encrypts a password under dek, generating a fresh nonce internally.

    Args:
        password (bytes): The password to encrypt.
        dek (bytes): The data encryption key used for encryption.

    Returns:
        tuple: (ciphertext, nonce). The nonce must be stored alongside the
        ciphertext — it's required to decrypt it later.
    """
    ...


def derive_keys(password: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """Derives a hash and kek from a password and an existing salt.

    Use this to verify a password against an already-stored salt (e.g.
    login). For deriving keys with a fresh salt, use derive_new_keys instead.

    Args:
        password (bytes): The password to derive keys from.
        salt (bytes): The salt used for key derivation.

    Returns:
        tuple: (hash, kek).
    """
    ...


def derive_new_keys(password: bytes) -> tuple[bytes, bytes, bytes]:
    """Derives a hash and kek from a password, generating a fresh salt internally.

    Use this for registration or password changes, where the salt is being
    created for the first time and needs to be persisted.

    Args:
        password (bytes): The password to derive keys from.

    Returns:
        tuple: (salt, hash, kek). The salt must be stored — it's required to
        verify the password later via derive_keys.
    """
    ...
