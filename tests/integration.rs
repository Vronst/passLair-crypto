use passlair_crypto::{decrypt_password, derive_keys, derive_new_keys, encrypt_password};

const BYTES: [u8; 64] = [0u8; 64];
const NONCE: [u8; 12] = [0u8; 12];
const DEK: [u8; 32] = [0u8; 32];
const DIFF_DEK: [u8; 32] = [1u8; 32];

mod positive {
    use argon2::password_hash::Salt;

    use super::*;

    #[test]
    fn encryption_decryption() {
        let (encrypted_password, nonce) = encrypt_password(&BYTES, &DEK).unwrap();
        let decrypted_password = decrypt_password(&encrypted_password, &nonce, &DEK).unwrap();

        assert_eq!(decrypted_password, BYTES);
    }

    #[test]
    fn derive_new_keys_and_check_with_derive_keys() {
        let password = [0u8; 64];
        let (salt, hash, key) = derive_new_keys(&password).unwrap();
        let (second_hash, second_key) = derive_keys(&password, &salt).unwrap();

        assert_eq!(hash, second_hash);
        assert_eq!(key, second_key);
    }

    #[test]
    fn derive_keys_same_output() {
        let password = [0u8; 64];
        let salt = [0u8; Salt::RECOMMENDED_LENGTH];
        let (hash, key) = derive_keys(&password, &salt).unwrap();
        let (second_hash, second_key) = derive_keys(&password, &salt).unwrap();

        assert_eq!(hash, second_hash);
        assert_eq!(key, second_key);
    }

    #[test]
    fn full_integration() {
        let password = [0u8; 64];
        let (salt, hash, key) = derive_new_keys(&password).unwrap();
        // TODO: encrypt/decrypt with salt/hash/key and try again with derive_keys
    }
}

mod negative {
    use argon2::password_hash::Salt;

    use super::*;

    #[test]
    fn decryption_with_invalid_nonce_length() {
        let (encrypted_password, _) = encrypt_password(&BYTES, &DEK).unwrap();
        decrypt_password(&encrypted_password, &[0u8; 1], &DEK).expect_err("Invalid nonce length");
    }

    #[test]
    fn encrypt_with_invalid_dek_length() {
        encrypt_password(&BYTES, &[0u8; 16]).expect_err("Invalid dek length");
    }

    #[test]
    fn decrypt_with_invalid_dek_length() {
        let (encrypted_password, nonce) = encrypt_password(&BYTES, &DEK).unwrap();
        decrypt_password(&encrypted_password, &nonce, &[0u8; 16]).expect_err("Invalid dek length");
    }

    #[test]
    fn decrypt_too_short() {
        decrypt_password(&[0u8; 1], &NONCE, &DEK).expect_err("Password too short");
    }

    #[test]
    fn decrypt_empty() {
        decrypt_password(&[], &NONCE, &DEK).expect_err("Password empty");
    }

    #[test]
    fn encryption_decryption_with_different_dek() {
        let (encrypted_password, nonce) = encrypt_password(&BYTES, &DEK).unwrap();

        decrypt_password(&encrypted_password, &nonce, &DIFF_DEK).expect_err("Wrong DEK");
    }

    #[test]
    fn encryption_decryption_with_different_nonce() {
        let (encrypted_password, _) = encrypt_password(&BYTES, &DEK).unwrap();

        decrypt_password(&encrypted_password, &NONCE, &DEK).expect_err("Wrong wrong NONCE");
    }

    #[test]
    fn encryption_with_invalid_encryption() {
        let (mut encrypted_password, nonce) = encrypt_password(&BYTES, &DEK).unwrap();
        encrypted_password[0] = 1;
        decrypt_password(&encrypted_password, &nonce, &DEK)
            .expect_err("Decryption failed, invalid encryption");
    }

    #[test]
    fn derive_new_keys_and_check_with_derive_keys() {
        let password = [0u8; 64];
        let corrupted_salt = [0u8; Salt::RECOMMENDED_LENGTH];
        let (_, hash, key) = derive_new_keys(&password).unwrap();
        let (second_hash, second_key) = derive_keys(&password, &corrupted_salt).unwrap();

        assert_ne!(hash, second_hash);
        assert_ne!(key, second_key);
    }

    #[test]
    fn derive_new_keys_wrong_salt() {
        let password = [0u8; 64];
        let corrupted_salt = [0u8; 100];

        derive_keys(&password, &corrupted_salt).expect_err("Salt is too long");

        let corrupted_salt = [0u8; 1];

        derive_keys(&password, &corrupted_salt).expect_err("Salt is too short");

        let corrupted_salt = [0u8; 32];

        derive_keys(&password, &corrupted_salt).expect_err("Salt is too short 2");

        let corrupted_salt = [0u8; 63];

        derive_keys(&password, &corrupted_salt).expect_err("Salt is too short 3");

        let corrupted_salt = [0u8; 65];

        derive_keys(&password, &corrupted_salt).expect_err("Salt is too long 2");

        let corrupted_salt = [0u8; 15];

        derive_keys(&password, &corrupted_salt).expect_err("Salt is too short by one");

        let corrupted_salt = [0u8; 17];

        derive_keys(&password, &corrupted_salt).expect_err("Salt is too long by one");
    }

    #[test]
    fn derive_keys_different_passwords_same_salt() {
        let password_a = [0u8; 64];
        let password_b = [1u8; 64];
        let salt = [0u8; Salt::RECOMMENDED_LENGTH];

        let (hash_a, key_a) = derive_keys(&password_a, &salt).unwrap();
        let (hash_b, key_b) = derive_keys(&password_b, &salt).unwrap();

        assert_ne!(hash_a, hash_b);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn derive_keys_empty_password() {
        let password = [];
        let salt = [0u8; Salt::RECOMMENDED_LENGTH];

        derive_keys(&password, &salt).expect_err("Password empty");
    }

    #[test]
    fn derive_new_keys_empty_password() {
        let password = [];

        derive_new_keys(&password).expect_err("Password empty");
    }
}
