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
}

mod negative {
    use argon2::password_hash::Salt;

    use super::*;

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
    fn derive_new_keys_and_check_with_derive_keys() {
        let password = [0u8; 64];
        let corrupted_salt = [0u8; Salt::RECOMMENDED_LENGTH];
        let (_, hash, key) = derive_new_keys(&password).unwrap();
        let (second_hash, second_key) = derive_keys(&password, &corrupted_salt).unwrap();

        assert_ne!(hash, second_hash);
        assert_ne!(key, second_key);
    }

    #[test]
    fn derive_new_keys_wrong_params() {
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
    }
}
