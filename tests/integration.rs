use passlair_crypto::{decrypt_password, derive_keys, encrypt_password};

const BYTES: [u8; 64] = [0u8; 64];
const NONCE: [u8; 12] = [0u8; 12];
const DEK: [u8; 32] = [0u8; 32];
const DIFF_DEK: [u8; 32] = [1u8; 32];

mod positive {
    use super::*;

    #[test]
    fn encryption_decryption() {
        let encrypted_password = encrypt_password(&BYTES, &NONCE, &DEK).unwrap();
        let decrypted_password = decrypt_password(&encrypted_password, &NONCE, &DEK).unwrap();

        assert_eq!(decrypted_password, BYTES);
    }
}

mod negative {
    use super::*;

    #[test]
    fn encryption_decryption_with_different_dek() {
        let encrypted_password = encrypt_password(&BYTES, &NONCE, &DEK).unwrap();

        decrypt_password(&encrypted_password, &NONCE, &DIFF_DEK).expect_err("Wrong DEK");
    }
}
