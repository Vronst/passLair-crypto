use passlair_crypto::{decrypt_password, encrypt_password};

const NONCE: [u8; 12] = [0u8; 12];

mod negative {
    use super::*;

    #[test]
    fn decryption_decryption_with_too_short_dek() {
        decrypt_password(&[0u8; 64], &NONCE, &[0u8; 31]).expect_err("Too short DEK");
    }

    #[test]
    fn encryption_decryption_with_too_short_dek() {
        encrypt_password(&[0u8; 64], &[0u8; 31]).expect_err("Too short DEK");
    }
}
