use passlair_crypto::helpers::{get_key, get_nonce};

mod positive {
    use super::*;

    #[test]
    fn get_nonce_accepts_a_12_byte_slice() {
        let bytes = [0u8; 12];
        let nonce = get_nonce(&bytes).expect("a 12-byte slice should produce a valid Nonce.");

        assert_eq!(nonce.as_slice(), &bytes);
    }

    #[test]
    fn get_key_accepts_a_12_byte_slice() {
        let bytes = [0u8; 32];
        let key = get_key(&bytes).expect("a 32-bytes slice should produce a valid Key.");

        assert_eq!(key.as_slice(), &bytes);
    }
}

mod negative {
    use super::*;

    #[test]
    fn get_nonce_declines_a_non_12_bytes_slice() {
        let bytes = [0u8; 24];
        get_nonce(&bytes).expect_err("Value declined.");

        let bytes = [0u8; 11];
        get_nonce(&bytes).expect_err("Value declined.");

        let bytes = [0u8; 0];
        get_nonce(&bytes).expect_err("Value declined.");

        let bytes = [0u8; 1];
        get_nonce(&bytes).expect_err("Value declined.");
    }

    #[test]
    fn get_key_declines_a_non_32_byte_slice() {
        let bytes = [0u8; 0];
        get_key(&bytes).expect_err("Value declined");

        let bytes = [0u8; 12];
        get_key(&bytes).expect_err("Value declined");

        let bytes = [0u8; 24];
        get_key(&bytes).expect_err("Value declined");

        let bytes = [0u8; 44];
        get_key(&bytes).expect_err("Value declined");

        let bytes = [0u8; 64];
        get_key(&bytes).expect_err("Value declined");
    }
}
