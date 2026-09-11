use super::Credentials;

#[test]
fn prepares_wpa2_vector_and_reuses_it_through_the_connection_psk_path() {
    // Independently reproducible with Python:
    // hashlib.pbkdf2_hmac('sha1', b'password', b'IEEE', 4096, 32).
    let expected = [
        0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b, 0x90, 0xb3, 0x8a, 0x5f,
        0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e, 0x97, 0x10,
        0xa1, 0x2e,
    ];
    let prepared = Credentials::Passphrase("password")
        .derive_psk("IEEE")
        .unwrap();
    assert_eq!(prepared, expected);
    for _ in 0..10 {
        let mut connection_pmk = [0; 32];
        // Same private method used by the connection operation. Raw PSK input
        // must be copied, not passed through PBKDF2 a second time.
        Credentials::PreSharedKey(&prepared)
            .pmk(&mut connection_pmk, "IEEE")
            .unwrap();
        assert_eq!(connection_pmk, expected);
    }
}

#[test]
fn changing_ssid_or_passphrase_requires_a_different_prepared_key() {
    let first = Credentials::Passphrase("password")
        .derive_psk("IEEE")
        .unwrap();
    let other_ssid = Credentials::Passphrase("password")
        .derive_psk("IEEE2")
        .unwrap();
    let other_password = Credentials::Passphrase("password2")
        .derive_psk("IEEE")
        .unwrap();
    assert_ne!(first, other_ssid);
    assert_ne!(first, other_password);
    assert_eq!(
        first,
        Credentials::Passphrase("password")
            .derive_psk("IEEE")
            .unwrap()
    );
}

#[test]
fn raw_psk_requires_exactly_32_bytes_and_is_not_derived_again() {
    let bytes = [0x55; 64];
    for length in [0, 1, 16, 31, 33, 63, 64] {
        assert!(
            Credentials::PreSharedKey(&bytes[..length])
                .derive_psk("IEEE")
                .is_err()
        );
    }
    assert_eq!(
        Credentials::PreSharedKey(&bytes[..32])
            .derive_psk("IEEE")
            .unwrap(),
        [0x55; 32]
    );
}
