pub const DEFAULT_IP_ADDRESS: &str = "127.0.0.1:8080";
pub const DEFAULT_PRIVATE_KEY_FILE: &str = match cfg!(debug_assertions) {
    true => "config/dev_ML-KEM768_decap_key.pem",
    false => "~/.security-lock/ML-KEM768_decap_key.pem",
};
pub const DEFAULT_PUBLIC_KEY_FILE: &str = match cfg!(debug_assertions) {
    true => "config/dev_ML-KEM768_encap_key.pub",
    false => "~/.security-lock/ML-KEM768_encap_key.pub",
};

pub const MESSAGE_SIZE: usize = 32; // size of the random message
pub const SYM_KEY_SIZE: usize = 32;
pub const SALT_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;

pub const MESSAGE_DELAY: u64 = 500; // in milliseconds
pub const TIMEOUT_WINDOW: u64 = 1000; // in milliseconds
pub const SEK_USE_LIMIT: u32 = 2_u32.pow(24);

pub const DISCONNECT_PROGRAM: &str = "systemctl";
pub const DISCONNECT_ARG: &str = "poweroff";
