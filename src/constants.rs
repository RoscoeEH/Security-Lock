pub const ADDRESS: &str = "127.0.0.1:8080";
pub const HMAC_KEY_FILE: &str = "config/test_key.bin";
pub const MESSAGE_SIZE: usize = 32; // size of the random message
pub const MESSAGE_DELAY: u64 = 500; // in milliseconds
pub const TIMEOUT_WINDOW: u64 = 1000; // in milliseconds
pub const DISCONNECT_PROGRAM: &str = "systemctl";
pub const DISCONNECT_ARG: &str = "poweroff";
