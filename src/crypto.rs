use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::error::Error;

type HmacSha256 = Hmac<Sha256>;

pub fn hmac_sign(message: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(message);

    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn hmac_verify(message: &[u8], key: &[u8], signature: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(message);

    mac.verify_slice(signature)?;
    Ok(())
}
