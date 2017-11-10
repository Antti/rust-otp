/// rust-otp is a Rust library for performing the HMAC-based One-time Passsword Algorithm as per RFC 4226
/// and the Time-based One-time Password Algorithm as per RFC 6238.
/// These are also the algorithms many mobile-based 2FA apps, such as Google Authenticator and Authy, use to generate 2FA codes.
///
/// ```rust
/// use otp::{make_hotp, make_totp};
/// // first argument is the secret, second argument is the counter
/// assert_eq!(make_hotp("base32secret3232", 0), Some(260182));
///
/// // first argument is the secret, followed by the time step in seconds (Google
/// // Authenticator uses a time step of 30), and then the skew in seconds
/// // (often used when calculating HOTPs for a sequence of consecutive
/// // time intervals, to deal with potential latency and desynchronization).
/// let totp = make_totp("base32secret3232", 30, 0); // Some(260182)
/// ```
extern crate openssl;
extern crate base32;
extern crate time;
extern crate byteorder;

use time::get_time;
use openssl::hash::MessageDigest;
use openssl::sign::Signer;
use openssl::pkey::PKey;
use base32::Alphabet::RFC4648;
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use std::io::Cursor;

/// Decodes a secret (given as an RFC4648 base32-encoded ASCII string)
/// into a byte string
fn decode_secret(secret: &str) -> Option<Vec<u8>> {
    base32::decode(RFC4648 { padding: false }, secret)
}

/// Calculates the HMAC digest for the given secret and counter.
fn calc_digest(pkey: &PKey, counter: u64) -> Vec<u8> {
    let mut wtr = vec![];
    wtr.write_u64::<BigEndian>(counter).unwrap();
    let mut signer = Signer::new(MessageDigest::sha1(), pkey).unwrap();
    signer.update(&wtr).unwrap();
    signer.finish().unwrap()
}

/// Encodes the HMAC digest into a 6-digit integer.
fn encode_digest(digest: &[u8]) -> Option<u32> {
    let offset = match digest.last() {
        Some(offset) => *offset as usize & 0xf,
        None => return None
    };
    let mut cursor = Cursor::new(&digest[offset..]);
    cursor.read_u32::<BigEndian>().ok().map(|code| (code & 0x7fffffff) % 1_000_000)
}

/// Performs the [HMAC-based One-time Password Algorithm](http://en.wikipedia.org/wiki/HMAC-based_One-time_Password_Algorithm)
/// (HOTP) given an RFC4648 base32 encoded secret, and an integer counter.
pub fn make_hotp(secret: &str, counter: u64) -> Option<u32> {
    decode_secret(secret).and_then(|decoded| {
        let key = PKey::hmac(&decoded).unwrap();
        encode_digest(&calc_digest(&key, counter))
    })
}

/// Function to make totp for a given time. Note that times
/// before Unix epoch are not supported.
fn make_totp_with_time(secret: &str, time_step: u64, skew: i64, time: u64) -> Option<u32> {
    let counter = ((time as i64 + skew) as u64) / time_step;
    make_hotp(secret, counter)
}

/// Performs the [Time-based One-time Password Algorithm](http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm)
/// (TOTP) given an RFC4648 base32 encoded secret, the time step in seconds,
/// and a skew in seconds.
pub fn make_totp(secret: &str, time_step: u64, skew: i64) -> Option<u32> {
    let now = get_time();
    make_totp_with_time(secret, time_step, skew, now.sec as u64)
}

#[cfg(test)]
mod tests {
    use super::{make_hotp, make_totp_with_time};

    #[test]
    fn hotp() {
        assert_eq!(make_hotp("base32secret3232", 0), Some(260182));
        assert_eq!(make_hotp("base32secret3232", 1), Some(55283));
        assert_eq!(make_hotp("base32secret3232", 1401), Some(316439));
    }

    #[test]
    fn totp() {
        assert_eq!(make_totp_with_time("base32secret3232", 30, 0, 0), Some(260182));
        assert_eq!(make_totp_with_time("base32secret3232", 3600, 0, 7), Some(260182));
        assert_eq!(make_totp_with_time("base32secret3232", 30, 0, 35), Some(55283));
        assert_eq!(make_totp_with_time("base32secret3232", 1, -2, 1403), Some(316439));
    }
}
