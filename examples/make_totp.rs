extern crate otp;
use std::env;

fn main() {
    let args = env::args();
    if args.len() != 2 {
        println!("Usage: ./make_totp secret");
    } else {
        let args = args.collect::<Vec<_>>();
        let secret = args.get(1).unwrap();
        println!("{:?}", otp::make_totp(secret, 30, 0));
    }
}
