use rand_old::*;

use ecies_ed25519::*;
use hex::*;

pub struct ECIESAPI;

pub struct ECIESPublicKey(String);
pub struct ECIESSecretKey(String);

impl ECIESAPI {
    pub fn new() -> (ECIESPublicKey,ECIESSecretKey) {
        let mut csprng = rand_old::thread_rng();
        let (secret, public) = ecies_ed25519::generate_keypair(&mut csprng);

        let pk_hex = hex::encode_upper(public.as_bytes());
        let sk_hex = hex::encode_upper(secret.as_bytes());

        return {
            (ECIESPublicKey(pk_hex),ECIESSecretKey(sk_hex))
        }
    }
}

impl ECIESPublicKey {
    pub fn public_key(self) -> String {
        return self.0
    }
}

impl ECIESSecretKey {
    pub fn secret_key(self) -> String {
        return self.0
    }
}

mod tests {
    use super::*;

    #[test]
    fn generate_keypair() {
        let keypair = ECIESAPI::new();

        println!("PK: {}",keypair.0.public_key());
        println!("SK: {}",keypair.1.secret_key());
    }
}