use schnorrkel::*;
use rand::{Rng, rngs::OsRng};

pub const CTX_DEFAULT: &[u8] = b"SLINKYv0.1.0";

// Public-Key: BASE32 FORMAT (CROCKFORD) || 52 len
// Secret-Key: BASE32 FORMAT (CROCKFORD) || 103 len
// Signature: BASE58 || 87-88 len


pub struct SchnorrAPI;

/// Schnorr Public Key (encoded in base32)
#[derive(Debug,Clone,PartialEq,PartialOrd,Hash)]
pub struct SchnorrPublicKey(String);
/// Schnorr Secret Key (encoded in base32)
#[derive(Debug,Clone,PartialEq,PartialOrd,Hash)]
pub struct SchnorrSecretKey(String);

#[derive(Debug,Clone,PartialEq,PartialOrd,Hash)]
pub struct SchnorrSignature(String);

impl SchnorrPublicKey {
    pub fn new<S: AsRef<str>>(pk: S) -> Self {
        if pk.as_ref().len() == 52 {
            return Self(pk.as_ref().to_owned())
        }
        else {
            panic!("Not Length 52");
        }
    }
    pub fn generate() -> (SchnorrPublicKey,SchnorrSecretKey) {
        let keypair: Keypair = Keypair::generate_with(OsRng);
        let bs32_public = base32::encode(base32::Alphabet::Crockford, &keypair.public.to_bytes());
        let bs32_secret = base32::encode(base32::Alphabet::Crockford, &keypair.secret.to_bytes());

        return (SchnorrPublicKey(bs32_public),SchnorrSecretKey(bs32_secret))
    }
    pub fn public_key(&self) -> String {
        return self.0.clone()
    }
    pub fn verify<T: AsRef<[u8]>>(&self, ctx: T, msg: T, signature: SchnorrSignature) -> bool {
        let pk = schnorrkel::keys::PublicKey::from_bytes(&self.to_bytes()).unwrap();
        let is_valid = pk.verify_simple(ctx.as_ref(), msg.as_ref(), &signature.to_signature_in_schnorrkel());

        if is_valid.unwrap() == () {
            return true
        }
        else {
            return false
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let bs32_decoded_as_bytes = base32::decode(base32::Alphabet::Crockford,&self.0).unwrap();
        return bs32_decoded_as_bytes
    }
}

impl SchnorrSecretKey {
    pub fn secret_key(&self) -> String {
        return self.0.clone()
    }
    pub fn sign<T: AsRef<[u8]>>(&self, ctx: T, msg: T) -> SchnorrSignature {
        let decoded = base32::decode(base32::Alphabet::Crockford, &self.0).unwrap();
        let sk = schnorrkel::SecretKey::from_bytes(&decoded).unwrap();
        let pk = sk.to_public();
        let signature = sk.sign_simple_doublecheck(ctx.as_ref(), msg.as_ref(), &pk).unwrap();
        let bs58_signature = bs58::encode(signature.to_bytes()).into_string();
        SchnorrSignature(bs58_signature)
    }
    pub fn validate(&self) -> bool {
        if self.0.len() == 103 {
            return true
        }
        else {
            return false
        }
    }
}

impl SchnorrSignature {
    pub fn to_slinky_signature(&self) -> String {
        return self.0.clone()
    }
    pub fn to_signature_in_schnorrkel(&self) -> schnorrkel::Signature {
        schnorrkel::Signature::from_bytes(&self.to_bytes()).unwrap()
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        return bs58::decode(&self.0).into_vec().unwrap()
    }
    pub fn validate(&self) -> bool {
        if self.0.len() == 87 || self.0.len() == 88 {
            return true
        }
        else {
            return false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_schnorr_keypair() {
        let (pk,sk) = SchnorrPublicKey::generate();

        let msg = "Default Message";
        let sig = sk.sign(CTX_DEFAULT, msg.as_bytes());

        let is_valid = pk.verify(CTX_DEFAULT,msg.as_bytes(),sig.clone());

        println!("Generated Keypair");
        println!("Public Key: {} | length: {}",pk.public_key(), pk.public_key().len());
        println!("Secret Key: {} | length: {}",sk.secret_key(), sk.secret_key().len());
        println!("Signature: {} | length: {}",sig.to_slinky_signature(), sig.to_slinky_signature().len());
        println!("Is Signature Valid: {}", is_valid);
    }
}
