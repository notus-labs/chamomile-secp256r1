use fastcrypto::{
    hash::Sha256,
    secp256r1::{
        recoverable::Secp256r1RecoverableSignature, Secp256r1KeyPair, Secp256r1PrivateKey,
        Secp256r1PublicKey,
    },
    traits::{RecoverableSignature, RecoverableSigner, ToFromBytes},
};
use rand_core::{CryptoRng, RngCore};
use secp256k1::rand::Rng;
use sha3::{Digest, Keccak256};

pub use secp256k1;

use crate::types::{new_io_error, PeerId, PEER_ID_LENGTH};

pub const SECRET_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 33;
pub const SIGNATURE_LENGTH: usize = 65;

/// Public Key
#[derive(Clone)]
pub struct PublicKey(Secp256r1PublicKey);

/// Secret Key
pub struct SecretKey(Secp256r1PrivateKey);

pub struct Signature(Secp256r1RecoverableSignature);

/// The keypair, include pk, sk, address
pub struct Key {
    pub pub_key: PublicKey,
    pub sec_key: SecretKey,
}

impl Key {
    pub fn from_sec_key(sec_key: SecretKey) -> Self {
        let pub_key: PublicKey = PublicKey(
            Secp256r1PublicKey::from_bytes(
                sec_key
                    .0
                    .privkey
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes(),
            )
            .unwrap(),
        );
        Self { pub_key, sec_key }
    }

    pub fn from_secp256r1_key(sec_key: Secp256r1PrivateKey) -> Self {
        let sec_key = SecretKey(sec_key);
        Self::from_sec_key(sec_key)
    }

    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Key {
        let random_bytes: [u8; 32] = rng.gen::<[u8; 32]>();
        let sec_key = SecretKey(Secp256r1KeyPair::from_bytes(&random_bytes).unwrap().secret);
        Self::from_sec_key(sec_key)
    }

    pub fn peer_id(&self) -> PeerId {
        self.pub_key.peer_id()
    }

    pub fn public(&self) -> PublicKey {
        self.pub_key.clone()
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        let keypair: Secp256r1KeyPair = Secp256r1PrivateKey::from_bytes(self.sec_key.0.as_bytes())
            .unwrap()
            .into();
        let signature = keypair.sign_recoverable_with_hash::<Sha256>(msg);
        Signature(signature)
    }

    pub fn to_db_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend(&self.sec_key.0.privkey.to_bytes());
        bytes
    }

    pub fn from_db_bytes(bytes: &[u8]) -> std::io::Result<Self> {
        if bytes.len() < SECRET_KEY_LENGTH {
            return Err(new_io_error("keypair from db bytes failure."));
        }
        let sec_key = SecretKey(
            Secp256r1PrivateKey::from_bytes(&bytes[..SECRET_KEY_LENGTH])
                .map_err(|_| new_io_error("secret key from db bytes failure."))?,
        );
        Ok(Self::from_sec_key(sec_key))
    }
}

impl PublicKey {
    pub fn new(pk: Secp256r1PublicKey) -> Self {
        Self(pk)
    }

    pub fn raw(&self) -> &Secp256r1PublicKey {
        &self.0
    }

    pub fn peer_id(&self) -> PeerId {
        let public_key = self.0.as_bytes();
        let mut hasher = Keccak256::new();
        hasher.update(&public_key[1..]);
        let result = hasher.finalize();
        let mut bytes = [0u8; PEER_ID_LENGTH];
        bytes.copy_from_slice(&result[12..]);
        PeerId(bytes)
    }
}

impl SecretKey {
    pub fn new(sk: Secp256r1PrivateKey) -> Self {
        Self(sk)
    }

    pub fn raw(&self) -> &Secp256r1PrivateKey {
        &self.0
    }
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> std::io::Result<Signature> {
        if bytes.len() != SIGNATURE_LENGTH {
            return Err(new_io_error("Invalid signature length"));
        }

        Ok(Signature(
            Secp256r1RecoverableSignature::from_bytes(bytes).unwrap(),
        ))
    }

    pub fn peer_id(&self, msg: &[u8]) -> std::io::Result<PeerId> {
        let pub_key = self.0.recover_with_hash::<Sha256>(msg);

        let pk = pub_key.map_err(|_| new_io_error("Invalid signature"))?;
        Ok(PublicKey(pk).peer_id())
    }
}

impl TryFrom<&str> for PublicKey {
    type Error = std::io::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(s).map_err(|_| new_io_error("Invalid public key hex"))?;
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(new_io_error("Invalid public key length"));
        }
        Ok(PublicKey(
            Secp256r1PublicKey::from_bytes(&bytes)
                .map_err(|_| new_io_error("Invalid public key value"))?,
        ))
    }
}

impl ToString for PublicKey {
    fn to_string(&self) -> String {
        hex::encode(self.0.as_bytes())
    }
}

impl TryFrom<&str> for SecretKey {
    type Error = std::io::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(s).map_err(|_| new_io_error("Invalid secret key hex"))?;
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(new_io_error("Invalid secret key length"));
        }
        Ok(SecretKey(
            Secp256r1PrivateKey::from_bytes(&bytes)
                .map_err(|_| new_io_error("Invalid secret key value"))?,
        ))
    }
}

impl ToString for SecretKey {
    fn to_string(&self) -> String {
        hex::encode(self.0.privkey.to_bytes())
    }
}
