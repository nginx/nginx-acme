use nginx_sys::ngx_str_t;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use thiserror::Error;

#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum PrivateKey {
    Ecdsa(u32),
    Rsa(u32),
    File(ngx_str_t),
    Unset,
}

impl Default for PrivateKey {
    fn default() -> Self {
        Self::Ecdsa(256)
    }
}

#[derive(Debug, Error)]
pub enum PKeyParseError {
    #[error("unsupported key size")]
    Bits,
    #[error("unsupported curve")]
    Curve,
    #[error("invalid UTF-8 in key name")]
    Utf8(#[from] core::str::Utf8Error),
}

#[derive(Debug, Error)]
pub enum PKeyGenError {
    #[error("key generation error: {0}")]
    Ssl(#[from] openssl::error::ErrorStack),
    #[error("cannot generate this key")]
    Invalid,
}

impl TryFrom<ngx_str_t> for PrivateKey {
    type Error = PKeyParseError;

    fn try_from(value: ngx_str_t) -> Result<Self, Self::Error> {
        let bytes = value.as_bytes();
        let split = if let Some(idx) = bytes.iter().position(|x| *x == b':') {
            (&bytes[..idx], Some(&bytes[idx + 1..]))
        } else {
            (bytes, None)
        };

        let p = match split.0 {
            b"ecdsa" => match split.1 {
                None | Some(b"256") => PrivateKey::Ecdsa(256),
                Some(b"384") => PrivateKey::Ecdsa(384),
                Some(b"521") => PrivateKey::Ecdsa(521),
                _ => return Err(PKeyParseError::Curve),
            },
            b"rsa" => match split.1 {
                None | Some(b"2048") => PrivateKey::Rsa(2048),
                Some(b"3072") => PrivateKey::Rsa(3072),
                Some(b"4096") => PrivateKey::Rsa(4096),
                _ => return Err(PKeyParseError::Bits),
            },
            _ => PrivateKey::File(value),
        };

        Ok(p)
    }
}

impl PrivateKey {
    pub fn generate(&self) -> Result<PKey<Private>, PKeyGenError> {
        match self {
            PrivateKey::Ecdsa(bits) => {
                let nid = match bits {
                    256 => Nid::X9_62_PRIME256V1,
                    384 => Nid::SECP384R1,
                    521 => Nid::SECP521R1,
                    _ => unreachable!(),
                };
                let group = openssl::ec::EcGroup::from_curve_name(nid)?;
                let ec_key = openssl::ec::EcKey::generate(&group)?;
                Ok(PKey::from_ec_key(ec_key)?)
            }
            PrivateKey::Rsa(bits) => {
                let rsa = openssl::rsa::Rsa::generate(*bits)?;
                Ok(PKey::from_rsa(rsa)?)
            }
            _ => Err(PKeyGenError::Invalid),
        }
    }
}
