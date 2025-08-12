// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::fmt;
use std::borrow::ToOwned;
use std::string::String;

use ngx::collections::{vec, Vec};
use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, PKeyRef, Private};
use openssl_foreign_types::ForeignTypeRef;
use serde::{ser::SerializeMap, Serialize, Serializer};
use thiserror::Error;

/// A JWS header, as defined in RFC 8555 Section 6.2.
#[derive(Serialize)]
struct JwsHeader<'a, Jwk: JsonWebKey> {
    pub alg: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<&'a str>,
    pub url: &'a str,
    // Per 8555 6.2, "jwk" and "kid" fields are mutually exclusive.
    #[serde(flatten)]
    pub key: JwsHeaderKey<'a, Jwk>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum JwsHeaderKey<'a, Jwk: JsonWebKey> {
    Jwk { jwk: &'a Jwk },
    Kid { kid: &'a str },
}

#[derive(Debug, Serialize)]
pub struct SignedMessage {
    protected: String,
    payload: String,
    signature: String,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("serialize failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("crypto: {0}")]
    Crypto(#[from] openssl::error::ErrorStack),
}

#[derive(Debug, Error)]
pub enum NewKeyError {
    #[error("unsupported key algorithm ({0:?})")]
    Algorithm(Id),
    #[error("unsupported key size ({0})")]
    Size(u32),
}

pub trait JsonWebKey: Serialize {
    fn alg(&self) -> &str;
    fn compute_mac(&self, header: &[u8], payload: &[u8]) -> Result<Vec<u8>, Error>;

    /// Returns a key thumbprint, as defined in RFC7638
    fn thumbprint(&self) -> Result<String, Error> {
        let data = serde_json::to_vec(self)?;
        Ok(base64url(openssl::sha::sha256(&data)))
    }
}

#[derive(Debug)]
pub(crate) struct ShaWithEcdsaKey(PKey<Private>);

#[derive(Debug)]
pub(crate) struct ShaWithRsaKey(PKey<Private>);

#[derive(Debug)]
pub(crate) struct ShaWithHmacKey<T>(T, u16)
where
    T: AsRef<[u8]>;

#[inline]
pub fn base64url<T: AsRef<[u8]>>(buf: T) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, buf)
}

pub fn sign_jws<Jwk: JsonWebKey>(
    jwk: &Jwk,
    kid: Option<&str>,
    url: &str,
    nonce: Option<&str>,
    payload: &[u8],
) -> Result<SignedMessage, Error> {
    let key = match kid {
        Some(kid) => JwsHeaderKey::Kid { kid },
        None => JwsHeaderKey::Jwk { jwk },
    };

    let header = JwsHeader {
        alg: jwk.alg(),
        nonce,
        url,
        key,
    };

    let header_json = serde_json::to_vec(&header)?;

    let protected = base64url(&header_json);
    let payload = base64url(payload);
    let signature = jwk.compute_mac(protected.as_bytes(), payload.as_bytes())?;
    let signature = base64url(signature);

    Ok(SignedMessage {
        protected,
        payload,
        signature,
    })
}

impl fmt::Display for SignedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            r#"{{"protected":"{}","payload":"{}","signature":"{}"}}"#,
            self.protected, self.payload, self.signature
        )
    }
}

impl JsonWebKey for ShaWithEcdsaKey {
    fn alg(&self) -> &str {
        match self.0.bits() {
            256 => "ES256",
            384 => "ES384",
            521 => "ES512",
            _ => unreachable!("unsupported key size"),
        }
    }

    fn compute_mac(&self, header: &[u8], payload: &[u8]) -> Result<Vec<u8>, Error> {
        let bits = self.0.bits() as usize;
        let pad_to = bits.div_ceil(8);

        let md = match bits {
            384 => openssl::hash::MessageDigest::sha384(),
            521 => openssl::hash::MessageDigest::sha512(),
            _ => openssl::hash::MessageDigest::sha256(),
        };

        let mut signer = openssl::sign::Signer::new(md, &self.0)?;
        signer.update(header)?;
        signer.update(b".")?;
        signer.update(payload)?;

        let mut buf = vec![0u8; signer.len()?];

        let len = signer.sign(&mut buf)?;
        buf.truncate(len);

        let sig = openssl::ecdsa::EcdsaSig::from_der(&buf)?;
        buf.resize(2 * pad_to, 0);

        bn2binpad(sig.r(), &mut buf[0..pad_to])?;
        bn2binpad(sig.s(), &mut buf[pad_to..])?;

        Ok(buf)
    }
}

impl Serialize for ShaWithEcdsaKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;

        let ec_key = self.0.ec_key().map_err(Error::custom)?;
        let group = ec_key.group();

        let (crv, bits): (_, usize) = match group.curve_name() {
            Some(Nid::X9_62_PRIME256V1) => ("P-256", 256),
            Some(Nid::SECP384R1) => ("P-384", 384),
            Some(Nid::SECP521R1) => ("P-521", 521),
            _ => return Err(Error::custom("unsupported curve")),
        };

        let mut x = BigNum::new().map_err(Error::custom)?;
        let mut y = BigNum::new().map_err(Error::custom)?;
        let mut ctx = BigNumContext::new().map_err(Error::custom)?;
        ec_key
            .public_key()
            .affine_coordinates(group, &mut x, &mut y, &mut ctx)
            .map_err(Error::custom)?;

        let mut buf = vec![0u8; bits.div_ceil(8)];

        let x = base64url(bn2binpad(&x, &mut buf).map_err(Error::custom)?);
        let y = base64url(bn2binpad(&y, &mut buf).map_err(Error::custom)?);

        let mut map = serializer.serialize_map(Some(4))?;
        // order is important for thumbprint generation (RFC7638)
        map.serialize_entry("crv", crv)?;
        map.serialize_entry("kty", "EC")?;
        map.serialize_entry("x", &x)?;
        map.serialize_entry("y", &y)?;
        map.end()
    }
}

impl TryFrom<&PKeyRef<Private>> for ShaWithEcdsaKey {
    type Error = NewKeyError;

    fn try_from(pkey: &PKeyRef<Private>) -> Result<Self, Self::Error> {
        if pkey.id() != Id::EC {
            return Err(NewKeyError::Algorithm(pkey.id()));
        }

        let bits = pkey.bits();
        if !matches!(bits, 256 | 384 | 521) {
            return Err(NewKeyError::Size(bits));
        }

        Ok(Self(pkey.to_owned()))
    }
}

impl JsonWebKey for ShaWithRsaKey {
    fn alg(&self) -> &str {
        "RS256"
    }

    fn compute_mac(&self, header: &[u8], payload: &[u8]) -> Result<Vec<u8>, Error> {
        let md = openssl::hash::MessageDigest::sha256();

        let mut signer = openssl::sign::Signer::new(md, &self.0)?;
        signer.update(header)?;
        signer.update(b".")?;
        signer.update(payload)?;

        let mut buf = vec![0u8; signer.len()?];

        let len = signer.sign(&mut buf)?;
        buf.truncate(len);

        Ok(buf)
    }
}

impl Serialize for ShaWithRsaKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;

        let rsa = self.0.rsa().map_err(Error::custom)?;

        let num_bytes = rsa.e().num_bytes().max(rsa.n().num_bytes()) as usize;
        let mut buf = vec![0u8; num_bytes];

        let e = base64url(bn2bin(rsa.e(), &mut buf).map_err(Error::custom)?);
        let n = base64url(bn2bin(rsa.n(), &mut buf).map_err(Error::custom)?);

        let mut map = serializer.serialize_map(Some(3))?;
        // order is important for thumbprint generation (RFC7638)
        map.serialize_entry("e", &e)?;
        map.serialize_entry("kty", "RSA")?;
        map.serialize_entry("n", &n)?;
        map.end()
    }
}

impl TryFrom<&PKeyRef<Private>> for ShaWithRsaKey {
    type Error = NewKeyError;

    fn try_from(pkey: &PKeyRef<Private>) -> Result<Self, Self::Error> {
        if pkey.id() != Id::RSA {
            return Err(NewKeyError::Algorithm(pkey.id()));
        }

        let bits = pkey.bits();
        if bits < 2048 {
            return Err(NewKeyError::Size(bits));
        }

        Ok(Self(pkey.to_owned()))
    }
}

impl<T> JsonWebKey for ShaWithHmacKey<T>
where
    T: AsRef<[u8]>,
{
    fn alg(&self) -> &str {
        match self.1 {
            256 => "HS256",
            384 => "HS384",
            512 => "HS512",
            _ => unreachable!("unsupported digest"),
        }
    }

    fn compute_mac(&self, header: &[u8], payload: &[u8]) -> Result<Vec<u8>, Error> {
        let md = match self.1 {
            384 => openssl::hash::MessageDigest::sha384(),
            512 => openssl::hash::MessageDigest::sha512(),
            _ => openssl::hash::MessageDigest::sha256(),
        };

        // Cannot use Signer here because BoringSSL does not provide `EVP_PKEY_new_from_mac`.
        let mut inbuf = Vec::with_capacity(header.len() + payload.len() + 1);
        inbuf.extend_from_slice(header);
        inbuf.push(b'.');
        inbuf.extend_from_slice(payload);

        let mut buf = vec![0u8; md.size()];

        let len = hmac(&md, self.0.as_ref(), &inbuf, &mut buf)?;
        buf.truncate(len);

        Ok(buf)
    }
}

impl<T> Serialize for ShaWithHmacKey<T>
where
    T: AsRef<[u8]>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let k = base64url(self.0.as_ref());
        let mut map = serializer.serialize_map(Some(2))?;
        // order is important for thumbprint generation (RFC7638)
        map.serialize_entry("k", &k)?;
        map.serialize_entry("kty", "oct")?;
        map.end()
    }
}

impl<T> ShaWithHmacKey<T>
where
    T: AsRef<[u8]>,
{
    pub fn new(key: T, bits: u16) -> Self {
        Self(key, bits)
    }
}

/// [openssl] offers [BigNumRef::to_vec()], but we want to avoid an extra allocation.
fn bn2bin<'a>(bn: &BigNumRef, out: &'a mut [u8]) -> Result<&'a [u8], ErrorStack> {
    debug_assert!(bn.num_bytes() as usize <= out.len());
    let n = unsafe { openssl_sys::BN_bn2bin(bn.as_ptr(), out.as_mut_ptr()) };
    if n >= 0 {
        Ok(&out[..n as usize])
    } else {
        Err(ErrorStack::get())
    }
}

/// [openssl] offers [BigNumRef::to_vec_padded()], but we want to avoid an extra allocation.
fn bn2binpad<'a>(bn: &BigNumRef, out: &'a mut [u8]) -> Result<&'a [u8], ErrorStack> {
    let n = unsafe { openssl_sys::BN_bn2binpad(bn.as_ptr(), out.as_mut_ptr(), out.len() as _) };
    if n >= 0 {
        Ok(&out[..n as usize])
    } else {
        Err(ErrorStack::get())
    }
}

fn hmac(
    digest: &openssl::hash::MessageDigest,
    key: &[u8],
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, ErrorStack> {
    debug_assert!(out.len() >= digest.size());

    let mut len: core::ffi::c_uint = 0;
    let p = unsafe {
        openssl_sys::HMAC(
            digest.as_ptr(),
            key.as_ptr().cast(),
            key.len() as _,
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
            &mut len,
        )
    };

    if p.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(len as _)
    }
}
