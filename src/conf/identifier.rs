// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use core::fmt;
use core::str;

use ngx::allocator::{AllocError, Allocator, TryCloneIn};
use ngx::core::NgxString;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum Identifier<S> {
    Dns(S),
    Ip(S),
    #[serde(untagged)]
    Other {
        #[serde(rename = "type")]
        kind: S,
        value: S,
    },
}

impl<S> Identifier<S> {
    pub fn as_ref<T>(&self) -> Identifier<&T>
    where
        S: AsRef<T>,
        T: ?Sized,
    {
        match self {
            Identifier::Dns(x) => Identifier::Dns(x.as_ref()),
            Identifier::Ip(x) => Identifier::Ip(x.as_ref()),
            Identifier::Other { kind, value } => Identifier::Other {
                kind: kind.as_ref(),
                value: value.as_ref(),
            },
        }
    }

    /// Borrows the current identifier with a str reference as an underlying data.
    pub fn as_str(&self) -> Result<Identifier<&str>, str::Utf8Error>
    where
        S: AsRef<[u8]>,
    {
        match self {
            Identifier::Dns(value) => str::from_utf8(value.as_ref()).map(Identifier::Dns),
            Identifier::Ip(value) => str::from_utf8(value.as_ref()).map(Identifier::Ip),
            Identifier::Other { kind, value } => Ok(Identifier::Other {
                kind: str::from_utf8(kind.as_ref())?,
                value: str::from_utf8(value.as_ref())?,
            }),
        }
    }

    pub fn value(&self) -> &S {
        match self {
            Identifier::Dns(value) => value,
            Identifier::Ip(value) => value,
            Identifier::Other { value, .. } => value,
        }
    }
}

impl<S> fmt::Display for Identifier<S>
where
    S: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Identifier::Dns(value) => write!(f, "DNS:{value}"),
            Identifier::Ip(value) => write!(f, "IP:{value}"),
            Identifier::Other { kind, value } => write!(f, "{kind}:{value}"),
        }
    }
}

// Allow comparing identifiers with any underlying types.
impl<S, O> PartialEq<Identifier<O>> for Identifier<S>
where
    S: PartialEq<O>,
{
    fn eq(&self, other: &Identifier<O>) -> bool {
        match (self, other) {
            (Identifier::Dns(x), Identifier::Dns(y)) => x == y,
            (Identifier::Ip(x), Identifier::Ip(y)) => x == y,
            (
                Identifier::Other {
                    kind: xk,
                    value: xv,
                },
                Identifier::Other {
                    kind: yk,
                    value: yv,
                },
            ) => xk == yk && xv == yv,
            _ => false,
        }
    }
}

impl<S> TryCloneIn for Identifier<S>
where
    S: AsRef<[u8]>,
{
    type Target<A: Allocator + Clone> = Identifier<NgxString<A>>;

    fn try_clone_in<A: Allocator + Clone>(&self, alloc: A) -> Result<Self::Target<A>, AllocError> {
        let try_clone =
            |x: &S| NgxString::try_from_bytes_in(x.as_ref(), alloc.clone()).map_err(|_| AllocError);

        match self {
            Identifier::Dns(x) => try_clone(x).map(Identifier::Dns),
            Identifier::Ip(x) => try_clone(x).map(Identifier::Ip),
            Identifier::Other { kind, value } => Ok(Identifier::Other {
                kind: try_clone(kind)?,
                value: try_clone(value)?,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_identifier() {
        let id: Identifier<&str> =
            serde_json::from_str(r#"{ "type": "dns", "value": "example.com" }"#).unwrap();
        assert_eq!(id, Identifier::Dns("example.com"));

        let id: Identifier<&str> =
            serde_json::from_str(r#"{ "type": "ip", "value": "127.0.0.1" }"#).unwrap();
        assert_eq!(id, Identifier::Ip("127.0.0.1"));

        let id: Identifier<&str> =
            serde_json::from_str(r#"{ "type": "email", "value": "admin@example.test" }"#).unwrap();
        assert_eq!(
            id,
            Identifier::Other {
                kind: "email",
                value: "admin@example.test"
            }
        );
    }
}
