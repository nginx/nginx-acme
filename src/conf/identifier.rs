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
    pub fn value(&self) -> &S {
        match self {
            Identifier::Dns(value) => value,
            Identifier::Ip(value) => value,
            Identifier::Other { value, .. } => value,
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
