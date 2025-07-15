use ngx::allocator::{AllocError, Allocator, TryCloneIn};
use ngx::core::NgxString;

#[derive(Clone, Debug, Eq, Hash, PartialOrd, Ord)]
pub enum Identifier<S> {
    Dns(S),
    Ip(S),
}

impl<S> Identifier<S> {
    pub fn value(&self) -> &S {
        match self {
            Identifier::Dns(value) => value,
            Identifier::Ip(value) => value,
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
        }
    }
}
