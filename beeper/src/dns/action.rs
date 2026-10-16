//! The DFA actions for [`dns::Parser`].
//!
//! The actions reside on the edges of the DFA and are executed by the eBPF
//! runtime when it consumes the byte associated with that edge.
//!
//! The state ids, action kinds, flags and fields below must stay in sync with
//! the `S_*`, `DNSA_*`, `DNSF_*` and `DNS_FIELD_*` constants of
//! dns/parser.bpf.c.

use crate::{StateId, dns::parser::types::dns_action};

/// The first byte of the header. The other eleven follow it.
pub const S_HDR: StateId = StateId(2);

/// The first byte of an entry of the question section.
pub const S_QNAME: StateId = StateId(14);

/// The first byte of a resource record.
pub const S_RRNAME: StateId = StateId(15);

/// The first byte of a TLV, of an OPT record or a DSO message.
pub const S_TLV: StateId = StateId(16);

/// While the runtime skips bytes on its own. It has no edges.
pub const S_SKIP: StateId = StateId(17);

/// Number of reserved states (see definitions above).
pub const S_RESERVED: u16 = 18;

/// The transition ends the entry, a question or the RDATA of a record.
pub const F_END: u8 = 1 << 0;

/// The different kinds of [`Action`]s.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Kind {
    /// A byte of the header, `val` being its index.
    Hdr = 1,

    /// The length of a label, which `val` holds.
    Label,

    /// The root label that ends a name.
    Root,

    /// The first byte of a compression pointer, `val` holding its upper bits.
    PtrHi,

    /// The second byte of a compression pointer, which ends the name.
    PtrLo,

    /// A byte of a field that is not its last one.
    Acc,

    /// The last byte of a field, `val` being a [`Field`].
    Store,

    /// The byte is malformed where it is.
    Err,
}

/// The fields a [`Kind::Store`] action completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Field {
    /// The type of a question.
    QType = 1,

    /// The class of a question.
    QClass,

    /// The type of a record.
    Type,

    /// The class of a record.
    Class,

    /// The TTL of a record.
    Ttl,

    /// The RDATA length of a record whose RDATA the DFA walks.
    RdLen,

    /// The RDATA length of a record whose RDATA is opaque.
    RdLenSkip,

    /// The RDATA length of an A record of the class IN, which has to be 4.
    RdLenA,

    /// The RDATA length of an AAAA record of the class IN, which has to be 16.
    RdLenAaaa,

    /// The RDATA length of an OPT record, whose RDATA is a sequence of TLVs.
    RdLenTlv,

    /// The length of the value of a TLV.
    TlvLen,
}

/// The DFA actions for [`dns::Parser`], wrapped for convenience in a struct
/// for usage in [`Dfa`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Action {
    pub kind: Kind,
    pub val: u16,
    pub flags: u8,
}

impl Action {
    /// Returns the action of an edge of `kind` carrying `val`.
    pub const fn new(kind: Kind, val: u16, flags: u8) -> Action {
        Action { kind, val, flags }
    }

    /// Returns the action that completes `field`.
    pub const fn store(field: Field, flags: u8) -> Action {
        Action::new(Kind::Store, field as u16, flags)
    }
}

impl From<Action> for dns_action {
    /// Converts the Rust-based [`Action`] into the eBPF-based `dns_action`.
    fn from(value: Action) -> Self {
        dns_action {
            val: value.val,
            kind: value.kind as u8,
            flags: value.flags,
        }
    }
}
