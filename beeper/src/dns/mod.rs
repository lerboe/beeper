//! DNS parsing.
//!
//! Unlike HTTP, a DNS message is laid out in binary and announces the length
//! of each of its parts, so [`Parser`] needs no patterns: it only picks which
//! functions of the target program to replace. The parser follows RFC 1035 and
//! the RFCs updating it, see `beeper/dns.h` for the details.
//!
//! The parser checks a message as a whole: its header, every question and
//! record, the compression pointers of every name, the RDATA of the types laid
//! out with names, the placement of the OPT and TSIG records and the
//! constraints the opcode puts on the counts. A message it accepts can then be
//! walked record by record, and its names extracted.
//!
//! # Examples
//!
//! ```no_run
//! # fn main() -> Result<(), beeper::Error> {
//! # let prog_fd = 0;
//! use beeper::{MessageBuffer, dns};
//!
//! let parser = dns::Parser::new()
//!     .parse_fn("parse_dns", MessageBuffer::Skb)
//!     .next_rr_fn("next_dns_rr", MessageBuffer::Skb)
//!     .extract_name_fn("extract_dns_name", MessageBuffer::Skb)
//!     .attach(prog_fd)?;
//! # Ok(())
//! # }
//! ```
//!
//! The target program declares the stubs and calls them on a UDP payload:
//!
//! ```c
//! #include "beeper/dns.h"
//!
//! BEEPER_DNS_PARSE_SKB(parse_dns)
//! BEEPER_DNS_NEXT_RR_SKB(next_dns_rr)
//! BEEPER_DNS_EXTRACT_NAME_SKB(extract_dns_name)
//!
//! SEC("tc")
//! int ingress(struct __sk_buff *skb) {
//!     u32 off = ...; // where the UDP payload starts
//!
//!     struct dns_parse_res pres = { 0 };
//!     if (parse_dns(skb, off, 0, &pres) < 0) return TC_ACT_SHOT;
//!
//!     struct dns_name_buf qname = { 0 };
//!     if (pres.hdr.qdcount > 0 &&
//!         extract_dns_name(skb, &pres, pres.q.name.off, DNS_NAME_LOWER, &qname) >= 0) {
//!         // qname.buf holds the qname.len octets of the name in wire format
//!     }
//!
//!     struct dns_rr rr = { 0 };
//!     while (next_dns_rr(skb, &pres, &rr) == 0) {
//!         // rr.type, rr.ttl, rr.rdata_off, ...
//!     }
//!
//!     return TC_ACT_OK;
//! }
//! ```

mod parser;

pub use parser::AttachedParser;
pub use parser::Parser;

#[cfg(test)]
mod tests;
