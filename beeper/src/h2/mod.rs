//! HTTP/2 parsing.
//!
//! HTTP/2 does not spell its header fields out on the wire. HPACK either
//! replaces a field with an index into the static or the dynamic table, or
//! Huffman encodes it. [`Parser`] therefore matches the Huffman encoded field
//! name against its DFA and mirrors the peer's dynamic table in a BPF map, so
//! that indexed fields can be resolved in the kernel as well.

use std::collections::HashMap;
use std::net::SocketAddr;

mod hpack;
mod parser;
pub use parser::{AttachedParser, Parser, ip4_addr, ip4_conn};

impl From<SocketAddr> for ip4_addr {
    /// Converts `addr` into the address the BPF programs key their per
    /// connection state with.
    ///
    /// # Panics
    ///
    /// Panics if `addr` is an IPv6 address, which Beeper does not support yet.
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => ip4_addr {
                ip4: u32::from_ne_bytes(addr.ip().octets()),
                port: addr.port() as u32,
            },
            SocketAddr::V6(_) => panic!("ip4_addr does not support IPv6 addresses"),
        }
    }
}

/// Returns the HPACK static table, split by whether an entry predefines a
/// value or not.
///
/// The first map goes from a field name to its index, the second from a field
/// name to the index of each of the values that are predefined for it. See
/// appendix A of RFC 7541.
fn create_header_maps() -> (
    HashMap<String, usize>,
    HashMap<String, HashMap<String, usize>>,
) {
    // HashMap for headers without values (header_name -> index)
    let mut headers_without_values = HashMap::new();

    // HashMap for headers with values (header_name -> (header_value -> index))
    let mut headers_with_values: HashMap<String, HashMap<String, usize>> = HashMap::new();

    // Headers without values
    headers_without_values.insert("authority".to_string(), 1);
    headers_without_values.insert("accept-charset".to_string(), 15);
    headers_without_values.insert("accept-language".to_string(), 17);
    headers_without_values.insert("accept-ranges".to_string(), 18);
    headers_without_values.insert("accept".to_string(), 19);
    headers_without_values.insert("access-control-allow-origin".to_string(), 20);
    headers_without_values.insert("age".to_string(), 21);
    headers_without_values.insert("allow".to_string(), 22);
    headers_without_values.insert("authorization".to_string(), 23);
    headers_without_values.insert("cache-control".to_string(), 24);
    headers_without_values.insert("content-disposition".to_string(), 25);
    headers_without_values.insert("content-encoding".to_string(), 26);
    headers_without_values.insert("content-language".to_string(), 27);
    headers_without_values.insert("content-length".to_string(), 28);
    headers_without_values.insert("content-location".to_string(), 29);
    headers_without_values.insert("content-range".to_string(), 30);
    headers_without_values.insert("content-type".to_string(), 31);
    headers_without_values.insert("cookie".to_string(), 32);
    headers_without_values.insert("date".to_string(), 33);
    headers_without_values.insert("etag".to_string(), 34);
    headers_without_values.insert("expect".to_string(), 35);
    headers_without_values.insert("expires".to_string(), 36);
    headers_without_values.insert("from".to_string(), 37);
    headers_without_values.insert("host".to_string(), 38);
    headers_without_values.insert("if-match".to_string(), 39);
    headers_without_values.insert("if-modified-since".to_string(), 40);
    headers_without_values.insert("if-none-match".to_string(), 41);
    headers_without_values.insert("if-range".to_string(), 42);
    headers_without_values.insert("if-unmodified-since".to_string(), 43);
    headers_without_values.insert("last-modified".to_string(), 44);
    headers_without_values.insert("link".to_string(), 45);
    headers_without_values.insert("location".to_string(), 46);
    headers_without_values.insert("max-forwards".to_string(), 47);
    headers_without_values.insert("proxy-authenticate".to_string(), 48);
    headers_without_values.insert("proxy-authorization".to_string(), 49);
    headers_without_values.insert("range".to_string(), 50);
    headers_without_values.insert("referer".to_string(), 51);
    headers_without_values.insert("refresh".to_string(), 52);
    headers_without_values.insert("retry-after".to_string(), 53);
    headers_without_values.insert("server".to_string(), 54);
    headers_without_values.insert("set-cookie".to_string(), 55);
    headers_without_values.insert("strict-transport-security".to_string(), 56);
    headers_without_values.insert("transfer-encoding".to_string(), 57);
    headers_without_values.insert("user-agent".to_string(), 58);
    headers_without_values.insert("vary".to_string(), 59);
    headers_without_values.insert("via".to_string(), 60);
    headers_without_values.insert("www-authenticate".to_string(), 61);

    // Headers with values
    // :method
    let mut method_map = HashMap::new();
    method_map.insert("GET".to_string(), 2);
    method_map.insert("POST".to_string(), 3);
    headers_with_values.insert("method".to_string(), method_map);

    // :path
    let mut path_map = HashMap::new();
    path_map.insert("/".to_string(), 4);
    path_map.insert("/index.html".to_string(), 5);
    headers_with_values.insert("path".to_string(), path_map);

    // :scheme
    let mut scheme_map = HashMap::new();
    scheme_map.insert("http".to_string(), 6);
    scheme_map.insert("https".to_string(), 7);
    headers_with_values.insert("scheme".to_string(), scheme_map);

    // :status
    let mut status_map = HashMap::new();
    status_map.insert("200".to_string(), 8);
    status_map.insert("204".to_string(), 9);
    status_map.insert("206".to_string(), 10);
    status_map.insert("304".to_string(), 11);
    status_map.insert("400".to_string(), 12);
    status_map.insert("404".to_string(), 13);
    status_map.insert("500".to_string(), 14);
    headers_with_values.insert("status".to_string(), status_map);

    // accept-encoding
    let mut accept_encoding_map = HashMap::new();
    accept_encoding_map.insert("gzip, deflate".to_string(), 16);
    headers_with_values.insert("accept-encoding".to_string(), accept_encoding_map);

    (headers_without_values, headers_with_values)
}

/// The action a transition of the DFA carries.
///
/// Unlike HTTP/1.x, a field value does not have to be delimited by matching its
/// end: HPACK prefixes it with its length. A single action per matched field
/// name is therefore enough.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Capture a field value identified by the capture id
    CaptureFieldValue(u8),

    /// Terminates parsing
    Done,

    /// No action
    None,
}

impl Action {
    /// Returns `true` if the transition carries an action.
    pub fn is_some(&self) -> bool {
        !self.is_none()
    }

    /// Returns `true` if the transition carries no action.
    pub fn is_none(&self) -> bool {
        matches!(self, Action::None)
    }
}
