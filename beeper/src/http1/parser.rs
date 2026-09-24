use crate::{
    Error, MatchId,
    dfa::{
        ANY_STATE, INIT_STATE,
        action::Action,
        parser::{self as dfa_parser, AttachedParser, load_parser_program},
    },
    pseudo_header::{METHOD, PATH, STATUS},
};
use std::collections::HashMap;

// the skeleton refers to libbpf by the name of the crate xbpf wraps
use xbpf::libbpf as libbpf_rs;

const CR: &str = "\r";
const LF: &str = "\n";

/// What a [`Parser`] keeps track of while it is being configured.
#[derive(Default)]
pub struct Http1 {
    /// The match id of every header captured so far, lowercased as the parser
    /// matches it, so that a header asked for twice is captured once.
    captures: HashMap<String, MatchId>,
}

/// A parser for HTTP/1.x messages.
///
/// The builder methods configure which fields the parser captures and which
/// functions of the target program it replaces. Nothing is loaded into the
/// kernel until [`Parser::attach`] is called.
pub type Parser = dfa_parser::Parser<Http1>;

xbpf::include_bpf!("http1/parser");
load_parser_program!("HTTP/1.1");

impl Parser {
    /// Configures the parser to capture the value of a header field.
    ///
    /// The field is matched case insensitively and its value is captured up to
    /// the end of the line, without the optional whitespace that may follow the
    /// colon. [`METHOD`], [`PATH`] and [`STATUS`] are not header fields in
    /// HTTP/1.x and are captured from the request or status line instead.
    ///
    /// # Arguments
    ///
    /// * `name` - The header name whose value to capture, matched case
    ///   insensitively. A [`PseudoHeader`] names a field of the request or
    ///   status line.
    ///
    /// # Errors
    ///
    /// Returns an error if the parser already captures as many fields as the
    /// parser program has room for.
    ///
    /// # Returns
    ///
    /// The match ID that can be used in eBPF to extract the captured value. A
    /// header that is already captured keeps the ID it was given the first
    /// time, rather than being captured a second time under a new one.
    pub fn capture_hdr<H: AsRef<str>>(&mut self, name: H) -> Result<MatchId, Error> {
        let name = name.as_ref().to_lowercase();
        if let Some(&mid) = self.proto.captures.get(&name) {
            return Ok(mid);
        }

        let mid = self.capture_new_hdr(&name)?;
        self.proto.captures.insert(name, mid);

        Ok(mid)
    }

    /// Configures the parser to capture the value of a header field it does
    /// not capture yet, see [`Parser::capture_hdr`].
    fn capture_new_hdr(&mut self, name: &str) -> Result<MatchId, Error> {
        if name == METHOD.as_str() || name == PATH.as_str() {
            return self.capture_status_line_hdr(name);
        } else if name == STATUS.as_str() {
            return self.capture_status_code();
        }

        let mid = self.new_match()?;
        let mut pattern = self.dfa.start_pattern(ANY_STATE);
        pattern
            .push(LF)
            .push_ci(name)
            .push_optional("\t", true)
            .push_optional(" ", true)
            .push_ci(":")
            .push_optional("\t", true)
            .push_optional(" ", true)
            .with(Action::StartCapture(mid));

        // the value begins here, and it may be empty
        let value = pattern.state();
        pattern
            .push_any(1..)
            .with(Action::EndCapture(mid))
            .push_optional(CR, false)
            .restart_with(LF);

        // an empty value ends its line where it would have begun, and there is
        // nothing in it to capture
        self.dfa
            .start_pattern(value)
            .push_optional(CR, false)
            .restart_with(LF);

        Ok(mid)
    }

    /// Configures the parser to match an HTTP/2 preface in an HTTP/1.1 connection.
    ///
    /// This method sets up pattern matching for the HTTP/2 connection preface
    /// (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`), which is used to upgrade from HTTP/1.1 to HTTP/2.
    ///
    /// The preface is captured as a match, so the target program can detect the
    /// upgrade and switch to an HTTP/2 parser for the rest of the connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the parser already captures as many fields as the
    /// parser program has room for.
    ///
    /// # Returns
    ///
    /// The match ID that can be used in eBPF to extract the captured value.
    pub fn match_http2_preface(&mut self) -> Result<MatchId, Error> {
        let mid = self.new_match()?;
        self.dfa
            .start_pattern(INIT_STATE)
            .with(Action::StartCapture(mid))
            .push(&format!(
                "PRI * HTTP/2.0{}{}{}{}SM{}{}{}{}",
                CR, LF, CR, LF, CR, LF, CR, LF
            ))
            .with(Action::EndCaptureAndDone(mid));

        Ok(mid)
    }

    /// Configures the parser to stop at the empty line that ends the header
    /// block, so that it never walks into the body of a message.
    fn done_on_hdr_end(&mut self) {
        self.dfa
            .start_pattern(ANY_STATE)
            .push_optional(CR, false)
            .push(LF)
            .push_optional(CR, false)
            .push(LF)
            .with(Action::Done);
    }

    /// Configures the parser to match the request line and capture the field
    /// `name` addresses.
    ///
    /// # Panics
    ///
    /// Panics if `name` is neither [`METHOD`] nor [`PATH`].
    ///
    /// # Errors
    ///
    /// Returns an error if the parser already captures as many fields as the
    /// parser program has room for.
    ///
    /// # Returns
    ///
    /// The match ID that can be used in eBPF to extract the captured value.
    fn capture_status_line_hdr(&mut self, name: &str) -> Result<MatchId, Error> {
        let methods = [
            "POST", "GET", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE",
        ];

        let mid = self.new_match()?;
        if name == METHOD.as_str() {
            self.dfa
                .start_pattern(INIT_STATE)
                .with(Action::StartCapture(mid))
                .push_options_ci(&methods)
                .with(Action::EndCapture(mid))
                .push(" ")
                .push_any(1..)
                .push_ci(" HTTP/1.1")
                .push_optional(CR, false)
                .restart_with(LF);
        } else if name == PATH.as_str() {
            self.dfa
                .start_pattern(INIT_STATE)
                .push_options_ci(&methods)
                .push(" ")
                .with(Action::StartCapture(mid))
                .push_any(1..)
                .with(Action::EndCapture(mid))
                .push_ci(" HTTP/1.1")
                .push_optional(CR, false)
                .restart_with(LF);
        } else {
            panic!(
                "capture_status_line_hdr called with unsupported header name: {}",
                name
            );
        }

        Ok(mid)
    }

    /// Configures the parser to match the status line of a response and capture
    /// its status code.
    ///
    /// # Errors
    ///
    /// Returns an error if the parser already captures as many fields as the
    /// parser program has room for.
    ///
    /// # Returns
    ///
    /// The match ID that can be used in eBPF to extract the captured value.
    fn capture_status_code(&mut self) -> Result<MatchId, Error> {
        let mid = self.new_match()?;
        self.dfa
            .start_pattern(INIT_STATE)
            .push_ci("HTTP/1.1 ")
            .with(Action::StartCapture(mid))
            .push_any(3..=3)
            .with(Action::EndCapture(mid))
            .push_any(1..)
            .push_optional(CR, false)
            .restart_with(LF);

        Ok(mid)
    }

    /// Loads the configured parser and attaches it to the target program.
    ///
    /// Every function configured with [`Parser::parse_fn`],
    /// [`Parser::matched_fn`] or [`Parser::extract_fn`] is replaced in the
    /// target program, the remaining parser programs are left
    /// unloaded. The parser always stops at the end of the header block, no
    /// matter which patterns were configured.
    ///
    /// # Arguments
    ///
    /// * `target` - The file descriptor of the target program to attach to
    ///
    /// # Errors
    ///
    /// Returns an error if the parser cannot be loaded, or if one of the
    /// functions it should replace does not exist in the target program with a
    /// matching signature.
    pub fn attach(mut self, target: i32) -> Result<AttachedParser, Error> {
        self.done_on_hdr_end();
        load(&self, target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dfa::parser::MAX_MATCHES;
    use http::HeaderName;

    fn hdr(i: u8) -> HeaderName {
        HeaderName::from_bytes(format!("x-{i}").as_bytes()).unwrap()
    }

    #[test]
    fn a_parser_captures_at_most_max_matches_ranges() {
        let mut parser = Parser::new();
        for i in 0..MAX_MATCHES {
            let mid = parser.capture_hdr(&hdr(i)).expect("capture header");
            assert_eq!(u8::from(mid), i);
        }

        assert!(matches!(
            parser.capture_hdr(&hdr(MAX_MATCHES)),
            Err(Error::MatchLimitExceeded(limit)) if limit == MAX_MATCHES as usize
        ));
    }

    #[test]
    fn the_same_header_is_captured_under_one_match_id() {
        // the status line fields are each captured by a path of their own
        let names: [&dyn AsRef<str>; 4] = [&hdr(0), &METHOD, &PATH, &STATUS];
        for name in names {
            let name = name.as_ref();
            let mut parser = Parser::new();
            let first = parser.capture_hdr(name).expect("capture header");
            let second = parser.capture_hdr(name).expect("capture header again");

            assert_eq!(
                first, second,
                "capturing {name} twice handed out two ids for one range"
            );
        }
    }
}
