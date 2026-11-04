//! C ABI of Beeper, for bindings in other languages. `include/beeper_ffi.h`
//! declares the functions.
//!
//! Every fallible function returns NULL on success and an error message
//! otherwise, which the caller frees with `beeper_free_error`.

#![allow(clippy::missing_safety_doc)]

use beeper::{MessageBuffer, http1, http2, http2::DynamicTableInfo};
use std::{
    ffi::{CStr, CString, c_char},
    fmt::Display,
    net::SocketAddr,
    ptr,
};

pub type Http1Parser = Option<http1::Parser>;
pub type Http2Parser = Option<http2::Parser>;

fn status<E: Display>(f: impl FnOnce() -> Result<(), E>) -> *mut c_char {
    let Err(err) = f() else {
        return ptr::null_mut();
    };
    let msg = err.to_string().replace('\0', "");
    CString::new(msg).unwrap_or_default().into_raw()
}

unsafe fn str<'a>(s: *const c_char) -> Result<&'a str, String> {
    if s.is_null() {
        return Err("a string argument is NULL".into());
    }
    unsafe { CStr::from_ptr(s) }
        .to_str()
        .map_err(|err| format!("a string argument is not UTF-8: {err}"))
}

unsafe fn addr(s: *const c_char) -> Result<SocketAddr, String> {
    let s = unsafe { str(s) }?;
    let addr: SocketAddr = s
        .parse()
        .map_err(|err| format!("{s} is not an IP:port address: {err}"))?;
    // http2::AttachedParser panics on IPv6 addresses
    if addr.is_ipv6() {
        return Err(format!("{s} is an IPv6 address, beeper supports only IPv4"));
    }
    Ok(addr)
}

fn msg_buf(buf: u32) -> Result<MessageBuffer, String> {
    match buf {
        0 => Ok(MessageBuffer::Skb),
        1 => Ok(MessageBuffer::Msg),
        2 => Ok(MessageBuffer::DynPtr),
        buf => Err(format!("{buf} is not a beeper_msg_buf")),
    }
}

fn parser<P>(p: Option<&mut Option<P>>) -> Result<&mut Option<P>, String> {
    p.ok_or_else(|| "the parser is NULL".into())
}

fn build<P>(p: &mut Option<P>, f: impl FnOnce(P) -> P) {
    *p = p.take().map(f);
}

fn out<T>(out: Option<&mut T>) -> Result<&mut T, String> {
    out.ok_or_else(|| "an out argument is NULL".into())
}

fn built<P>(p: &mut Option<P>) -> Result<&mut P, String> {
    p.as_mut().ok_or_else(|| "the parser was moved".into())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn beeper_free_error(err: *mut c_char) {
    if !err.is_null() {
        drop(unsafe { CString::from_raw(err) });
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn beeper_http1_new() -> *mut Http1Parser {
    Box::into_raw(Box::new(Some(http1::Parser::new())))
}

#[unsafe(no_mangle)]
pub extern "C" fn beeper_http1_free(p: Option<Box<Http1Parser>>) {
    drop(p);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn beeper_http1_parse_fn(
    p: Option<&mut Http1Parser>,
    name: *const c_char,
    buf: u32,
) -> *mut c_char {
    status(|| {
        let p = parser(p)?;
        let name = unsafe { str(name) }?;
        let buf = msg_buf(buf)?;
        build(p, |p| p.parse_fn(name, buf));
        Ok::<_, String>(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn beeper_http1_matched_fn(
    p: Option<&mut Http1Parser>,
    name: *const c_char,
) -> *mut c_char {
    status(|| {
        let p = parser(p)?;
        let name = unsafe { str(name) }?;
        build(p, |p| p.matched_fn(name));
        Ok::<_, String>(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn beeper_http1_get_fn(
    p: Option<&mut Http1Parser>,
    name: *const c_char,
    buf: u32,
) -> *mut c_char {
    status(|| {
        let p = parser(p)?;
        let name = unsafe { str(name) }?;
        let buf = msg_buf(buf)?;
        build(p, |p| p.get_fn(name, buf));
        Ok::<_, String>(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn beeper_http1_capture_hdr(
    p: Option<&mut Http1Parser>,
    name: *const c_char,
    mid: Option<&mut u8>,
) -> *mut c_char {
    status(|| {
        let p = built(parser(p)?)?;
        let name = unsafe { str(name) }?;
        let mid = out(mid)?;
        *mid = p.capture_hdr(name).map_err(|err| err.to_string())?.into();
        Ok::<_, String>(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn beeper_http1_match_http2_preface(
    p: Option<&mut Http1Parser>,
    mid: Option<&mut u8>,
) -> *mut c_char {
    status(|| {
        let p = built(parser(p)?)?;
        let mid = out(mid)?;
        *mid = p
            .match_http2_preface()
            .map_err(|err| err.to_string())?
            .into();
        Ok::<_, String>(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn beeper_http1_attach(
    p: Option<Box<Http1Parser>>,
    prog_fd: i32,
    attached: Option<&mut *mut http1::AttachedParser>,
) -> *mut c_char {
    status(|| {
        let p = p.and_then(|p| *p).ok_or("the parser is NULL")?;
        let attached = out(attached)?;
        let p = p.attach(prog_fd).map_err(|err| err.to_string())?;
        *attached = Box::into_raw(Box::new(p));
        Ok::<_, String>(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn beeper_http1_detach(p: Option<Box<http1::AttachedParser>>) {
    drop(p);
}

#[unsafe(no_mangle)]
pub extern "C" fn beeper_http2_new() -> *mut Http2Parser {
    Box::into_raw(Box::new(Some(http2::Parser::new())))
}

#[unsafe(no_mangle)]
pub extern "C" fn beeper_http2_free(p: Option<Box<Http2Parser>>) {
    drop(p);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn beeper_http2_parse_fn(
    p: Option<&mut Http2Parser>,
    name: *const c_char,
    buf: u32,
) -> *mut c_char {
    status(|| {
        let p = parser(p)?;
        let name = unsafe { str(name) }?;
        let buf = msg_buf(buf)?;
        build(p, |p| p.parse_fn(name, buf));
        Ok::<_, String>(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn beeper_http2_matched_fn(
    p: Option<&mut Http2Parser>,
    name: *const c_char,
) -> *mut c_char {
    status(|| {
        let p = parser(p)?;
        let name = unsafe { str(name) }?;
        build(p, |p| p.matched_fn(name));
        Ok::<_, String>(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn beeper_http2_get_fn(
    p: Option<&mut Http2Parser>,
    name: *const c_char,
    buf: u32,
) -> *mut c_char {
    status(|| {
        let p = parser(p)?;
        let name = unsafe { str(name) }?;
        let buf = msg_buf(buf)?;
        build(p, |p| p.get_fn(name, buf));
        Ok::<_, String>(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn beeper_http2_get_dynamic_table_entry_fn(
    p: Option<&mut Http2Parser>,
    name: *const c_char,
) -> *mut c_char {
    status(|| {
        let p = parser(p)?;
        let name = unsafe { str(name) }?;
        build(p, |p| p.get_dynamic_table_entry(name));
        Ok::<_, String>(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn beeper_http2_capture_hdr(
    p: Option<&mut Http2Parser>,
    name: *const c_char,
    mid: Option<&mut u8>,
) -> *mut c_char {
    status(|| {
        let p = built(parser(p)?)?;
        let name = unsafe { str(name) }?;
        let mid = out(mid)?;
        *mid = p.capture_hdr(name).map_err(|err| err.to_string())?.into();
        Ok::<_, String>(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn beeper_http2_attach(
    p: Option<Box<Http2Parser>>,
    prog_fd: i32,
    attached: Option<&mut *mut http2::AttachedParser>,
) -> *mut c_char {
    status(|| {
        let p = p.and_then(|p| *p).ok_or("the parser is NULL")?;
        let attached = out(attached)?;
        let p = p.attach(prog_fd).map_err(|err| err.to_string())?;
        *attached = Box::into_raw(Box::new(p));
        Ok::<_, String>(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn beeper_http2_detach(p: Option<Box<http2::AttachedParser>>) {
    drop(p);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn beeper_http2_dynamic_table_info(
    p: Option<&http2::AttachedParser>,
    local: *const c_char,
    remote: *const c_char,
    info: Option<&mut DynamicTableInfo>,
    found: Option<&mut bool>,
) -> *mut c_char {
    status(|| {
        let p = p.ok_or("the parser is NULL")?;
        let local = unsafe { addr(local) }?;
        let remote = unsafe { addr(remote) }?;
        let info = out(info)?;
        let found = out(found)?;
        *found = false;
        let Some(res) = p.dynamic_table_info(local, remote) else {
            return Ok(());
        };
        *info = res.map_err(|err| err.to_string())?;
        *found = true;
        Ok::<_, String>(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn beeper_http2_forget_conn(
    p: Option<&http2::AttachedParser>,
    local: *const c_char,
    remote: *const c_char,
) -> *mut c_char {
    status(|| {
        let p = p.ok_or("the parser is NULL")?;
        let local = unsafe { addr(local) }?;
        let remote = unsafe { addr(remote) }?;
        p.forget_conn(local, remote).map_err(|err| err.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(msg: *mut c_char) -> Option<String> {
        if msg.is_null() {
            return None;
        }
        let s = unsafe { CStr::from_ptr(msg) }
            .to_string_lossy()
            .into_owned();
        unsafe { beeper_free_error(msg) };
        Some(s)
    }

    #[test]
    fn builders_report_errors_as_messages() {
        let p = beeper_http1_new();
        let mut mid = u8::MAX;

        let path = c":path".as_ptr();
        assert_eq!(
            err(unsafe { beeper_http1_capture_hdr(p.as_mut(), path, Some(&mut mid)) }),
            None
        );
        assert_eq!(mid, 0);
        assert!(
            err(unsafe { beeper_http1_capture_hdr(p.as_mut(), ptr::null(), Some(&mut mid)) })
                .is_some()
        );
        assert!(err(unsafe { beeper_http1_capture_hdr(None, path, Some(&mut mid)) }).is_some());
        assert!(err(unsafe { beeper_http1_parse_fn(p.as_mut(), c"parse".as_ptr(), 3) }).is_some());
        assert_eq!(
            err(unsafe { beeper_http1_parse_fn(p.as_mut(), c"parse".as_ptr(), 1) }),
            None
        );

        let mut mids = 1;
        while err(unsafe {
            beeper_http1_capture_hdr(
                p.as_mut(),
                CString::new(format!("x-{mids}")).unwrap().as_ptr(),
                Some(&mut mid),
            )
        })
        .is_none()
        {
            mids += 1;
        }
        assert_eq!(mids, 32);
        beeper_http1_free(Some(unsafe { Box::from_raw(p) }));

        let p = beeper_http2_new();
        assert_eq!(
            err(unsafe { beeper_http2_capture_hdr(p.as_mut(), path, Some(&mut mid)) }),
            None
        );
        assert_eq!(
            err(unsafe { beeper_http2_get_fn(p.as_mut(), c"get".as_ptr(), 1) }),
            None
        );
        assert!(err(beeper_http2_attach(None, -1, None)).is_some());
        assert!(unsafe { addr(c"[::1]:80".as_ptr()) }.is_err());
        beeper_http2_free(Some(unsafe { Box::from_raw(p) }));
    }
}
