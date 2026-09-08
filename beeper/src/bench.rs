use anyhow::{Result, bail};
use std::{
    slice,
    time::{Duration, Instant},
};
use xbpf::libbpf::{ProgramInput, ProgramMut};

/// The number of bytes a benchmark program parses at most.
///
/// This is the length of the slice the parsers read out of a dynptr, so it is
/// also how much of the buffer they see. Must stay in sync with
/// `BEEPER_BUF_LEN` of beeper.h.
pub const BUF_LEN: usize = 1024;

/// What a benchmark program is run with. Must stay in sync with `bench_args` of
/// the parser programs.
#[repr(C)]
struct Args {
    n: u32,
    len: u32,
    buf: [u8; BUF_LEN],
}

/// Runs the benchmark program `prog` over `buf` `n` times and returns how long
/// a single pass took on average.
///
/// The whole run happens inside one `BPF_PROG_TEST_RUN`, so the syscall and the
/// setup of the buffer are amortized over `n` passes rather than charged to
/// each of them.
pub(crate) fn run(prog: &ProgramMut<'_>, buf: &[u8], n: u32) -> Result<Duration> {
    if buf.len() > BUF_LEN {
        bail!(
            "a benchmark parses at most {BUF_LEN} bytes, this one was given {}",
            buf.len()
        );
    }
    if n == 0 {
        bail!("a benchmark has to parse at least once");
    }

    let mut args = Args {
        n,
        len: buf.len() as u32,
        buf: [0; BUF_LEN],
    };
    args.buf[..buf.len()].copy_from_slice(buf);

    // the program reads its context as the bytes user space handed it, so the
    // struct above is passed on as its own representation
    let args =
        unsafe { slice::from_raw_parts_mut((&raw mut args).cast::<u8>(), size_of::<Args>()) };

    let input = ProgramInput {
        context_in: Some(args),
        ..Default::default()
    };

    let start = Instant::now();
    let output = prog.test_run(input)?;
    let elapsed = start.elapsed();

    let res = output.return_value as i32;
    if res < 0 {
        bail!("the benchmark program did not parse its buffer: {res}");
    }

    Ok(elapsed / n)
}
